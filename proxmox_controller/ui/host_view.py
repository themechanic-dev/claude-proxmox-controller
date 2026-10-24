"""The page of one Proxmox host: its state, the node's numbers, storage, and every container and VM."""

from __future__ import annotations

import html
import ipaddress
import re
import time
from typing import Callable

from PySide6.QtCore import QEvent, QRectF, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QFontMetrics, QIcon, QPainter
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QDialog, QGridLayout, QHBoxLayout,
                               QHeaderView, QMenu, QScrollArea, QStackedWidget, QStyle, QStyledItemDelegate,
                               QStyleOptionViewItem, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)

from ..core import netinfo, setupdisc, spice, startup, tasks, wol  # noqa: F401 (netinfo: the tests replace its ARP table)
from ..core.details import read_details
from ..core.pve import Host, Pve, PveError, storage_order
from . import theme
from .tasks_panel import SHOWN as TASKS_SHOWN, TaskLogDialog, TasksPanel
from .widgets import (ElidedLabel, FlowLayout, Pill, StatCard, button, card, confirm, dot_icon, error, gib, label,
                      mem_text, power_icon, uptime_text)
from .worker import Runner

CONSOLE_WAYS = (("spice", "SPICE — sound, clipboard, USB"), ("vnc", "Built-in console"),
                ("browser", "Proxmox console in the browser"))
DETAILS_REFRESH_S = 60  # notes, MAC and IP addresses change rarely: read them once a minute
AFTER_START_S = 30      # …and once more this long after a start, when a booted guest has its address
WAKE_TIMEOUT_S = 240
UPDATES_EVERY_S = 1800  # the waiting package updates are counted again this often (the host checks daily)
SETUP_DISCS_EVERY_S = 60  # new VMs' setup discs are checked this often (core/setupdisc.py)
MULTI = ("start", "shutdown", "stop", "reboot")  # what works on several selected guests at once
CLOSED_LOGS_KEPT = 5  # closed task-log windows kept for reopening; older ones are freed
COLUMNS = ["", "ID", "Name", "Type", "Status", "Boot", "CPU", "Memory", "Disk", "IP address", "Uptime", ""]
(COL_DOT, COL_ID, COL_NAME, COL_TYPE, COL_STATUS, COL_BOOT, COL_CPU, COL_MEM, COL_DISK, COL_IP, COL_UPTIME,
 COL_FILL) = range(len(COLUMNS))
RIGHT_ALIGNED = (COL_CPU, COL_MEM, COL_DISK, COL_UPTIME)  # numbers line up on the right
BOOT_TIP = "Starts when the host starts (Start at boot)"
HEADER_PAD, ARROW_ROOM = 8, 18
NAME_MIN_W = 150  # the Name column shrinks to this before the table needs a horizontal scroll bar  # the column titles' side padding (theme) and the sort arrow's room
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
TAGS_ROLE = Qt.ItemDataRole.UserRole + 2
ARP_TIP = ("Found in this computer's network table by the VM's MAC address, because the VM has no QEMU guest agent "
           "to report it. It may be out of date.")
NO_AGENT_TIP = ("No address known. Turn on the QEMU guest agent for this VM (Proxmox: VM → Options → QEMU Guest "
                "Agent) and install qemu-guest-agent inside it. Until then the app looks in this computer's network "
                "table, which only knows machines this computer has talked to.")
SILENT_AGENT_TIP = ("The QEMU guest agent is turned on for this VM but does not answer: install and start "
                    "qemu-guest-agent inside the VM.")


def kind_label(g: dict) -> str:
    if g.get("template"):
        return "Template"
    return "Container" if g["type"] == "lxc" else "VM"


def split_tags(text: str) -> list[str]:
    """Proxmox keeps tags as one string: 'a;b' (older versions: commas or spaces)."""
    return [t for t in re.split(r"[;,\s]+", text or "") if t]


STORAGE_COLUMNS = 4  # storage cards side by side at most, as the cards above them; more go on to another row
CONTENT_WORDS = {"images": "VM disks", "rootdir": "container disks", "iso": "ISO images", "vztmpl": "container templates",
                 "backup": "backups", "import": "disk images to import", "snippets": "snippets"}


def storage_entries(by_node: dict[str, list[dict]]) -> list[dict]:
    """One card for each storage of the host, every one of them: a storage the nodes of a cluster share (a NAS,
    Ceph) once, a node's own with the node's name when there are several. One that is disabled or does not answer
    (a NAS that is off) says so instead of disappearing."""
    several = len(by_node) > 1
    out, seen = [], set()
    for node, items in by_node.items():
        for st in sorted(items, key=storage_order):
            name = st.get("storage", "")
            shared = bool(st.get("shared"))
            key = name if shared else f"{node}/{name}"
            if key in seen:
                continue
            seen.add(key)
            title = f"{node} · {name}" if several and not shared else name
            kind = st.get("type", "")
            used, total = st.get("used") or 0, st.get("total") or 0
            holds = ", ".join(CONTENT_WORDS.get(c, c) for c in (st.get("content") or "").split(",") if c)
            tip = f"{name} ({kind})" + (f" — holds {holds}" if holds else "")
            if not st.get("enabled", 1):
                value, fraction, caption = "—", None, "Disabled"
            elif not total or not st.get("active", 1):
                value, fraction, caption = "—", None, "Not available"
            else:
                fraction = used / total
                value, caption = gib(used), f"of {gib(total)} · {fraction * 100:.0f} % used"
                tip += f"\n{gib(max(total - used, 0))} free"
            out.append({"key": key, "title": f"{title} ({kind})" if kind else title, "value": value,
                        "fraction": fraction, "caption": caption, "tip": tip})
    return out


def ip_key(ips: list[str]) -> list[int]:
    """Sort key: guests with an address first, in numeric order."""
    for ip in ips:
        try:
            return [0, int(ipaddress.IPv4Address(ip))]
        except ValueError:
            continue
    return [1, 0]


class SortItem(QTableWidgetItem):
    """Sorts by a key kept with the item (numbers as numbers), not by its text."""

    def __lt__(self, other):
        a, b = self.data(SORT_ROLE), other.data(SORT_ROLE)
        if a is None or b is None:
            return super().__lt__(other)
        return a < b


class NameDelegate(QStyledItemDelegate):
    """The guest's name followed by its Proxmox tags as small rounded labels."""

    PAD, GAP, TAG_PAD, TAG_SPACE = 8, 8, 6, 4

    @staticmethod
    def _small(font: QFont) -> QFont:
        f = QFont(font)
        f.setPointSizeF(font.pointSizeF() * 0.85)
        return f

    def paint(self, painter: QPainter, option, index) -> None:
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        name, opt.text = opt.text, ""
        style = opt.widget.style() if opt.widget is not None else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)  # background, selection
        c = theme.colors()
        r = option.rect.adjusted(self.PAD, 0, -self.PAD, 0)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(opt.font)
        painter.setPen(QColor(c.text))
        name = QFontMetrics(opt.font).elidedText(name, Qt.TextElideMode.ElideRight, max(0, r.width()))
        painter.drawText(r, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, name)
        small = self._small(opt.font)
        sfm = QFontMetrics(small)
        painter.setFont(small)
        h = sfm.height() + 2
        x = r.left() + QFontMetrics(opt.font).horizontalAdvance(name) + self.GAP
        y = r.top() + (r.height() - h) / 2
        fill = QColor(c.dim)
        fill.setAlphaF(0.28)
        for tag in index.data(TAGS_ROLE) or []:
            w = sfm.horizontalAdvance(tag) + 2 * self.TAG_PAD
            if x + w > r.right() + self.PAD:
                break
            rect = QRectF(x, y, w, h)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill)
            painter.drawRoundedRect(rect, h / 2, h / 2)
            painter.setPen(QColor(c.text))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, tag)
            x += w + self.TAG_SPACE
        painter.restore()

    def sizeHint(self, option, index) -> QSize:
        size = super().sizeHint(option, index)
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        width = 2 * self.PAD + QFontMetrics(opt.font).horizontalAdvance(opt.text)
        tags = index.data(TAGS_ROLE) or []
        if tags:
            sfm = QFontMetrics(self._small(opt.font))
            width += self.GAP + sum(sfm.horizontalAdvance(t) + 2 * self.TAG_PAD + self.TAG_SPACE for t in tags)
        return QSize(max(width, size.width()), size.height())


class StorageCards(QWidget):
    """The host's storages as cards like CPU and Memory above them: all the same width (a long name ends in "…"),
    side by side up to STORAGE_COLUMNS, further ones on the next row. The cards stay while the storages do (no
    flicker every refresh)."""

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lay.addWidget(label("Storage", "heading"))
        self.grid = QGridLayout()
        self.grid.setSpacing(12)
        lay.addLayout(self.grid)
        self.empty = label("No storage reported.", "dim")
        self.empty.hide()
        lay.addWidget(self.empty)
        self.cards: dict[str, StatCard] = {}
        self.columns = 0

    def show_entries(self, entries: list[dict]) -> None:
        if [e["key"] for e in entries] != list(self.cards):
            self._lay_out(entries)
        for e in entries:
            c = self.cards[e["key"]]
            c.title.setText(e["title"])
            c.show_fraction(e["value"], e["fraction"], e["caption"])
            c.setToolTip(e["tip"])

    def _lay_out(self, entries: list[dict]) -> None:
        for c in self.cards.values():
            self.grid.removeWidget(c)
            c.deleteLater()
        self.cards = {}
        for col in range(self.grid.columnCount()):
            self.grid.setColumnStretch(col, 0)
        self.columns = min(len(entries), STORAGE_COLUMNS)
        for i, e in enumerate(entries):
            c = StatCard(e["title"], elide=True)
            self.grid.addWidget(c, i // self.columns, i % self.columns)
            self.cards[e["key"]] = c
        for col in range(self.columns):
            self.grid.setColumnStretch(col, 1)
        self.empty.setVisible(not entries)


class HostView(QWidget):
    def __init__(self, host: Host, make_client: Callable[[Host], Pve], runner: Runner,
                 notify: Callable[[str], None], on_edit_host: Callable[[Host], None],
                 on_state: Callable[[str, str], None] | None = None, corner: QWidget | None = None,
                 prefs: dict | None = None, on_prefs_changed: Callable[[], None] | None = None,
                 on_host_changed: Callable[[], None] | None = None):
        super().__init__()
        self.host = host
        self.on_host_changed = on_host_changed or (lambda: None)  # the host's own settings changed here (SSH): save
        self.updates_at = 0.0  # when the waiting package updates were last counted (for the Upgrade button)
        self.make_client = make_client
        self.runner = runner
        self.notify = notify
        self.on_edit_host = on_edit_host
        self.on_state = on_state  # (host id, "online" | "offline") for the dot in the ☰ menu
        self.prefs = prefs if prefs is not None else {}  # the window's settings (hide_stopped)
        self.on_prefs_changed = on_prefs_changed
        self.inflight = False
        self.refresh_again = False  # asked while a read was running (it may have begun before a change): once more
        self.online: bool | None = None
        self.nodes: list[str] = []
        self.guests: list[dict] = []
        self.details: dict[int, dict] = {}
        self.details_at = 0.0
        self.details_inflight = False
        self.details_again = False  # a change came while the details were being read: read them once more
        self.waking_until = 0.0
        self.sort = (COL_ID, Qt.SortOrder.AscendingOrder)
        self.task_logs: dict[str, TaskLogDialog] = {}
        self.discs_at = 0.0  # when the setup discs were last checked
        self.discs_inflight = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(24, 20, 24, 24)
        lay.setSpacing(16)

        # header
        self.title = ElidedLabel(host.name, "title")
        self.pill = Pill("Connecting…", "unknown")
        self.caption = label(host.address, "dim", selectable=True)
        head = QHBoxLayout()
        head.setSpacing(8)  # (it took the page's 16 between every button, and the row no longer fitted 1060 px)
        head.addWidget(self.title)
        head.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addStretch(1)
        self.wake_btn = button("Wake", tooltip="Send a Wake-on-LAN packet to turn the host on")
        self.wake_btn.clicked.connect(self.wake)
        self.shutdown_btn = button("Shut Down Host…")
        self.shutdown_btn.clicked.connect(lambda: self.node_command("shutdown"))
        self.reboot_btn = button("Reboot Host…")
        self.reboot_btn.clicked.connect(lambda: self.node_command("reboot"))
        self.console_btn = QToolButton()  # a click: the host's shell; the arrow: its SSH settings
        self.console_btn.setText("Console")
        self.console_btn.setToolTip("The host's own shell (root), in this computer's terminal over SSH")
        self.console_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.console_btn.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.console_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        shell_menu = QMenu(self.console_btn)
        shell_menu.addAction("Console").triggered.connect(self.open_host_console)
        shell_menu.addAction("SSH Settings…").triggered.connect(self.ssh_settings)
        self.console_btn.setMenu(shell_menu)
        self.console_btn.clicked.connect(self.open_host_console)
        self.upgrade_btn = button("Upgrade", "", "The package updates waiting on the host, and the upgrade")
        self.upgrade_btn.clicked.connect(self.open_upgrade)
        self.upgrade_dialog = None
        self.wall_btn = button("Graph Wall", "", "Every running VM and container's graphs in one window")
        self.wall_btn.clicked.connect(self.open_wall)
        self.web_btn = button("Web UI", "", "Open the Proxmox web interface in the browser")
        self.web_btn.clicked.connect(self.open_web_ui)
        self.edit_btn = button("Edit…", "", "Address, API token, certificate, Wake-on-LAN")
        self.edit_btn.clicked.connect(lambda: self.on_edit_host(self.host))
        for b in (self.wake_btn, self.shutdown_btn, self.reboot_btn, self.console_btn, self.upgrade_btn, self.wall_btn,
                  self.web_btn, self.edit_btn):
            head.addWidget(b)
        if corner is not None:  # the window's ☰ menu button
            head.addWidget(corner)
        lay.addLayout(head)
        lay.addWidget(self.caption)

        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)

        # state page (connecting / offline / error)
        self.state_title = label("Connecting…", "heading")
        self.state_text = label("", "dim", wrap=True, selectable=True)
        self.state_wake = button("Wake", "suggested")
        self.state_wake.clicked.connect(self.wake)
        self.state_retry = button("Try again")
        self.state_retry.clicked.connect(self.refresh)
        state_row = QHBoxLayout()
        state_row.addWidget(self.state_wake)
        state_row.addWidget(self.state_retry)
        state_row.addStretch(1)
        state_box = card(self.state_title, self.state_text)
        state_box.layout().addLayout(state_row)
        state_page = QWidget()
        sp = QVBoxLayout(state_page)
        sp.setContentsMargins(0, 0, 0, 0)
        sp.addWidget(state_box)
        sp.addStretch(1)
        self.stack.addWidget(state_page)

        # content page
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(16)
        grid = QGridLayout()
        grid.setSpacing(12)
        self.cpu_card = StatCard("CPU")
        self.mem_card = StatCard("Memory")
        self.disk_card = StatCard("System disk")
        self.up_card = StatCard("Uptime")
        for i, c in enumerate((self.cpu_card, self.mem_card, self.disk_card, self.up_card)):
            grid.addWidget(c, 0, i)
        cl.addLayout(grid)

        self.storage_cards = StorageCards()
        cl.addWidget(self.storage_cards)

        guests_head = QHBoxLayout()
        guests_head.setSpacing(10)
        guests_head.addWidget(label("Containers and virtual machines", "heading"))
        self.count = label("", "dim")
        guests_head.addWidget(self.count)
        guests_head.addStretch(1)
        self.hide_stopped = QCheckBox("Hide stopped")
        self.hide_stopped.setChecked(bool(self.prefs.get("hide_stopped")))
        self.hide_stopped.toggled.connect(self._hide_stopped_changed)
        guests_head.addWidget(self.hide_stopped)
        guests_head.addSpacing(6)
        self.jobs_btn = QToolButton()  # a click: the scheduled backups; the arrow: those of deleted guests too
        self.jobs_btn.setText("Backup Jobs…")
        self.jobs_btn.setToolTip("Scheduled backups (Datacenter → Backup) — the arrow: backups of deleted guests")
        self.jobs_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.jobs_btn.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.jobs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        jobs_menu = QMenu(self.jobs_btn)
        jobs_menu.addAction("Backup Jobs…").triggered.connect(self.open_backup_jobs)
        jobs_menu.addAction("Backups of Deleted Guests…").triggered.connect(self.open_deleted_backups)
        self.jobs_btn.setMenu(jobs_menu)
        self.jobs_btn.clicked.connect(self.open_backup_jobs)
        self.jobs_dialog = None
        self.deleted_dialog = None
        guests_head.addWidget(self.jobs_btn)
        self.new_vm_btn = button("New VM…", "suggested")
        self.new_vm_btn.clicked.connect(self.new_vm)
        guests_head.addWidget(self.new_vm_btn)
        self.new_btn = button("New Container…", "suggested")
        self.new_btn.clicked.connect(self.new_container)
        guests_head.addWidget(self.new_btn)
        cl.addLayout(guests_head)

        # one row where the window is wide enough, two (or more) where it is not: the groups move down whole
        self.actions = FlowLayout(spacing=6)
        self.act: dict[str, object] = {}
        group = None
        for key, text in (("start", "Start"), ("shutdown", "Shut Down…"), ("stop", "Stop…"), ("reboot", "Reboot…"),
                          ("|", ""), ("console", "Console"), ("files", "Files…"), ("agent", "Install Guest Agent…"),
                          ("|", ""), ("edit", "Edit…"), ("notes", "Notes…"), ("snapshots", "Snapshots…"),
                          ("backups", "Backups…"), ("graphs", "Graphs…"),
                          ("|", ""), ("delete", "Delete…")):
            if group is None or key == "|":
                box = QWidget()
                group = QHBoxLayout(box)
                group.setContentsMargins(0, 0, 0, 0)
                group.setSpacing(6)
                self.actions.addWidget(box)
                if key == "|":
                    continue
            if key == "console":  # a click opens the usual console; the arrow offers every kind
                b = QToolButton()
                b.setText(text)
                b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
                b.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                menu = QMenu(b)
                for how, title in CONSOLE_WAYS:
                    menu.addAction(title).triggered.connect(lambda _=False, h=how: self.open_selected_console(h))
                b.setMenu(menu)
            else:
                b = button(text, "destructive" if key == "delete" else "")
            b.clicked.connect(lambda _=False, k=key: self.guest_action(k))
            group.addWidget(b)
            self.act[key] = b
        self.act["files"].setToolTip("Copy files and folders between this computer and the guest (a VM whose "
                                     "guest agent does not answer: the app offers to install it)")
        self.act["agent"].setToolTip("Install the QEMU guest agent in a running VM whose agent does not answer — "
                                     "through its console (it shows the VM's address, and Files and Commands need it)")
        self.act["console"].setFixedHeight(self.act["start"].sizeHint().height())  # a tool button is a bit taller
        self.console_btn.setFixedHeight(self.reboot_btn.sizeHint().height())
        self.jobs_btn.setFixedHeight(self.new_btn.sizeHint().height())
        cl.addLayout(self.actions)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        for col in range(len(COLUMNS)):
            right = col in RIGHT_ALIGNED
            self.table.horizontalHeaderItem(col).setTextAlignment(
                (Qt.AlignmentFlag.AlignRight if right else Qt.AlignmentFlag.AlignLeft) | Qt.AlignmentFlag.AlignVCenter)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)  # Ctrl/Shift: several
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setIconSize(QSize(16, 16))
        self.table.setMinimumHeight(220)  # a header and six guests without scrolling
        self.table.setItemDelegateForColumn(COL_NAME, NameDelegate(self.table))
        hdr = self.table.horizontalHeader()
        hdr.setMinimumSectionSize(1)  # the empty column on the right may shrink to nothing
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)  # widths come from _fit_columns
        hdr.resizeSection(COL_FILL, 0)  # kept for its place; the room is shared out by _fit_columns instead
        hdr.setSortIndicatorShown(True)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(COL_ID, Qt.SortOrder.AscendingOrder)
        hdr.sortIndicatorChanged.connect(self._sort_changed)
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.doubleClicked.connect(lambda *_: self.guest_action("edit"))
        self.table.viewport().installEventFilter(self)  # its size is final when this one hears of it
        cl.addWidget(self.table, 1)
        self.tasks_panel = TasksPanel(self.open_task_log, self.stop_task, self.prefs, self.on_prefs_changed)
        # Bulk Start / Shut Down beside the tasks they make (the rows above are as wide as a 1060-px window allows)
        self.bulk_start_btn = button("Bulk Start…", "", "Start several guests in one go, in their boot order")
        self.bulk_start_btn.clicked.connect(lambda: self.open_bulk("start"))
        self.bulk_stop_btn = button("Bulk Shut Down…", "",
                                    "Shut several guests down in one go, in reverse boot order")
        self.bulk_stop_btn.clicked.connect(lambda: self.open_bulk("shutdown"))
        self.tasks_panel.head.addWidget(self.bulk_start_btn)
        self.tasks_panel.head.addWidget(self.bulk_stop_btn)
        cl.addWidget(self.tasks_panel)
        self.stack.addWidget(content)

        self._show_state("Connecting…", f"Asking {host.address} for its state.", wake=False)
        self._update_actions()

    def showEvent(self, ev) -> None:
        super().showEvent(ev)
        want = bool(self.prefs.get("hide_stopped"))  # another host's page may have changed it
        if self.hide_stopped.isChecked() != want:
            self.hide_stopped.setChecked(want)

    # -- loading -----------------------------------------------------------------------------------

    def client(self) -> Pve:
        return self.make_client(self.host)

    def refresh(self) -> None:
        if self.inflight:
            self.refresh_again = True
            return
        self.inflight = True
        pve = self.client()

        def load():
            version = pve.version()
            nodes = [n["node"] for n in pve.nodes() if n.get("status", "online") == "online"]
            node_status = {n: pve.node_status(n) for n in nodes}
            storage = {n: pve.storages(n) for n in nodes}
            guests = pve.guests()
            try:  # a token that may not read the task list still shows everything else
                task_rows, problem = [], ""
                for n in nodes:
                    task_rows += [dict(t, node=t.get("node") or n) for t in pve.tasks(n, limit=TASKS_SHOWN)]
            except PveError as e:
                if not e.status:
                    raise
                task_rows, problem = None, f"Could not read the tasks — {e}"
            return {"version": version, "nodes": nodes, "status": node_status, "storage": storage,
                    "guests": guests, "tasks": task_rows, "tasks_problem": problem}

        self.runner.run(load, self._loaded)

    def _loaded(self, data, err) -> None:
        self.inflight = False
        if self.refresh_again:
            self.refresh_again = False
            QTimer.singleShot(0, self.refresh)
        if err is not None:
            self.online = False
            self._report_state()
            self._update_header()
            waking = time.monotonic() < self.waking_until
            if waking:
                self._show_state("Waking up…", "The Wake-on-LAN packet was sent. Waiting for Proxmox to answer "
                                 "(this can take a few minutes).", wake=False)
            else:
                self._show_state("No answer from this host", str(err), wake=bool(self.host.mac))
            return
        self.online = True
        self._report_state()
        self.waking_until = 0.0
        self.nodes = data["nodes"]
        v = data["version"]
        self.caption.setText(f"{self.host.address}  ·  Proxmox VE {v.get('version', '?')}  ·  "
                             f"{len(self.nodes)} node{'s' if len(self.nodes) != 1 else ''}: {', '.join(self.nodes)}")
        self._show_numbers(data)
        self.guests = sorted(data["guests"], key=lambda g: g["vmid"])
        self._fill_table()
        self.tasks_panel.show_tasks(data["tasks"], {g["vmid"]: g for g in self.guests}, data["tasks_problem"])
        self._update_header()
        self.stack.setCurrentIndex(1)
        self._refresh_details()
        self._tidy_setup_discs()

    def _show_numbers(self, data) -> None:
        sts = list(data["status"].values())
        if not sts:
            for c in (self.cpu_card, self.mem_card, self.disk_card, self.up_card):
                c.clear()
            return
        cpu = sum(s.get("cpu", 0) for s in sts) / len(sts)
        cpus = sum((s.get("cpuinfo") or {}).get("cpus", 0) for s in sts)
        model = (sts[0].get("cpuinfo") or {}).get("model", "")
        self.cpu_card.show_fraction(f"{cpu * 100:.0f} %", cpu, f"{cpus} threads · {model}".strip(" ·"))
        used = sum((s.get("memory") or {}).get("used", 0) for s in sts)
        total = sum((s.get("memory") or {}).get("total", 0) for s in sts)
        self.mem_card.show_fraction(gib(used), used / total if total else None, f"of {gib(total)}")
        rused = sum((s.get("rootfs") or {}).get("used", 0) for s in sts)
        rtotal = sum((s.get("rootfs") or {}).get("total", 0) for s in sts)
        self.disk_card.show_fraction(gib(rused), rused / rtotal if rtotal else None, f"of {gib(rtotal)}")
        up = min(s.get("uptime", 0) for s in sts)
        load = " / ".join(str(x) for x in (sts[0].get("loadavg") or [])[:3])
        self.up_card.show_fraction(uptime_text(up), None, f"load {load}" if load else "")
        self.storage_cards.show_entries(storage_entries(data["storage"]))

    # -- the guests table --------------------------------------------------------------------------

    def _fill_table(self) -> None:
        keep = self.selected_vmids()
        c = theme.colors()
        t = self.table
        t.setSortingEnabled(False)  # rows must not move while they are being filled
        t.setRowCount(len(self.guests))
        for r, g in enumerate(self.guests):
            running = g.get("status") == "running"
            vmid = g["vmid"]
            mem, maxmem = g.get("mem") or 0, g.get("maxmem") or 0
            cells = [
                ("", [0 if running else 1, vmid]),
                (str(vmid), vmid),
                (g.get("name", ""), g.get("name", "").lower()),
                (kind_label(g), kind_label(g)),
                (g.get("status", "?").capitalize(), [0 if running else 1, g.get("status", "")]),
                ("", [1, vmid]),  # Boot: arrives with the details (it is in the config, not in the list)
                (f"{g.get('cpu', 0) * 100:.0f} % of {g.get('maxcpu', 0)}" if running else "—",
                 float(g.get("cpu", 0)) if running else -1.0),
                (f"{mem_text(mem)} / {mem_text(maxmem)}" if running else mem_text(maxmem),
                 [mem if running else -1, maxmem]),
                (gib(g.get("maxdisk")), g.get("maxdisk") or 0),
                ("—", [1, 0]),  # the address arrives with the details
                (uptime_text(g.get("uptime")) if running else "—", (g.get("uptime") or 0) if running else -1),
                ("", 0),
            ]
            for col, (text, key) in enumerate(cells):
                item = SortItem(text)
                item.setData(Qt.ItemDataRole.UserRole, vmid)
                item.setData(SORT_ROLE, key)
                if col in RIGHT_ALIGNED:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                t.setItem(r, col, item)
            t.item(r, COL_DOT).setIcon(dot_icon(c.success if running else c.dim))  # keeps its colour when selected
            t.item(r, COL_NAME).setData(TAGS_ROLE, split_tags(g.get("tags", "")))
            self._show_details(r, g)
        t.setSortingEnabled(True)
        t.sortByColumn(*self.sort)
        self._select(keep)
        self._apply_filter()
        running = sum(1 for g in self.guests if g.get("status") == "running")
        self.count.setText(f"{running} of {len(self.guests)} running")
        self._fit_columns()
        self._update_actions()

    def _show_details(self, row: int, g: dict) -> None:
        """The address and the tooltips of one row, from what read_details found."""
        d = self.details.get(g["vmid"])
        running = g.get("status") == "running"
        ips = (d or {}).get("ips", []) if running else []
        ip_item = self.table.item(row, COL_IP)
        ip_item.setText(", ".join(ips) or "—")
        ip_item.setData(SORT_ROLE, ip_key(ips))
        tip = ""
        ip_item.setData(Qt.ItemDataRole.ForegroundRole, None)
        if ips and d.get("source") == "arp":
            tip = ARP_TIP
            ip_item.setForeground(QColor(theme.colors().dim))
        elif running and not ips and d is not None and g["type"] == "qemu":
            tip = SILENT_AGENT_TIP if d.get("agent") else NO_AGENT_TIP
        ip_item.setToolTip(tip)
        boot_item = self.table.item(row, COL_BOOT)
        on = bool((d or {}).get("onboot"))
        order = startup.parse((d or {}).get("startup", ""))["order"] if on else None
        boot_item.setIcon(power_icon(theme.colors().accent) if on else QIcon())
        boot_item.setText(str(order) if order else "")
        more = startup.describe((d or {}).get("startup", "")) if on else ""
        boot_item.setToolTip((BOOT_TIP + (f" — {more}" if more else "")) if on else "")
        boot_item.setData(SORT_ROLE, [0 if on else 1, order or 1 << 30, g["vmid"]])  # in start order
        name_item = self.table.item(row, COL_NAME)
        tags, notes = name_item.data(TAGS_ROLE) or [], (d or {}).get("notes", "")
        parts = [f"<b>{html.escape(g.get('name', ''))}</b>"]
        if tags:
            parts.append("Tags: " + html.escape(", ".join(tags)))
        if notes:
            text = notes if len(notes) <= 600 else notes[:600] + "…"
            parts.append(html.escape(text).replace("\n", "<br>"))
        name_item.setToolTip("<br>".join(parts))  # at least the whole name, for when the column shows "…"

    def _refresh_details(self, force: bool = False) -> None:
        now = time.monotonic()
        if self.details_inflight and force:  # that read may have begun before the change: one more after it
            self.details_again = True
            return
        if self.details_inflight or not self.guests or (not force and now - self.details_at < DETAILS_REFRESH_S):
            return
        self.details_inflight = True
        self.details_at = now
        pve, guests = self.client(), [dict(g) for g in self.guests]
        self.runner.run(lambda: read_details(pve, guests), self._got_details)

    def _got_details(self, details, err) -> None:
        self.details_inflight = False
        if self.details_again:
            self.details_again = False
            QTimer.singleShot(0, lambda: self._refresh_details(force=True))
        if err is not None or not details:
            return
        self.details.update(details)
        t = self.table
        by_id = {g["vmid"]: g for g in self.guests}
        t.setSortingEnabled(False)
        for r in range(t.rowCount()):
            g = by_id.get(t.item(r, COL_ID).data(Qt.ItemDataRole.UserRole))
            if g is not None:
                self._show_details(r, g)
        t.setSortingEnabled(True)
        t.sortByColumn(*self.sort)
        self._apply_filter()
        self._fit_columns()
        self._update_actions()  # whether a VM's agent answers is known now (Install Guest Agent…)

    def _fit_columns(self) -> None:
        """Every column as wide as its contents, and any room the window has to spare shared out among them in
        proportion, so a bigger window spreads the list instead of leaving a gap on the right. (Qt's own sizing keeps
        room for a sort arrow in every title; here only the sorted column gets it.)"""
        t, hdr = self.table, self.table.horizontalHeader()
        f = QFont(hdr.font())
        f.setWeight(QFont.Weight.DemiBold)  # as the theme draws the titles
        fm = QFontMetrics(f)
        icon_only = t.iconSize().width() + 14  # the status dot and the boot sign need no text room
        widths = {}
        for col, title in enumerate(COLUMNS):
            if col == COL_FILL:
                continue
            need = fm.horizontalAdvance(title) + 2 * HEADER_PAD + (ARROW_ROOM if col == self.sort[0] else 0)
            contents = icon_only if col == COL_DOT else t.sizeHintForColumn(col)
            widths[col] = max(contents, need, 28)
        spare = t.viewport().width() - sum(widths.values())
        growing = [c for c in widths if c not in (COL_DOT, COL_BOOT)]
        if spare < 0:  # too narrow: the Name column gives way (long names end in "…") before anything is cut off
            widths[COL_NAME] -= min(-spare, max(0, widths[COL_NAME] - NAME_MIN_W))
        elif spare > 0:
            total = sum(widths[c] for c in growing)
            for c in growing:
                widths[c] += int(spare * widths[c] / total)
            widths[COL_UPTIME] += t.viewport().width() - sum(widths.values())  # what rounding left over
        for col, w in widths.items():
            hdr.resizeSection(col, w)
        hdr.resizeSection(COL_FILL, 0)

    def eventFilter(self, obj, ev) -> bool:
        if obj is self.table.viewport() and ev.type() == QEvent.Type.Resize:
            self._fit_columns()  # the visible width changed (window resized): share it out again
        return super().eventFilter(obj, ev)

    def _row_of(self, vmid: int) -> int | None:
        for r in range(self.table.rowCount()):
            item = self.table.item(r, COL_ID)
            if item is not None and item.data(Qt.ItemDataRole.UserRole) == vmid:
                return r
        return None

    def _sort_changed(self, col: int, order) -> None:
        if col == COL_FILL:  # the empty column on the right: keep the order the user chose before
            self.table.sortByColumn(*self.sort)
            return
        self.sort = (col, order)
        self._apply_filter()
        self._fit_columns()

    def _hide_stopped_changed(self, on: bool) -> None:
        if bool(self.prefs.get("hide_stopped")) != on:
            self.prefs["hide_stopped"] = on
            if self.on_prefs_changed is not None:
                self.on_prefs_changed()
        self._apply_filter()

    def _apply_filter(self) -> None:
        hide = self.hide_stopped.isChecked()
        status = {g["vmid"]: g.get("status") for g in self.guests}
        for r in range(self.table.rowCount()):
            item = self.table.item(r, COL_ID)
            vmid = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            self.table.setRowHidden(r, hide and status.get(vmid) != "running")
        shown = [v for v in self.selected_vmids() if not self.table.isRowHidden(self._row_of(v))]
        if shown != self.selected_vmids():  # a hidden guest must not be acted on unseen
            self._select(shown)

    # -- state -------------------------------------------------------------------------------------

    def _show_state(self, title: str, text: str, wake: bool) -> None:
        self.state_title.setText(title)
        self.state_text.setText(text)
        self.state_wake.setVisible(wake)
        self.stack.setCurrentIndex(0)

    def _report_state(self) -> None:
        if self.on_state is not None:
            self.on_state(self.host.id, "online" if self.online else "offline")

    def _update_header(self) -> None:
        if self.online:
            self.pill.set("Online", "online")
        elif time.monotonic() < self.waking_until:
            self.pill.set("Waking…", "unknown")
        elif self.online is False:
            self.pill.set("Offline", "offline")
        else:
            self.pill.set("Connecting…", "unknown")
        self.wake_btn.setVisible(bool(self.host.mac) and not self.online)
        self.shutdown_btn.setEnabled(bool(self.online))
        self.wall_btn.setEnabled(bool(self.online))
        self.reboot_btn.setEnabled(bool(self.online))
        self.console_btn.setEnabled(bool(self.online))
        self.upgrade_btn.setEnabled(bool(self.online))
        if self.online and time.monotonic() - self.updates_at > UPDATES_EVERY_S:
            self._count_updates()
        self.new_btn.setEnabled(bool(self.online))
        self.new_vm_btn.setEnabled(bool(self.online))
        self.jobs_btn.setEnabled(bool(self.online))
        self.bulk_start_btn.setEnabled(bool(self.online))
        self.bulk_stop_btn.setEnabled(bool(self.online))

    def set_host(self, host: Host) -> None:
        """The host's settings changed (Edit…)."""
        self.host = host
        self.title.setText(host.name)
        self.caption.setText(host.address)
        self.details.clear()
        self.details_at = 0.0
        self.online = None
        self._update_header()
        self.refresh()

    # -- guests ------------------------------------------------------------------------------------

    def selected_vmids(self) -> list[int]:
        """The selected guests' IDs, top to bottom (Ctrl/Shift-click selects several)."""
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        return [self.table.item(r, COL_ID).data(Qt.ItemDataRole.UserRole) for r in rows
                if self.table.item(r, COL_ID) is not None]

    def selected_vmid(self) -> int | None:
        ids = self.selected_vmids()
        return ids[0] if len(ids) == 1 else None

    def selected(self) -> dict | None:
        """The selected guest — only when exactly one is selected."""
        vmid = self.selected_vmid()
        return next((g for g in self.guests if g["vmid"] == vmid), None)

    def selected_guests(self) -> list[dict]:
        by_id = {g["vmid"]: g for g in self.guests}
        return [by_id[v] for v in self.selected_vmids() if v in by_id]

    def _select(self, vmids: list[int]) -> None:
        sel = self.table.selectionModel()
        sel.clearSelection()
        flags = sel.SelectionFlag.Select | sel.SelectionFlag.Rows
        for vmid in vmids:
            row = self._row_of(vmid)
            if row is not None:
                sel.select(self.table.model().index(row, 0), flags)

    def _update_actions(self) -> None:
        many = self.selected_guests()
        if len(many) > 1:  # several: what can be done to all of them together
            startable = any(g.get("status") == "stopped" and not g.get("template") for g in many)
            up = any(g.get("status") == "running" for g in many)
            enabled = {key: False for key in self.act}
            enabled.update(start=startable, shutdown=up, stop=up, reboot=up)
        else:
            g = self.selected()
            running = bool(g) and g.get("status") == "running"
            stopped = bool(g) and g.get("status") == "stopped"
            template = bool(g) and bool(g.get("template"))  # a template is copied, never started
            enabled = {"start": stopped and not template, "shutdown": running, "stop": running, "reboot": running,
                       "console": running, "files": running, "agent": self._agent_missing(g),
                       "edit": bool(g), "notes": bool(g), "snapshots": bool(g) and not template,
                       "backups": bool(g),
                       "graphs": bool(g),
                       "delete": stopped}
        for key, b in self.act.items():
            b.setEnabled(bool(self.online) and enabled[key])

    def _context_menu(self, pos) -> None:
        if not self.selected_guests():
            return
        menu = QMenu(self)
        for key, b in self.act.items():
            if key == "console":
                sub = menu.addMenu("Console")
                sub.setEnabled(b.isEnabled())
                for how, title in CONSOLE_WAYS:
                    sub.addAction(title).triggered.connect(lambda _=False, h=how: self.open_selected_console(h))
                continue
            if key == "agent" and not b.isEnabled():  # offered only where it is needed
                continue
            a = menu.addAction(b.text())
            a.setEnabled(b.isEnabled())
            a.triggered.connect(lambda _=False, k=key: self.guest_action(k))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def guest_action(self, key: str) -> None:
        many = self.selected_guests()
        if len(many) > 1:
            if key in MULTI:
                self.multi_action(key, many)
            return
        g = self.selected()
        if g is None:
            return
        what = f"{'container' if g['type'] == 'lxc' else 'VM'} {g['vmid']} ({g.get('name', '')})"
        if key in ("start", "shutdown", "stop", "reboot"):
            texts = {
                "shutdown": ("Shut it down?", "Asks the operating system inside to shut down cleanly.", "Shut Down",
                             False),
                "stop": ("Stop it at once?", "Cuts it off immediately, like pulling the plug: unsaved work is lost. "
                         "Use this only if Shut Down does not work.", "Stop", True),
                "reboot": ("Reboot it?", "Restarts it cleanly.", "Reboot", False),
            }
            if key in texts:
                title, body, action, destructive = texts[key]
                if not confirm(self, title, f"{what}\n\n{body}", action, destructive):
                    return
            self._run_task(lambda pve: pve.guest_action(g["node"], g["type"], g["vmid"], key),
                           g["node"], f"{key.capitalize()} sent to {what}", f"{key.capitalize()} {what}",
                           started=key in ("start", "reboot"))
        elif key == "console":
            self.open_console(g, self.prefs.get("console", "auto"))
        elif key == "files":
            self.open_files(g)
        elif key == "agent":
            self.install_agent(g)
        else:
            from . import guest_dialogs
            if key == "graphs":  # a window of its own, for any screen; it holds no reference to this page
                make, host = self.make_client, self.host
                guest_dialogs.show_graphs(f"{host.id}/{g['vmid']}", lambda: make(host), self.runner, g, host.name,
                                          self.prefs, self.on_prefs_changed)
                return
            if key == "backups":  # a backup takes a while: the window stays beside the app
                from .backups import BackupsDialog
                dlg = BackupsDialog(self, self.client, self.runner, g)
                dlg.finished.connect(lambda *_: self.refresh())
                dlg.show()
                return
            if key == "notes":  # beside the main window, not in front of it
                dlg = guest_dialogs.NotesDialog(self, self.client, self.runner, g)
                dlg.finished.connect(lambda *_: self._refresh_details(force=True))  # the notes tooltip
                dlg.show()
                return
            opener = {"edit": guest_dialogs.EditGuestDialog, "snapshots": guest_dialogs.SnapshotsDialog,
                      "graphs": guest_dialogs.GraphsDialog, "delete": guest_dialogs.DeleteDialog}[key]
            dlg = opener(self, self.client, self.runner, g)
            dlg.finished.connect(lambda *_: (self.refresh(), self._refresh_details(force=True)))
            dlg.open()

    def multi_action(self, key: str, many: list[dict]) -> None:
        """Several selected guests: Start and Shut Down go through Bulk (one Proxmox task, in boot order); Stop and
        Reboot are sent to each."""
        if key == "start":
            self.open_bulk("start", [g["vmid"] for g in many])
            return
        if key == "shutdown":
            self.open_bulk("shutdown", [g["vmid"] for g in many])
            return
        up = [g for g in many if g.get("status") == "running"]
        if not up:
            return
        names = ", ".join(f"{g.get('name', '')} ({g['vmid']})" for g in up)
        count = f"{len(up)} guest{'s' if len(up) != 1 else ''}"
        if key == "stop":
            ok = confirm(self, f"Stop {count} at once?", f"{names}\n\nCuts them off immediately, like pulling the "
                         "plug: unsaved work is lost. Use this only if Shut Down does not work.", "Stop", True)
        else:
            ok = confirm(self, f"Reboot {count}?", f"{names}\n\nRestarts them cleanly.", "Reboot", False)
        if not ok:
            return
        pve = self.client()

        def job():
            started = [(g["node"], pve.guest_action(g["node"], g["type"], g["vmid"], key)) for g in up]
            problems = []
            for node, upid in started:
                try:
                    if isinstance(upid, str) and upid.startswith("UPID:"):
                        pve.wait_task(node, upid, timeout=300)
                except PveError as e:
                    problems.append(str(e))
            if problems:
                raise PveError("\n".join(problems))

        def finished(_r, err):
            if err is not None:
                error(self, f"{key.capitalize()} {count}", str(err))
            else:
                self.notify(f"{key.capitalize()} sent to {count}")
            self.details_at = 0.0
            self.refresh()
            if key == "reboot" and err is None:
                QTimer.singleShot(AFTER_START_S * 1000, lambda: self._refresh_details(force=True))

        self.notify(f"{key.capitalize()} {count}…")
        self.runner.run(job, finished)
        self.refresh()  # the tasks appear in the Tasks panel at once

    def open_bulk(self, action: str, preselect: list[int] | None = None) -> None:
        if not self.online or not self.guests:
            return
        from .bulk import BulkDialog

        def done():
            self.details_at = 0.0
            self.refresh()
            if action == "start":  # booted guests have their addresses a little later
                QTimer.singleShot(AFTER_START_S * 1000, lambda: self._refresh_details(force=True))

        dlg = BulkDialog(self, self.client, self.runner, self.guests, self.details, action, preselect,
                         on_started=self.refresh, on_done=done)
        dlg.show()

    # -- tasks -------------------------------------------------------------------------------------

    def open_task_log(self, task: dict) -> None:
        upid = task.get("upid", "")
        dlg = self.task_logs.get(upid)
        if dlg is None:
            title = tasks.describe(task, {g["vmid"]: g for g in self.guests})
            dlg = TaskLogDialog(self, self.client, self.runner, task, title, on_end=self.refresh)
            self.task_logs[upid] = dlg
            closed = [u for u, d in self.task_logs.items() if not d.isVisible() and not d.polling]
            for u in closed[:-CLOSED_LOGS_KEPT]:  # oldest first; one still waiting for an answer is kept
                self.task_logs.pop(u).deleteLater()
        else:
            dlg.resume()
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def stop_task(self, task: dict) -> None:
        if not tasks.running(task):
            return
        title = tasks.describe(task, {g["vmid"]: g for g in self.guests})
        if not confirm(self, "Stop this task?", f"{title}\n\nProxmox stops it where it is. A backup or a copy "
                       "stopped halfway is left unfinished.", "Stop Task", destructive=True):
            return
        pve, node, upid = self.client(), task.get("node", ""), task.get("upid", "")

        def finished(_r, err):
            if err is not None:
                error(self, "Stop task", str(err))
            self.refresh()

        self.runner.run(lambda: pve.stop_task(node, upid), finished)

    # -- consoles ----------------------------------------------------------------------------------

    def open_selected_console(self, how: str) -> None:
        g = self.selected()
        if g is not None and g.get("status") == "running":
            self.open_console(g, how)

    def open_console(self, g: dict, how: str = "auto") -> None:
        """auto: SPICE when the VM offers it and remote-viewer is here, otherwise the built-in console."""
        what = f"{g.get('name', '')} ({g['vmid']})"
        if how == "browser":
            QDesktopServices.openUrl(QUrl(self.client().console_url(g["node"], g["type"], g["vmid"])))
            self.notify(f"Console of {what} opened in the browser (it needs a Proxmox login there)")
            return
        if how == "vnc" or g["type"] == "lxc":
            if how == "spice":
                self.notify("SPICE is for VMs: containers open in the built-in console")
            self.open_builtin_console(g)
            return
        pve, node, vmid = self.client(), g["node"], g["vmid"]

        def job():
            if how == "auto" and not (spice.viewer() and pve.has_spice(node, vmid)):
                return None
            if not spice.viewer():
                raise FileNotFoundError(f"remote-viewer was not found. {spice.install_hint()}")
            return pve.spice_config(node, vmid)

        def done(cfg, err):
            if err is not None:
                error(self, "SPICE console", f"{err}\n\nThe built-in console works without SPICE.")
                return
            if cfg is None:
                self.open_builtin_console(g)
                return
            try:
                spice.launch(cfg)
            except OSError as e:
                error(self, "SPICE console", str(e))
                return
            self.notify(f"SPICE console of {what} opened in remote-viewer")

        self.notify(f"Opening the console of {what}…")
        self.runner.run(job, done)

    def open_builtin_console(self, g: dict) -> None:
        from . import console
        # the console's thread calls this: it must not hold this page (a widget) — only the host and the client type
        node, kind, vmid, make, host = g["node"], g["type"], g["vmid"], self.make_client, self.host
        console.show(f"{host.id}/{vmid}", f"{g.get('name', '')} ({vmid}) — {host.name}",
                     lambda: make(host).open_vnc(node, kind, vmid))

    def new_vm(self) -> None:
        if not self.nodes:
            return
        from .vm_dialog import CreateVmDialog
        dlg = CreateVmDialog(self, self.client, self.runner, self.nodes, remember=self.remember_setup_disc)
        dlg.finished.connect(lambda *_: self._after_new_vm(dlg))
        dlg.open()

    def _after_new_vm(self, dlg) -> None:
        if dlg.created:
            self.notify(dlg.done_text)
            self.details_at = 0.0
        if dlg.boot_keys:  # Windows' installer disc asks for a key before it boots: pressed here, not in the window
            node, vmid = dlg.boot_keys
            pve = self.client()
            self.runner.run(lambda: setupdisc.press_boot_key(pve, node, vmid),
                            lambda n, err: self.notify(f"VM {vmid}: Enter pressed at the installer's question — "
                                                       "Windows Setup runs by itself now" if n else
                                                       f"VM {vmid}: Enter could not be pressed — press a key in its "
                                                       "Console at “Press any key to boot from CD”"))
        self.refresh()

    # -- setup discs of new VMs --------------------------------------------------------------------

    def remember_setup_disc(self, disc: dict) -> None:
        """Keeps a new VM's setup disc in the settings until it is taken away (it holds the user's password)."""
        self.prefs.setdefault("setup_discs", []).append({**disc, "host": self.host.id})
        if self.on_prefs_changed:
            self.on_prefs_changed()

    def _tidy_setup_discs(self) -> None:
        """Takes away the discs of this host's VMs that are set up (or gone) — checked once a minute."""
        discs = [d for d in self.prefs.get("setup_discs") or [] if d.get("host") == self.host.id]
        if not discs or self.discs_inflight or time.monotonic() < self.discs_at:
            return
        self.discs_inflight, self.discs_at = True, time.monotonic() + SETUP_DISCS_EVERY_S
        pve, guests = self.client(), [dict(g) for g in self.guests]

        def done(result, err):
            self.discs_inflight = False
            if err is not None or not result:
                return  # tried again the next time
            gone, said = result
            if gone:
                self.prefs["setup_discs"] = [d for d in self.prefs.get("setup_discs") or []
                                             if d.get("volid") not in gone]
                if self.on_prefs_changed:
                    self.on_prefs_changed()
            for text in said:
                self.notify(text)

        self.runner.run(lambda: setupdisc.tidy(pve, discs, guests), done)

    def new_container(self) -> None:
        if not self.nodes:
            return
        from .guest_dialogs import CreateContainerDialog
        dlg = CreateContainerDialog(self, self.client, self.runner, self.nodes)
        dlg.finished.connect(lambda *_: self.refresh())
        dlg.open()

    def _run_task(self, start: Callable[[Pve], str], node: str, done_text: str, failed_title: str,
                  started: bool = False) -> None:
        pve = self.client()

        def job():
            upid = start(pve)
            if isinstance(upid, str) and upid.startswith("UPID:"):
                pve.wait_task(node, upid, timeout=300)

        def finished(_r, err):
            if err is not None:
                error(self, failed_title, str(err))
            else:
                self.notify(done_text)
            self.details_at = 0.0  # read the addresses again with the new state
            self.refresh()
            if started and err is None:  # a guest that just booted has its address a little later
                QTimer.singleShot(AFTER_START_S * 1000, lambda: self._refresh_details(force=True))

        self.notify(f"{failed_title}…")
        self.runner.run(job, finished)

    # -- the host itself ---------------------------------------------------------------------------

    def wake(self) -> None:
        if not self.host.mac:
            error(self, "Wake-on-LAN", "Set this host's MAC address first (Edit…).")
            return
        host = self.host

        def finished(_r, err):
            if err is not None:
                error(self, "Wake-on-LAN", str(err))
                return
            self.waking_until = time.monotonic() + WAKE_TIMEOUT_S
            self.notify(f"Wake-on-LAN packet sent to {host.mac}")
            self._update_header()
            self._show_state("Waking up…", "The Wake-on-LAN packet was sent. Waiting for Proxmox to answer "
                             "(this can take a few minutes).", wake=False)
            QTimer.singleShot(5000, self.refresh)

        self.runner.run(lambda: wol.send(host.mac, host.broadcast or "255.255.255.255"), finished)

    def node_command(self, command: str) -> None:
        if not self.nodes:
            return
        running = sum(1 for g in self.guests if g.get("status") == "running")
        node = self.nodes[0]
        if command == "shutdown":
            ok = confirm(self, "Shut down the host?",
                         f"{self.host.name} ({node}) shuts down its {running} running guest(s) first and then turns "
                         f"off.{' It can be woken again with Wake-on-LAN.' if self.host.mac else ''}",
                         "Shut Down Host", destructive=True)
        else:
            ok = confirm(self, "Reboot the host?",
                         f"{self.host.name} ({node}) shuts down its {running} running guest(s) and restarts.",
                         "Reboot Host", destructive=True)
        if not ok:
            return
        pve = self.client()

        def finished(_r, err):
            if err is not None:
                error(self, "Host", str(err))
            else:
                self.notify(f"{command.capitalize()} sent to {self.host.name}")
            QTimer.singleShot(3000, self.refresh)

        self.runner.run(lambda: pve.node_command(node, command), finished)

    def open_backup_jobs(self) -> None:
        if not self.nodes:
            return
        if self.jobs_dialog is None:
            from .backup_jobs import BackupJobsDialog
            self.jobs_dialog = BackupJobsDialog(self, self.client, self.runner, self.nodes, self.host.name)
        else:
            self.jobs_dialog.load()
        self.jobs_dialog.show()
        self.jobs_dialog.raise_()
        self.jobs_dialog.activateWindow()

    def open_deleted_backups(self) -> None:
        if not self.nodes:
            return
        if self.deleted_dialog is None:
            from .backups import DeletedBackupsDialog
            self.deleted_dialog = DeletedBackupsDialog(self, self.client, self.runner, self.host.name)
        else:
            self.deleted_dialog.load()
        self.deleted_dialog.show()
        self.deleted_dialog.raise_()
        self.deleted_dialog.activateWindow()

    # -- the host's shell and upgrade (over SSH) -----------------------------------------------------------------

    def _with_ssh(self, then: Callable[[], None]) -> None:
        """Runs `then` once the host's SSH is set up — asking for it the first time (or when its key changed)."""
        from . import host_shell
        if host_shell.ready(self.host):
            then()
            return
        dlg = host_shell.SshDialog(self, self.host, self.runner, self.on_host_changed, first_time=True)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            then()

    def _shell(self, command: list[str] | tuple = (), what: str = "Console") -> None:
        from ..core.ssh import SshError
        from . import host_shell
        try:
            host_shell.open_shell(self.host, command, what)
        except (SshError, OSError) as e:
            error(self, "Console", str(e))

    def open_host_console(self) -> None:
        self._with_ssh(self._shell)

    # -- files and the guest agent -------------------------------------------------------------------

    def _agent_missing(self, g: dict | None) -> bool:
        """A running VM whose QEMU guest agent does not answer (as the last look at its addresses found)."""
        return (bool(g) and g["type"] == "qemu" and g.get("status") == "running" and g["vmid"] in self.details
                and (self.details.get(g["vmid"]) or {}).get("source") != "guest")

    def open_files(self, g: dict) -> None:
        """Files…: this computer ↔ the guest — a VM through its guest agent (and the network), a container through the
        host's SSH with the app's key. A VM whose agent does not answer is offered the agent first."""
        from ..core import guestfiles
        host = self.host
        if self._agent_missing(g):
            if confirm(self, "Install the guest agent?", f"VM {g['vmid']} ({g.get('name', '')}): its QEMU guest agent "
                       "does not answer, and Files needs it. The app can install it through the VM's console.",
                       "Install Guest Agent…"):
                self.install_agent(g)
            return
        title = f"{'Container' if g['type'] == 'lxc' else 'VM'} {g['vmid']} ({g.get('name', '')})"
        if g["type"] == "lxc":
            def go():
                from . import host_shell
                s = host_shell.settings_of(host)
                if not s.get("key"):
                    error(self, "Files", "Copies to and from a container go over SSH with this app's key: turn on "
                                         "'Use a key' in SSH Settings (the arrow beside Console, at the top).")
                    return
                port, user = int(s.get("port", 22)), str(s.get("user") or "root")
                self._show_files(title, "Container · over the host's SSH",
                                 lambda: guestfiles.ContainerFiles(host.hostname, port, user, g["vmid"]))
            self._with_ssh(go)
            return
        client = self.client()

        def make():
            os_name = guestfiles.os_of(client.guest_config(g["node"], "qemu", g["vmid"]))
            return guestfiles.VmFiles(client, g["node"], g["vmid"], os_name,
                                      guestfiles.address_towards(host.hostname, host.port))
        self._show_files(title, "", make)

    def _show_files(self, title: str, subtitle: str, make) -> None:
        from . import files_window
        dlg = files_window.FilesWindow(self, title, subtitle, make, self.runner)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.show()

    def install_agent(self, g: dict) -> None:
        from . import agent_setup
        dlg = agent_setup.AgentSetupDialog(self, self.client, self.runner, g)
        dlg.finished.connect(lambda *_: self._refresh_details(force=True))
        dlg.show()

    def ssh_settings(self) -> None:
        from . import host_shell
        host_shell.SshDialog(self, self.host, self.runner, self.on_host_changed).exec()

    def open_upgrade(self) -> None:
        if not self.nodes:
            return
        from . import host_shell
        if self.upgrade_dialog is None:
            self.upgrade_dialog = host_shell.UpgradeDialog(
                self, self.client, self.runner, self.host, self.nodes[0],
                lambda: self._with_ssh(lambda: self._shell(host_shell.UPGRADE, "Upgrade")))
            self.upgrade_dialog.finished.connect(lambda *_: self._count_updates())
        else:
            self.upgrade_dialog.load()
        self.upgrade_dialog.show()
        self.upgrade_dialog.raise_()
        self.upgrade_dialog.activateWindow()

    def _count_updates(self) -> None:
        """«Upgrade (12)» on the button — counted when the host comes online, then every half hour."""
        if not self.nodes:
            return
        self.updates_at = time.monotonic()
        pve, node = self.client(), self.nodes[0]

        def done(updates, err):
            n = 0 if err is not None else len(updates)
            self.upgrade_btn.setText(f"Upgrade ({n})" if n else "Upgrade")
            self.upgrade_btn.setToolTip(f"{n} package update{'' if n == 1 else 's'} waiting on the host" if n else
                                        "The package updates waiting on the host, and the upgrade")

        self.runner.run(lambda: pve.apt_updates(node), done)

    def open_wall(self) -> None:
        from . import graph_wall
        make, host = self.make_client, self.host  # the wall holds no reference to this page
        graph_wall.show_wall(host.id, lambda: make(host), self.runner, host.name, self.prefs, self.on_prefs_changed)

    def open_web_ui(self) -> None:
        QDesktopServices.openUrl(QUrl(f"https://{self.host.hostname}:{self.host.port}/"))


__all__ = ["HostView", "PveError", "read_details"]
