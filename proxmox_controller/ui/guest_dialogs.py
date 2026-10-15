"""Dialogs for one guest (edit, snapshots, graphs, delete) and the new-container form."""

from __future__ import annotations

import html
import re
import time
from typing import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFontDatabase, QKeySequence, QShortcut
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton,
                               QRadioButton, QSpinBox, QSplitter, QTextBrowser, QVBoxLayout, QWidget)

from ..core import vmhw
from ..core.pve import Pve, PveError
from . import geometry
from .chart import LineChart, align
from .startup_fields import StartupFields
from .vm_hardware import HardwareFields
from .widgets import button, confirm, error, fit_to_width, gib, info, label, mem_text
from .worker import Runner

HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9-]{1,63})*$")
SNAPNAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,39}$")
CIDR = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def kind_name(g: dict) -> str:
    return "container" if g["type"] == "lxc" else "VM"


def parse_net(text: str) -> dict:
    """'name=eth0,bridge=vmbr0,ip=dhcp' → {'name': 'eth0', 'bridge': 'vmbr0', 'ip': 'dhcp'} (order kept)."""
    out = {}
    for part in (text or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def format_net(fields: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in fields.items() if v != "")


def notes_change(text: str) -> dict:
    """The config change for new notes. Empty notes are removed (Proxmox wants delete=description, not an empty
    value)."""
    return {"description": text} if text.strip() else {"delete": "description"}


def disk_size_gb(volume: str) -> int:
    m = re.search(r"size=(\d+(?:\.\d+)?)([TGMK])", volume or "")
    if not m:
        return 0
    n, unit = float(m.group(1)), m.group(2)
    return int(n * {"T": 1024, "G": 1, "M": 1 / 1024, "K": 1 / 1048576}[unit])


class _GuestDialog(QDialog):
    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, guest: dict, title: str):
        super().__init__(parent)
        self.client, self.runner, self.g = client, runner, guest
        self.setWindowTitle(f"{title} — {kind_name(guest)} {guest['vmid']} ({guest.get('name', '')})")
        self.setModal(True)
        self.lay = QVBoxLayout(self)
        self.lay.setSpacing(12)
        self.status = label("", "dim", wrap=True)

    def busy(self, text: str) -> None:
        self.status.setText(text)
        self.setEnabled(False)

    def idle(self, text: str = "") -> None:
        self.status.setText(text)
        self.setEnabled(True)

    def run_task(self, start: Callable[[Pve], object], done: Callable[[], None], what: str) -> None:
        pve, node = self.client(), self.g["node"]

        def job():
            upid = start(pve)
            if isinstance(upid, str) and upid.startswith("UPID:"):
                pve.wait_task(node, upid, timeout=600)

        def finished(_r, err):
            if err is not None:
                self.idle()
                error(self, what, str(err))
            else:
                done()

        self.busy(f"{what}…")
        self.runner.run(job, finished)


# -- edit ------------------------------------------------------------------------------------------

class EditGuestDialog(_GuestDialog):
    def __init__(self, parent, client, runner, guest):
        super().__init__(parent, client, runner, guest, "Edit")
        self.lxc = guest["type"] == "lxc"
        self.original: dict = {}
        self.usb_limit = vmhw.USB_SLOTS
        self.pending_after: list[str] = []
        self.width_ = 480 if self.lxc else 580
        form = QFormLayout()
        form.setVerticalSpacing(8)
        self.name = QLineEdit()
        self.cores = QSpinBox()
        self.cores.setRange(1, 512)
        self.memory = QSpinBox()
        self.memory.setRange(16, 4 * 1024 * 1024)
        self.memory.setSingleStep(256)
        self.memory.setSuffix(" MiB")
        self.swap = QSpinBox()
        self.swap.setRange(0, 4 * 1024 * 1024)
        self.swap.setSingleStep(256)
        self.swap.setSuffix(" MiB")
        self.onboot = QCheckBox("Start at boot")
        self.disk = label("", "dim")
        self.grow = QSpinBox()
        self.grow.setRange(0, 16384)
        self.grow.setSuffix(" GiB")
        self.bridge = QComboBox()
        self.bridge.setEditable(True)
        self.dhcp = QRadioButton("DHCP")
        self.static = QRadioButton("Static")
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("192.168.1.50/24")
        self.gw = QLineEdit()
        self.gw.setPlaceholderText("192.168.1.1")
        mode = QButtonGroup(self)
        mode.addButton(self.dhcp)
        mode.addButton(self.static)
        self.dhcp.toggled.connect(self._mode)
        self.notes = QPlainTextEdit()
        self.notes.setFixedHeight(70)
        form.addRow("Hostname" if self.lxc else "Name", self.name)
        form.addRow("CPU cores", self.cores)
        form.addRow("Memory", self.memory)
        self.hw = None if self.lxc else HardwareFields(form)  # display, sound, USB: VMs only
        if self.lxc:
            form.addRow("Swap", self.swap)
            form.addRow("Disk", self.disk)
            form.addRow("Grow disk by", self.grow)
            net = QHBoxLayout()
            net.setSpacing(12)
            net.addWidget(self.dhcp)
            net.addWidget(self.static)
            net.addStretch(1)
            form.addRow("Network bridge", self.bridge)
            form.addRow("Address", net)
            form.addRow("IP / prefix", self.ip)
            form.addRow("Gateway", self.gw)
        form.addRow("", self.onboot)
        self.startup = StartupFields(form, self.onboot, lambda: fit_to_width(self, self.width_))
        form.addRow("Notes", self.notes)
        self.lay.addLayout(form)
        self.lay.addWidget(label("A disk can only grow, never shrink. CPU and memory changes apply at once to "
                                 "containers; a VM may need a restart.", "caption", wrap=True))
        self.lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setProperty("kind", "suggested")
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        self.lay.addWidget(buttons)
        fit_to_width(self, self.width_)
        self.busy("Reading the configuration…")
        pve, g, lxc = self.client(), guest, self.lxc

        def load():
            devices = None
            if not lxc:
                try:
                    devices = pve.usb_devices(g["node"])
                except PveError:
                    pass  # shown as "could not read"; the rest of the form still works
            return (pve.guest_config(g["node"], g["type"], g["vmid"]), pve.bridges(g["node"]) if lxc else [],
                    devices, pve.version())

        self.runner.run(load, self._loaded)

    def _loaded(self, data, err) -> None:
        if err is not None:
            self.idle()
            error(self, "Edit", str(err))
            self.reject()
            return
        cfg, bridges, devices, version = data
        self.original = cfg
        major = str((version or {}).get("version", "8")).split(".")[0]
        self.usb_limit = vmhw.USB_SLOTS if not major.isdigit() or int(major) >= 8 else vmhw.USB_SLOTS_OLD
        if self.hw is not None:
            self.hw.load(cfg, devices or [])
            if devices is None:
                self.hw.usb.addItem("Could not read the host's USB devices.")
        self.name.setText(str(cfg.get("hostname" if self.lxc else "name", self.g.get("name", ""))))
        self.cores.setValue(int(cfg.get("cores", 1)))
        self.memory.setValue(int(cfg.get("memory", 512)))
        self.swap.setValue(int(cfg.get("swap", 0)))
        self.onboot.setChecked(bool(int(cfg.get("onboot", 0))))
        self.startup.load(cfg)
        self.notes.setPlainText(str(cfg.get("description", "")))
        if self.lxc:
            self.disk.setText(f"{disk_size_gb(cfg.get('rootfs', ''))} GiB  ({cfg.get('rootfs', '').split(',')[0]})")
            net = parse_net(cfg.get("net0", ""))
            self.bridge.addItems(bridges or [net.get("bridge", "vmbr0")])
            self.bridge.setCurrentText(net.get("bridge", "vmbr0"))
            if net.get("ip", "dhcp") == "dhcp":
                self.dhcp.setChecked(True)
            else:
                self.static.setChecked(True)
                self.ip.setText(net.get("ip", ""))
                self.gw.setText(net.get("gw", ""))
            self._mode()
        self.idle()
        fit_to_width(self, self.width_)

    def _mode(self) -> None:
        on = self.static.isChecked()
        self.ip.setEnabled(on)
        self.gw.setEnabled(on)

    def changes(self) -> dict:
        cfg = self.original
        out = {}
        name_key = "hostname" if self.lxc else "name"
        if self.name.text().strip() != str(cfg.get(name_key, "")):
            out[name_key] = self.name.text().strip()
        for key, w in (("cores", self.cores), ("memory", self.memory)) + ((("swap", self.swap),) if self.lxc else ()):
            if w.value() != int(cfg.get(key, -1)):
                out[key] = w.value()
        if int(self.onboot.isChecked()) != int(cfg.get("onboot", 0)):
            out["onboot"] = int(self.onboot.isChecked())
        if self.notes.toPlainText() != str(cfg.get("description", "")):
            out.update(notes_change(self.notes.toPlainText()))
        if self.lxc:
            net = parse_net(cfg.get("net0", ""))
            new = dict(net)
            new["bridge"] = self.bridge.currentText().strip()
            if self.dhcp.isChecked():
                new["ip"] = "dhcp"
                new.pop("gw", None)
            else:
                new["ip"] = self.ip.text().strip()
                new["gw"] = self.gw.text().strip()
            if new != net:
                out["net0"] = format_net(new)
        out = vmhw.merge(out, self.startup.changes(cfg))
        if self.hw is not None:
            out = vmhw.merge(out, self.hw.changes(cfg, self.usb_limit))
        return out

    def save(self) -> None:
        if self.lxc and not HOSTNAME.match(self.name.text().strip()):
            error(self, "Edit", "The hostname may use letters, digits and hyphens only.")
            return
        if self.lxc and self.static.isChecked():
            if not CIDR.match(self.ip.text().strip()):
                error(self, "Edit", "Write the static address with its prefix, for example 192.168.1.50/24.")
                return
            if self.gw.text().strip() and not IPV4.match(self.gw.text().strip()):
                error(self, "Edit", "The gateway must be an IPv4 address, for example 192.168.1.1.")
                return
        try:
            changes, grow = self.changes(), self.grow.value()
        except ValueError as e:  # too many USB devices
            error(self, "Edit", str(e))
            return
        if not changes and not grow:
            self.accept()
            return
        g = self.g

        def apply(pve: Pve):
            pve.update_config(g["node"], g["type"], g["vmid"], changes)
            if grow:
                pve.resize_disk(g["node"], g["type"], g["vmid"], "rootfs", grow)
            if not self.lxc and g.get("status") == "running":
                self.pending_after = pve.pending(g["node"], g["vmid"])

        self.run_task(apply, self._saved, "Saving")

    PENDING_NAMES = {"vga": "Display", "audio0": "Sound", "cores": "CPU cores", "memory": "Memory"}

    def _saved(self) -> None:
        if self.pending_after:
            names = sorted({self.PENDING_NAMES.get(k, "USB" if k.startswith("usb") else k) for k in self.pending_after})
            info(self, "Saved", f"Saved. {', '.join(names)} will change at the VM's next start: use Reboot here (or "
                                "Shut Down, then Start). A restart from inside the VM is not enough.")
        self.accept()


# -- notes -----------------------------------------------------------------------------------------

class NotesDialog(_GuestDialog):
    """The guest's notes (Proxmox: Summary → Notes): write on the left, see them as Proxmox shows them (Markdown) on
    the right. Ctrl+S saves and stays open; Save saves and closes. It does not block the main window."""

    PLACEHOLDER = ("Notes for this guest — what it is for, addresses, passwords' hints, what to remember.\n\n"
                   "Markdown works:  # Title   - list item   **bold**   [link](https://…)")

    def __init__(self, parent, client, runner, guest):
        super().__init__(parent, client, runner, guest, "Notes")
        self.setModal(False)
        self.title = self.windowTitle()
        self.original = ""
        self.loaded = False
        heads = QHBoxLayout()
        heads.addWidget(label("Write", "heading"), 1)
        heads.addWidget(label("As Proxmox shows it", "heading"), 1)
        self.lay.addLayout(heads)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.editor = QPlainTextEdit()
        self.editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.editor.setPlaceholderText(self.PLACEHOLDER)
        self.preview = QTextBrowser()
        self.preview.setOpenExternalLinks(True)
        split.addWidget(self.editor)
        split.addWidget(self.preview)
        split.setSizes([1, 1])
        self.lay.addWidget(split, 1)
        self.lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Save).setProperty("kind", "suggested")
        buttons.accepted.connect(lambda: self.save(close=True))
        buttons.rejected.connect(self.reject)
        self.lay.addWidget(buttons)
        QShortcut(QKeySequence(QKeySequence.StandardKey.Save), self, activated=lambda: self.save(close=False))
        self.render_timer = QTimer(self)
        self.render_timer.setSingleShot(True)
        self.render_timer.setInterval(150)
        self.render_timer.timeout.connect(self._render)
        self.editor.textChanged.connect(self._changed)
        self.resize(920, 580)
        self.busy("Reading the notes…")
        pve, g = self.client(), guest
        self.runner.run(lambda: pve.guest_config(g["node"], g["type"], g["vmid"]), self._loaded)

    def _loaded(self, cfg, err) -> None:
        if err is not None:
            self.idle()
            error(self, "Notes", str(err))
            return
        self.original = str((cfg or {}).get("description") or "")
        self.editor.setPlainText(self.original)
        self.loaded = True
        self._render()
        self._mark()
        self.idle()
        self.editor.setFocus()

    def dirty(self) -> bool:
        return self.loaded and self.editor.toPlainText() != self.original

    def _changed(self) -> None:
        self.render_timer.start()
        self._mark()

    def _render(self) -> None:
        self.preview.setMarkdown(self.editor.toPlainText())

    def _mark(self) -> None:
        self.setWindowTitle(("• " if self.dirty() else "") + self.title)

    def save(self, close: bool = True) -> None:
        if not self.dirty():
            if close:
                self.accept()
            return
        text, g = self.editor.toPlainText(), self.g
        change = notes_change(text)

        def done():
            self.original = text
            self._mark()
            self.idle("Saved.")
            if close:
                self.accept()

        self.run_task(lambda pve: pve.update_config(g["node"], g["type"], g["vmid"], change), done, "Saving the notes")

    def reject(self) -> None:  # Close, Esc and the window's ✕
        if self.dirty() and not confirm(self, "Discard the changes?", "The notes were changed but not saved.",
                                        "Discard", destructive=True):
            return
        super().reject()


# -- snapshots -------------------------------------------------------------------------------------

class SnapshotsDialog(_GuestDialog):
    def __init__(self, parent, client, runner, guest):
        super().__init__(parent, client, runner, guest, "Snapshots")
        self.lay.addWidget(label("A snapshot saves the guest's disks and settings as they are now, so you can go "
                                 "back to this moment later. Take one before risky changes.", "dim", wrap=True))
        self.list = QListWidget()
        self.list.setMinimumHeight(180)
        self.lay.addWidget(self.list)
        new_row = QHBoxLayout()
        self.snap_name = QLineEdit(time.strftime("snap_%Y%m%d_%H%M"))
        self.snap_name.setMinimumWidth(180)
        self.snap_desc = QLineEdit()
        self.snap_desc.setPlaceholderText("What is about to change (optional)")
        take = button("Take Snapshot", "suggested")
        take.clicked.connect(self.take)
        new_row.addWidget(self.snap_name)
        new_row.addWidget(self.snap_desc, 1)
        new_row.addWidget(take)
        self.lay.addLayout(new_row)
        act = QHBoxLayout()
        self.rollback_btn = button("Roll Back…", "destructive")
        self.rollback_btn.clicked.connect(self.rollback)
        self.delete_btn = button("Delete Snapshot…")
        self.delete_btn.clicked.connect(self.delete)
        close = button("Close")
        close.clicked.connect(self.accept)
        act.addWidget(self.rollback_btn)
        act.addWidget(self.delete_btn)
        act.addStretch(1)
        act.addWidget(close)
        self.lay.addLayout(act)
        self.lay.addWidget(self.status)
        self.list.itemSelectionChanged.connect(self._sel)
        fit_to_width(self, 560)
        self.load()

    def load(self) -> None:
        pve, g = self.client(), self.g
        self.busy("Reading the snapshots…")
        self.runner.run(lambda: pve.snapshots(g["node"], g["type"], g["vmid"]), self._loaded)

    def _loaded(self, snaps, err) -> None:
        self.idle()
        self.list.clear()
        if err is not None:
            self.status.setText(str(err))
            return
        for s in sorted(snaps or [], key=lambda s: s.get("snaptime", 0), reverse=True):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["snaptime"])) if s.get("snaptime") else ""
            text = f"{s['name']}    {when}" + (f"\n{s['description'].strip()}" if s.get("description") else "")
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, s["name"])
            self.list.addItem(item)
        if not snaps:
            self.status.setText("No snapshots yet.")
        self._sel()

    def _sel(self) -> None:
        has = bool(self.list.selectedItems())
        self.rollback_btn.setEnabled(has)
        self.delete_btn.setEnabled(has)

    def _name(self) -> str | None:
        items = self.list.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else None

    def take(self) -> None:
        name, desc = self.snap_name.text().strip(), self.snap_desc.text().strip()
        if not SNAPNAME.match(name):
            error(self, "Snapshot", "The name must start with a letter and use letters, digits, - and _ "
                                    "(2–40 characters).")
            return
        g = self.g
        self.run_task(lambda pve: pve.create_snapshot(g["node"], g["type"], g["vmid"], name, desc),
                      self._after, "Taking the snapshot")

    def rollback(self) -> None:
        name = self._name()
        if name and confirm(self, "Roll back to this snapshot?",
                            f"The {kind_name(self.g)} goes back to “{name}”. Everything that changed since then is "
                            "lost.", "Roll Back", destructive=True):
            g = self.g
            self.run_task(lambda pve: pve.rollback_snapshot(g["node"], g["type"], g["vmid"], name),
                          self._after, "Rolling back")

    def delete(self) -> None:
        name = self._name()
        if name and confirm(self, "Delete this snapshot?", f"“{name}” is removed. The {kind_name(self.g)} itself "
                            "is not changed.", "Delete Snapshot", destructive=True):
            g = self.g
            self.run_task(lambda pve: pve.delete_snapshot(g["node"], g["type"], g["vmid"], name),
                          self._after, "Deleting the snapshot")

    def _after(self) -> None:
        self.snap_name.setText(time.strftime("snap_%Y%m%d_%H%M"))
        self.snap_desc.clear()
        self.load()


# -- graphs ----------------------------------------------------------------------------------------

def show_rrd(rows: list | None, cpu: LineChart, mem: LineChart) -> None:
    """Proxmox's averages for a guest into a CPU chart (% of its cores) and a memory chart with its allocation."""
    rows = [r for r in rows or [] if "cpu" in r or "mem" in r]
    cpu_points = [(r["time"], r.get("cpu", 0) * 100) for r in rows if r.get("cpu") is not None]
    mem_points = [(r["time"], r.get("mem", 0)) for r in rows if r.get("mem") is not None]
    maxmem = max((r.get("maxmem", 0) for r in rows), default=0)
    # memory in GiB (or MiB for small guests) so the axis gets round numbers
    div, unit = ((1 << 30), "GiB") if maxmem >= (1 << 30) else ((1 << 20), "MiB")
    mem.fmt = (lambda v: f"{v:.1f} {unit}") if unit == "GiB" else (lambda v: f"{v:.0f} {unit}")
    mem.short = lambda v: f"{v:g} {unit}"
    cpu.set_data(cpu_points)
    mem.set_data([(t, v / div) for t, v in mem_points],
                 (maxmem / div, f"Allocated {mem_text(maxmem)}") if maxmem else None)


GRAPHS: dict[str, "GraphsDialog"] = {}  # open graph windows, so a second click brings one back


class GraphsDialog(_GuestDialog):
    """CPU and memory of one guest in a window of its own: it can go to another screen, grow to fill it, and stays
    current by itself. It never blocks the app, and several can be open at once."""

    FRAMES = (("hour", "Hour"), ("day", "Day"), ("week", "Week"), ("month", "Month"))
    REFRESH_MS = {"hour": 60_000, "day": 300_000, "week": 1_800_000, "month": 3_600_000}  # Proxmox's step per frame

    def __init__(self, parent, client, runner, guest, host_name: str = ""):
        super().__init__(None, client, runner, guest, "Graphs")  # no parent: free to move to any screen
        self.setModal(False)
        if host_name:
            self.setWindowTitle(f"{self.windowTitle()} — {host_name}")
        self.key = ""
        self.prefs: dict | None = None
        self.save_prefs = None
        self.frame = "hour"
        self.loading = False
        top = QHBoxLayout()
        self.frame_buttons = {}
        group = QButtonGroup(self)
        for key, text in self.FRAMES:
            b = QPushButton(text)
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key: self.load(k))
            group.addButton(b)
            top.addWidget(b)
            self.frame_buttons[key] = b
        top.addStretch(1)
        self.lay.addLayout(top)
        self.lay.addWidget(label("CPU", "heading"))
        self.cpu = LineChart(lambda v: f"{v:.0f} %", lambda v: f"{v:.0f}%")
        self.lay.addWidget(self.cpu, 1)  # the charts take the room when the window grows
        self.lay.addWidget(label("Memory", "heading"))
        self.mem = LineChart(lambda v: f"{v:.2f} GiB", lambda v: f"{v:g} GiB")  # unit set in _loaded
        self.lay.addWidget(self.mem, 1)
        self.lay.addWidget(self.status)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        close.accepted.connect(self.accept)
        self.lay.addWidget(close)
        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.load(self.frame, quiet=True))
        self.finished.connect(lambda *_: self._closed())
        self.resize(760, 560)
        self.frame_buttons["hour"].setChecked(True)
        self.load("hour")

    def load(self, frame: str, quiet: bool = False) -> None:
        self.frame = frame
        self.frame_buttons[frame].setChecked(True)
        self.timer.start(self.REFRESH_MS[frame])
        if self.loading:
            return
        self.loading = True
        pve, g = self.client(), self.g
        if not quiet:
            self.status.setText("Reading the data Proxmox keeps…")
        self.runner.run(lambda: pve.rrd(g["node"], g["type"], g["vmid"], frame),
                        lambda rows, err: self._loaded(rows, err, frame))

    def _loaded(self, rows, err, frame: str = "hour") -> None:
        self.loading = False
        if frame != self.frame:  # another range was chosen meanwhile
            self.load(self.frame, quiet=True)
            return
        if err is not None:
            self.status.setText(str(err))
            return
        show_rrd(rows, self.cpu, self.mem)
        align(self.cpu, self.mem)
        self.status.setText("CPU is a share of the cores this guest has. Averages kept by Proxmox itself. "
                            f"Updated {time.strftime('%H:%M')}.")

    def _closed(self) -> None:
        self.timer.stop()
        geometry.remember(self, f"graphs/{self.key}", self.prefs, self.save_prefs)
        if GRAPHS.get(self.key) is self:
            del GRAPHS[self.key]


def show_graphs(key: str, client: Callable[[], Pve], runner: Runner, guest: dict, host_name: str,
                prefs: dict | None = None, save_prefs: Callable[[], None] | None = None) -> GraphsDialog:
    """Open a guest's graph window (where it was last time), or bring back the one already open."""
    dlg = GRAPHS.get(key)
    if dlg is None:
        dlg = GraphsDialog(None, client, runner, guest, host_name)
        dlg.key = key
        dlg.prefs, dlg.save_prefs = prefs, save_prefs
        geometry.restore(dlg, f"graphs/{key}", prefs)
        GRAPHS[key] = dlg
    dlg.show()
    dlg.raise_()
    dlg.activateWindow()
    return dlg


def close_all_graphs() -> None:
    for dlg in list(GRAPHS.values()):
        dlg.close()


# -- delete ----------------------------------------------------------------------------------------

def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def backup_line(b: dict) -> str:
    """One backup in the Delete window: when, where, how big, its notes; a protected one says it stays."""
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(b.get("ctime", 0)))
    notes = (b.get("notes") or "").strip().splitlines()
    text = f"{when} · {b.get('storage', '')} · {gib(b.get('size'))}" + (f" · {notes[0][:40]}" if notes else "")
    return html.escape(text) + (" — <b>protected, kept</b>" if b.get("protected") else "")


class DeleteDialog(_GuestDialog):
    """Deleting a guest takes its disks and snapshots with it (Proxmox does that). Its backups Proxmox keeps: they are
    listed here and deleted too unless the box is cleared — all but the protected ones, which stay."""

    LISTED = 6  # backups shown one by one; the rest are counted

    def __init__(self, parent, client, runner, guest):
        super().__init__(parent, client, runner, guest, "Delete")
        name = guest.get("name", "")
        self.backups: list[dict] | None = None  # None while they are being looked for
        self.lay.addWidget(label(f"<b>Delete {kind_name(guest)} {guest['vmid']} ({name}) for good?</b>", wrap=True))
        self.gone = label("Its disks, snapshots and settings are removed from the host. This cannot be undone.",
                          "dim", wrap=True)
        self.lay.addWidget(self.gone)
        self.with_backups = QCheckBox()
        self.with_backups.setChecked(True)
        self.with_backups.hide()
        self.lay.addWidget(self.with_backups)
        self.found = label("Looking for its backups…", "dim", wrap=True)
        self.found.setTextFormat(Qt.TextFormat.RichText)  # always: an escaped '&' in notes must not show as '&amp;'
        self.lay.addWidget(self.found)
        self.lay.addWidget(label(f"Type <b>{name}</b> to confirm:", wrap=True))
        self.typed = QLineEdit()
        self.typed.setPlaceholderText(name)
        self.lay.addWidget(self.typed)
        self.lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.go = buttons.addButton("Delete", QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("kind", "destructive")
        self.go.setEnabled(False)
        buttons.accepted.connect(self.delete)
        buttons.rejected.connect(self.reject)
        self.lay.addWidget(buttons)
        self.typed.textChanged.connect(self._can_go)
        fit_to_width(self, 460)
        self._look()

    def _can_go(self) -> None:
        name = self.g.get("name", "")
        self.go.setEnabled(bool(name) and self.typed.text() == name and self.backups is not None)

    def _look(self) -> None:
        pve, g = self.client(), self.g

        def job():
            found = {}
            for key, read in (("snapshots", lambda: pve.snapshots(g["node"], g["type"], g["vmid"])),
                              ("backups", lambda: pve.backups(g["node"], g["vmid"]))):
                try:
                    found[key] = read()
                except PveError as e:
                    found[key] = e
            return found

        self.runner.run(job, lambda found, err: self._show(found if err is None else {"backups": err}))

    def _show(self, found: dict) -> None:
        snaps, backups = found.get("snapshots"), found.get("backups")
        if isinstance(snaps, list) and snaps:
            self.gone.setText(f"Its disks, its {plural(len(snaps), 'snapshot')} and its settings are removed from "
                              "the host. This cannot be undone.")
        if not isinstance(backups, list):
            self.backups = []
            self.found.setText(f"Its backups could not be listed, so none are deleted: {html.escape(str(backups))}")
        else:
            self.backups = backups
            free = [b for b in backups if not b.get("protected")]
            if free:
                self.with_backups.setText(f"Also delete its {plural(len(free), 'backup')} "
                                          f"({gib(sum(b.get('size') or 0 for b in free))})")
                self.with_backups.show()
            lines = [backup_line(b) for b in backups[:self.LISTED]]
            if len(backups) > self.LISTED:
                lines.append(f"…and {len(backups) - self.LISTED} more")
            later = ("<br><i>What stays is found later under Backup Jobs ▾ → Backups of Deleted Guests.</i>"
                     if len(free) < len(backups) else "")
            if not backups:
                self.found.setText("It has no backups.")
            elif free:
                self.found.setText("<br>".join(lines) + later)
            else:
                one = len(backups) == 1
                self.found.setText(f"Its {plural(len(backups), 'backup')} "
                                   f"{'is protected and stays' if one else 'are protected and stay'}:<br>" +
                                   "<br>".join(lines) + later)
        self._can_go()
        fit_to_width(self, 460)

    def delete(self) -> None:
        if self.typed.text() != self.g.get("name") or self.g.get("status") != "stopped" or self.backups is None:
            return
        g, pve = self.g, self.client()
        doomed = [b for b in self.backups if not b.get("protected")] \
            if not self.with_backups.isHidden() and self.with_backups.isChecked() else []

        def job():
            upid = pve.delete_guest(g["node"], g["type"], g["vmid"])
            if isinstance(upid, str) and upid.startswith("UPID:"):
                pve.wait_task(g["node"], upid, timeout=600)
            return pve.delete_backups(g["node"], doomed)  # only once the guest itself is gone

        def finished(failed, err):
            if err is not None:
                self.idle()
                error(self, "Deleting", str(err))
                return
            if failed:
                error(self, "Backups", f"{kind_name(g).capitalize()} {g['vmid']} was deleted, but "
                      f"{plural(len(failed), 'backup')} could not be:\n\n" +
                      "\n".join(f"{b['volid']}: {why}" for b, why in failed))
            self.accept()

        self.busy(f"Deleting it and {plural(len(doomed), 'backup')}…" if doomed else "Deleting…")
        self.runner.run(job, finished)


# -- new container ---------------------------------------------------------------------------------

class CreateContainerDialog(QDialog):
    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, nodes: list[str]):
        super().__init__(parent)
        self.client, self.runner, self.nodes = client, runner, nodes
        self.setWindowTitle("New Container")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        form = QFormLayout()
        form.setVerticalSpacing(8)
        self.node = QComboBox()
        self.node.addItems(nodes)
        self.vmid = QSpinBox()
        self.vmid.setRange(100, 999999999)
        self.hostname = QLineEdit()
        self.hostname.setPlaceholderText("my-container")
        self.template = QComboBox()
        self.download_btn = button("Download…", tooltip="Get more templates from Proxmox")
        self.download_btn.clicked.connect(self.download)
        trow = QHBoxLayout()
        trow.setSpacing(8)
        trow.addWidget(self.template, 1)
        trow.addWidget(self.download_btn)
        self.cores = QSpinBox()
        self.cores.setRange(1, 512)
        self.memory = QSpinBox()
        self.memory.setRange(64, 4 * 1024 * 1024)
        self.memory.setSingleStep(256)
        self.memory.setValue(512)
        self.memory.setSuffix(" MiB")
        self.swap = QSpinBox()
        self.swap.setRange(0, 4 * 1024 * 1024)
        self.swap.setSingleStep(256)
        self.swap.setValue(512)
        self.swap.setSuffix(" MiB")
        self.disk = QSpinBox()
        self.disk.setRange(1, 65536)
        self.disk.setValue(8)
        self.disk.setSuffix(" GiB")
        self.storage = QComboBox()
        drow = QHBoxLayout()
        drow.setSpacing(8)
        drow.addWidget(self.disk)
        drow.addWidget(label("on"))
        drow.addWidget(self.storage, 1)
        self.bridge = QComboBox()
        self.bridge.setEditable(True)
        self.dhcp = QRadioButton("DHCP")
        self.static = QRadioButton("Static")
        self.dhcp.setChecked(True)
        mode = QButtonGroup(self)
        mode.addButton(self.dhcp)
        mode.addButton(self.static)
        nrow = QHBoxLayout()
        nrow.setSpacing(8)
        nrow.addWidget(self.dhcp)
        nrow.addWidget(self.static)
        nrow.addStretch(1)
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("192.168.1.50/24")
        self.gw = QLineEdit()
        self.gw.setPlaceholderText("192.168.1.1")
        self.dhcp.toggled.connect(lambda on: (self.ip.setEnabled(not on), self.gw.setEnabled(not on)))
        self.ip.setEnabled(False)
        self.gw.setEnabled(False)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password2 = QLineEdit()
        self.password2.setEchoMode(QLineEdit.EchoMode.Password)
        self.sshkey = QPlainTextEdit()
        self.sshkey.setPlaceholderText("ssh-ed25519 AAAA… (optional: lets you log in with your key)")
        self.sshkey.setFixedHeight(56)
        self.unprivileged = QCheckBox("Unprivileged container (recommended)")
        self.unprivileged.setChecked(True)
        self.nesting = QCheckBox("Allow nesting (needed to run Docker inside)")
        self.onboot = QCheckBox("Start at boot")
        self.start = QCheckBox("Start it when it is created")
        self.start.setChecked(True)
        if len(nodes) > 1:
            form.addRow("Node", self.node)
        form.addRow("ID", self.vmid)
        form.addRow("Hostname", self.hostname)
        form.addRow("Template", trow)
        form.addRow("CPU cores", self.cores)
        form.addRow("Memory", self.memory)
        form.addRow("Swap", self.swap)
        form.addRow("Disk", drow)
        form.addRow("Network bridge", self.bridge)
        form.addRow("Address", nrow)
        form.addRow("IP / prefix", self.ip)
        form.addRow("Gateway", self.gw)
        form.addRow("Root password", self.password)
        form.addRow("Repeat password", self.password2)
        form.addRow("SSH public key", self.sshkey)
        for cb in (self.unprivileged, self.nesting, self.onboot, self.start):
            form.addRow("", cb)
            if cb is self.onboot:
                self.startup = StartupFields(form, self.onboot, lambda: fit_to_width(self, 560))
        lay.addLayout(form)
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.create_btn = buttons.addButton("Create", QDialogButtonBox.ButtonRole.AcceptRole)
        self.create_btn.setProperty("kind", "suggested")
        buttons.accepted.connect(self.create)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        fit_to_width(self, 560)
        self.node.currentTextChanged.connect(lambda *_: self.load())
        self.load()

    def busy(self, text: str) -> None:
        self.status.setText(text)
        self.setEnabled(False)

    def idle(self, text: str = "") -> None:
        self.status.setText(text)
        self.setEnabled(True)

    def load(self) -> None:
        pve, node = self.client(), self.node.currentText()
        self.busy("Reading templates, storage and networks…")
        self.runner.run(lambda: {"id": pve.next_id(), "templates": pve.templates(node),
                                 "storage": pve.storages(node, content="rootdir"), "bridges": pve.bridges(node)},
                        self._loaded)

    def _loaded(self, data, err) -> None:
        if err is not None:
            self.idle()
            error(self, "New Container", str(err))
            return
        self.vmid.setValue(int(data["id"]))
        current = self.template.currentData()
        self.template.clear()
        for t in data["templates"]:
            self.template.addItem(t["volid"].split("/")[-1], t["volid"])
        if current:
            i = self.template.findData(current)
            if i >= 0:
                self.template.setCurrentIndex(i)
        self.storage.clear()
        for st in data["storage"]:
            free = (st.get("total", 0) - st.get("used", 0)) / (1 << 30)
            self.storage.addItem(f"{st['storage']}  ({free:.0f} GiB free)", st["storage"])
        self.bridge.clear()
        self.bridge.addItems(data["bridges"] or ["vmbr0"])
        self.idle("" if data["templates"] else "There are no templates on this host yet: use Download… first.")
        fit_to_width(self, 560)

    def download(self) -> None:
        pve, node = self.client(), self.node.currentText()
        self.busy("Asking Proxmox which templates it can download…")
        self.runner.run(lambda: (pve.appliances(node), pve.storages(node, content="vztmpl")), self._pick)

    def _pick(self, data, err) -> None:
        self.idle()
        if err is not None:
            error(self, "Download", str(err))
            return
        apps, stores = data
        dlg = QDialog(self)
        dlg.setWindowTitle("Download a Template")
        v = QVBoxLayout(dlg)
        lst = QListWidget()
        for a in sorted(apps, key=lambda a: a.get("headline", a["template"])):
            item = QListWidgetItem(f"{a.get('headline', a['template'])}    —    {a['template']}")
            item.setData(Qt.ItemDataRole.UserRole, a["template"])
            lst.addItem(item)
        lst.setMinimumSize(560, 320)
        v.addWidget(lst)
        target = QComboBox()
        for st in stores:
            target.addItem(st["storage"])
        v.addWidget(label("Save to storage:"))
        v.addWidget(target)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        get = bb.addButton("Download", QDialogButtonBox.ButtonRole.AcceptRole)
        get.setProperty("kind", "suggested")
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        v.addWidget(bb)
        if dlg.exec() != QDialog.DialogCode.Accepted or not lst.selectedItems() or not target.currentText():
            return
        template, storage = lst.selectedItems()[0].data(Qt.ItemDataRole.UserRole), target.currentText()
        node = self.node.currentText()

        def job():
            upid = pve.download_template(node, storage, template)
            pve.wait_task(node, upid, timeout=1800)

        pve = self.client()
        self.busy(f"Downloading {template} (this can take a few minutes)…")
        self.runner.run(job, lambda _r, e: (error(self, "Download", str(e)) if e else None, self.load()))

    def params(self) -> dict | str:
        """The API parameters, or a sentence saying what is wrong."""
        host = self.hostname.text().strip()
        if not HOSTNAME.match(host):
            return "Choose a hostname: letters, digits and hyphens."
        if not self.template.currentData():
            return "Choose a template (or download one first)."
        if not self.storage.currentData():
            return "No storage on this host accepts containers."
        if len(self.password.text()) < 5:
            return "The root password must have at least 5 characters."
        if self.password.text() != self.password2.text():
            return "The two passwords are not the same."
        net = {"name": "eth0", "bridge": self.bridge.currentText().strip() or "vmbr0"}
        if self.dhcp.isChecked():
            net["ip"] = "dhcp"
        else:
            if not CIDR.match(self.ip.text().strip()):
                return "Write the static address with its prefix, for example 192.168.1.50/24."
            net["ip"] = self.ip.text().strip()
            if self.gw.text().strip():
                if not IPV4.match(self.gw.text().strip()):
                    return "The gateway must be an IPv4 address."
                net["gw"] = self.gw.text().strip()
        p = {"vmid": self.vmid.value(), "hostname": host, "ostemplate": self.template.currentData(),
             "cores": self.cores.value(), "memory": self.memory.value(), "swap": self.swap.value(),
             "rootfs": f"{self.storage.currentData()}:{self.disk.value()}", "net0": format_net(net),
             "password": self.password.text(), "unprivileged": self.unprivileged.isChecked(),
             "onboot": self.onboot.isChecked(), "start": self.start.isChecked(), **self.startup.params()}
        if self.nesting.isChecked():
            p["features"] = "nesting=1"
        if self.sshkey.toPlainText().strip():
            p["ssh-public-keys"] = self.sshkey.toPlainText().strip()
        return p

    def create(self) -> None:
        p = self.params()
        if isinstance(p, str):
            error(self, "New Container", p)
            return
        pve, node = self.client(), self.node.currentText()

        def job():
            upid = pve.create_container(node, p)
            pve.wait_task(node, upid, timeout=900)

        def finished(_r, err):
            if err is not None:
                self.idle()
                error(self, "New Container", str(err))
            else:
                self.accept()

        self.busy(f"Creating container {p['vmid']} ({p['hostname']})…")
        self.runner.run(job, finished)
