"""Files…: this computer on the left, a VM or a container on the right. Choose on one side and press Send → or
← Receive — or drag from one side to the other (or files from the desktop's file manager onto the guest). The bar
shows how far, how fast and which way it goes. The copies themselves are core/guestfiles.

A right click on either side opens what FileZilla's does (the user's wish, 26/10): Open, Send / Receive, Rename…
(F2), Delete… (Del — on this computer into the Trash, in the guest for good), New Folder…, Refresh (F5), Copy Path
and Properties… (Alt+Enter: a folder's whole size, what it holds, times, owner, rights); in a Linux guest also
Permissions… (chmod and chown, on what is chosen or with what is inside)."""

from __future__ import annotations

import os
import shutil
import stat
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QFile, QMimeData, QObject, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QGridLayout, QHBoxLayout, QHeaderView, QLineEdit, QMenu, QProgressBar, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core import guestfiles
from ..core.guestfiles import Cancelled, Entry, GuestError, Props
from ..core.pve import PveError
from .widgets import DialogHead, boxed, button, card, confirm, error, fit_to_width, guest_card, label

MIME = "application/x-proxmox-controller-files"
WAYS = {"network": "over the network", "proxmox": "through Proxmox (slow)", "ssh": "over the host's SSH"}
NAME, SIZE, WHEN = range(3)


def file_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit, step in (("KiB", 1 << 10), ("MiB", 1 << 20), ("GiB", 1 << 30), ("TiB", 1 << 40)):
        if n < step * 1024 or unit == "TiB":
            value = n / step
            return f"{value:.1f} {unit}" if value < 100 else f"{value:.0f} {unit}"
    return f"{n} B"


def when_text(ts: int) -> str:
    if not ts:
        return ""
    d = datetime.fromtimestamp(ts)
    today = datetime.now().date()
    if d.date() == today:
        return d.strftime("Today %H:%M")
    if (today - d.date()).days == 1:
        return d.strftime("Yesterday %H:%M")
    return d.strftime("%d/%m/%Y")


def to_trash(path: Path) -> bool:
    """This computer's file or folder into the desktop's Trash (False where there is none, as on some mounts)."""
    return bool(QFile.moveToTrash(str(path)))


class NameDialog(QDialog):
    """A name to give — Rename… and New Folder… — checked as the system it goes to wants it."""

    def __init__(self, parent: QWidget, title: str, text: str, name: str, os_name: str, icon: str = "edit"):
        super().__init__(parent)
        self.os_name = os_name
        self.setWindowTitle(title)
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(12)
        lay.addWidget(DialogHead(icon, title, text))
        self.name = QLineEdit(name)
        self.name.selectAll()
        if "." in name[1:]:  # the name without its extension chosen, as file managers do
            self.name.setSelection(0, name.rindex("."))
        lay.addWidget(self.name)
        self.problem = label("", "dim", wrap=True)
        lay.addWidget(self.problem)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok.setProperty("kind", "suggested")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        self.name.textChanged.connect(self._check)
        self._check()
        fit_to_width(self, 420)

    def _check(self) -> None:
        problem = guestfiles.check_name(self.os_name, self.name.text())
        self.problem.setText(problem)
        self.ok.setEnabled(not problem)


def ask_name(parent: QWidget, title: str, text: str, name: str, os_name: str, icon: str = "edit") -> str:
    """The name typed, or "" when cancelled."""
    dlg = NameDialog(parent, title, text, name, os_name, icon)
    return dlg.name.text().strip() if dlg.exec() == QDialog.DialogCode.Accepted else ""


def count(n: int, what: str) -> str:
    return f"{n:,} {what}{'' if n == 1 else 's'}"


def full_size(n: int) -> str:
    return file_size(n) + (f" ({n:,} bytes)" if n >= 1024 else "")


def rights_text(mode: int) -> str:
    """0o755 → "rwxr-xr-x (755)"."""
    return f"{stat.filemode(stat.S_IFREG | mode)[1:]} ({mode:03o})"


def id_text(name: str, number: int | None) -> str:
    if number is None:
        return name
    return f"{name} ({number})" if name and name != str(number) else str(number)


class PropertiesDialog(QDialog):
    """Properties…: what is chosen — or the folder itself — as its own system tells it. It opens at once; a folder's
    whole size is counted meanwhile (on a big one that takes a while), then `fill` shows it all. `values` holds what
    is shown, by row."""

    KINDS = {"file": "File", "folder": "Folder", "link": "Link", "other": "Special file"}

    def __init__(self, parent: QWidget, where: str, title: str, folder: bool):
        super().__init__(parent)
        self.setWindowTitle(f"Properties — {title}")
        self.setModal(False)
        self.values: dict[str, str] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(12)
        self.head = DialogHead("folder" if folder else "notes", title, where)
        lay.addWidget(self.head)
        self.form = QFormLayout()
        self.form.setHorizontalSpacing(16)
        self.form.setVerticalSpacing(8)
        self.state = label("Counting…" if folder else "Reading…", "dim")
        self.form.addRow(self.state)
        lay.addWidget(boxed(self.form))
        row = QHBoxLayout()
        row.addStretch(1)
        close = button("Close")
        close.clicked.connect(self.close)
        row.addWidget(close)
        lay.addLayout(row)
        fit_to_width(self, 480)

    def _row(self, name: str, value: str) -> None:
        if value:
            self.values[name] = value
            key, shown = label(name, "dim"), label(value, "", wrap=True, selectable=True)
            self.form.addRow(key, shown)
            key.show()  # (now: a widget added to an open window shows only later, and the size is measured now)
            shown.show()

    def fill(self, props: list[Props]) -> None:
        self.form.removeRow(self.state)
        if len(props) == 1:
            p = props[0]
            self._row("Kind", self.KINDS.get(p.kind, p.kind))
            if p.kind == "link":
                self._row("Points to", p.link)
            elif p.kind != "other":
                self._row("Size", full_size(p.size))
            if p.kind == "folder":
                self._row("Holds", f"{count(p.files, 'file')}, {count(p.folders, 'folder')}")
            for name, ts in (("Modified", p.mtime), ("Accessed", p.atime), ("Created", p.btime)):
                self._row(name, datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S") if ts else "")
            self._row("Owner", id_text(p.owner, p.uid))
            self._row("Group", id_text(p.group, p.gid))
            self._row("Permissions", rights_text(p.mode) if p.mode is not None else "")
            self._row("Attributes", p.attributes)
        else:
            files = sum(p.kind == "file" for p in props)
            folders = sum(p.kind == "folder" for p in props)
            others = len(props) - files - folders
            self._row("Chosen", ", ".join(t for t in (count(files, "file") if files else "",
                                                       count(folders, "folder") if folders else "",
                                                       count(others, "other") if others else "") if t))
            self._row("Size", full_size(sum(p.size for p in props if p.kind in ("file", "folder"))))
            if folders:
                self._row("Holds", f"{count(files + sum(p.files for p in props), 'file')}, "
                                   f"{count(folders + sum(p.folders for p in props), 'folder')}")
        fit_to_width(self, 480)  # (taller now: the rows came)

    def failed(self, err) -> None:
        self.state.setText(f"⚠ {err}")
        self.state.setWordWrap(True)
        self.values["Error"] = str(err)
        fit_to_width(self, 480)


class PermissionsDialog(QDialog):
    """Permissions… (Linux guests): Read / Write / Execute for the owner, the group and others, ticked as they are now
    — half-ticked where what is chosen differs, and left so — the same as a number (755), the owner and the group,
    and with a folder chosen how far it goes. What is touched is what changes: the rights as a whole once any box or
    the number was touched (as FileZilla sends them), the owner and group once either was picked or typed."""

    WHO = (("u", "Owner"), ("g", "Group"), ("o", "Others"))
    WHAT = (("r", "Read"), ("w", "Write"), ("x", "Execute"))
    BIT = {w + b: v << shift for w, shift in (("u", 6), ("g", 3), ("o", 0)) for b, v in (("r", 4), ("w", 2), ("x", 1))}
    SCOPES = (("self", "Only what is chosen"), ("all", "What is chosen and everything inside"),
              ("files", "Only the files — inside the folders too"), ("folders", "Only the folders — and those inside"))

    def __init__(self, parent: QWidget | None, title: str, where: str, props: list[Props],
                 users: list[tuple[str, int]], groups: list[tuple[str, int]]):
        super().__init__(parent)
        self.setWindowTitle(f"Permissions — {title}")
        self.setModal(True)
        self.touched = self.owner_touched = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(12)
        lay.addWidget(DialogHead("lock", title, where))
        modes = [p.mode for p in props if p.kind != "link" and p.mode is not None]
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(8)
        for col, (_b, text) in enumerate(self.WHAT, 1):
            grid.addWidget(label(text, "dim"), 0, col)
        self.boxes: dict[str, QCheckBox] = {}
        for row, (who, text) in enumerate(self.WHO, 1):
            grid.addWidget(label(text), row, 0)
            for col, (what, _t) in enumerate(self.WHAT, 1):
                bit = self.BIT[who + what]
                box = QCheckBox()
                have = {bool(m & bit) for m in modes}
                if len(have) > 1:
                    box.setTristate(True)
                    box.setCheckState(Qt.CheckState.PartiallyChecked)
                else:
                    box.setChecked(have == {True})
                box.clicked.connect(self._box_clicked)
                self.boxes[who + what] = box
                grid.addWidget(box, row, col)
        grid.setColumnStretch(4, 1)
        number_row = QHBoxLayout()
        self.number = QLineEdit()
        self.number.setMaxLength(3)
        self.number.setFixedWidth(64)
        self.number.setPlaceholderText("mixed")
        self.number.textEdited.connect(self._number_edited)
        number_row.addWidget(label("As a number"))
        number_row.addWidget(self.number)
        number_row.addStretch(1)
        rights = QVBoxLayout()
        rights.setSpacing(12)
        rights.addLayout(grid)
        rights.addLayout(number_row)
        if any(m & 0o7000 for m in modes):
            rights.addWidget(label("Setuid, setgid and the sticky bit stay as they are.", "caption", wrap=True))
        lay.addWidget(boxed(rights))
        self._show_number()

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        self.user, self.group = QComboBox(), QComboBox()
        for combo, names, now in ((self.user, users, {p.owner or str(p.uid) for p in props}),
                                  (self.group, groups, {p.group or str(p.gid) for p in props})):
            combo.setEditable(True)
            combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
            combo.addItems([n for n, _num in names])
            for i, (_n, num) in enumerate(names):
                combo.setItemData(i, f"{num}", Qt.ItemDataRole.ToolTipRole)
            combo.setCurrentText(now.pop() if len(now) == 1 else "")
            combo.lineEdit().setPlaceholderText("as each is")
            combo.activated.connect(self._owner_touched)
            combo.lineEdit().textEdited.connect(self._owner_touched)
        self.first = (self.user.currentText(), self.group.currentText())
        form.addRow(label("Owner", "dim"), self.user)
        form.addRow(label("Group", "dim"), self.group)
        lay.addWidget(boxed(form))

        self.scope = QComboBox()
        for key, text in self.SCOPES:
            self.scope.addItem(text, key)
        self.has_scope = any(p.kind == "folder" for p in props)  # (with a folder chosen: how far it goes)
        if self.has_scope:
            scope_row = QFormLayout()
            scope_row.addRow(label("Apply to", "dim"), self.scope)
            lay.addWidget(boxed(scope_row))
        self.problem = label("", "dim", wrap=True)
        lay.addWidget(self.problem)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.apply = buttons.addButton("Apply", QDialogButtonBox.ButtonRole.AcceptRole)
        self.apply.setProperty("kind", "suggested")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        for combo in (self.user, self.group):
            combo.currentTextChanged.connect(self._check)
        self._check()
        fit_to_width(self, 460)

    def bits(self) -> dict[str, bool | None]:
        states = {Qt.CheckState.Checked: True, Qt.CheckState.Unchecked: False}
        return {k: states.get(b.checkState()) for k, b in self.boxes.items()}

    def _box_clicked(self) -> None:
        self.touched = True
        self._show_number()

    def _show_number(self) -> None:
        bits = self.bits()
        if None in bits.values():
            self.number.setText("")
            return
        self.number.setText("".join(str(sum(v for b, v in (("r", 4), ("w", 2), ("x", 1)) if bits[who + b]))
                                    for who in "ugo"))

    def _number_edited(self, text: str) -> None:
        if len(text) == 3 and all(c in "01234567" for c in text):
            self.touched = True
            for who, digit in zip("ugo", text):
                for b, v in (("r", 4), ("w", 2), ("x", 1)):
                    box = self.boxes[who + b]
                    box.setTristate(False)
                    box.setChecked(bool(int(digit) & v))
        self._check()

    def _owner_touched(self, *_a) -> None:
        self.owner_touched = True

    def _check(self) -> None:
        problem = ""
        for what, combo in (("owner", self.user), ("group", self.group)):
            text = combo.currentText().strip()
            if any(c in text for c in ": \t"):
                problem = f"The {what}: a name or a number, without spaces or ':'."
        text = self.number.text()
        if text and not (len(text) == 3 and all(c in "01234567" for c in text)):
            problem = problem or "As a number: three digits from 0 to 7, as 755."
        self.problem.setText(problem)
        self.apply.setEnabled(not problem)

    def changes(self) -> tuple[str, str, str]:
        """(chmod's clauses, chown's "user:group", the scope) — "" for what is left as it is."""
        mode = guestfiles.mode_spec(self.bits()) if self.touched else ""
        owner = ""
        if self.owner_touched:
            user, group = self.user.currentText().strip(), self.group.currentText().strip()
            owner = user + (f":{group}" if group else "")
        return mode, owner, self.scope.currentData() if self.has_scope else "self"


def ask_permissions(parent: QWidget, title: str, where: str, props: list[Props], users, groups):
    """(mode, owner, scope) to set, or None: cancelled, or nothing touched."""
    dlg = PermissionsDialog(parent, title, where, props, users, groups)
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None
    mode, owner, scope = dlg.changes()
    return (mode, owner, scope) if mode or owner else None


def local_listing(folder: Path) -> list[Entry]:
    out = []
    with os.scandir(folder) as it:
        for e in it:
            try:
                st = e.stat()
                is_dir = e.is_dir()
            except OSError:
                continue
            out.append(Entry(e.name, is_dir, 0 if is_dir else st.st_size, int(st.st_mtime)))
    out.sort(key=lambda e: (not e.is_dir, e.name.lower()))
    return out


class FileTree(QTreeWidget):
    """A folder's list: a drag from it carries its side's chosen names; a drop on it is a copy from the other side
    (or, on the guest's side, files dragged from the desktop)."""

    dropped = Signal(str, list)  # the side it came from ("local" | "remote" | "desktop"), local paths for "desktop"

    def __init__(self, side: str):
        super().__init__()
        self.side = side
        self.setHeaderLabels(["Name", "Size", "Modified"])
        self.setRootIsDecorated(False)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.CopyAction)
        self.header().setSectionResizeMode(NAME, QHeaderView.ResizeMode.Stretch)
        self.header().setSectionResizeMode(SIZE, QHeaderView.ResizeMode.ResizeToContents)
        self.header().setSectionResizeMode(WHEN, QHeaderView.ResizeMode.ResizeToContents)
        self.setMinimumHeight(260)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def mimeTypes(self):
        return [MIME]

    def mimeData(self, items):
        data = QMimeData()
        data.setData(MIME, self.side.encode())
        return data

    def _wanted(self, event) -> str | None:
        mime = event.mimeData()
        if mime.hasFormat(MIME):
            side = bytes(mime.data(MIME)).decode()
            return side if side != self.side else None
        if self.side == "remote" and mime.hasUrls() and all(u.isLocalFile() for u in mime.urls()):
            return "desktop"
        return None

    def dragEnterEvent(self, event):
        if self._wanted(event):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if self._wanted(event):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        side = self._wanted(event)
        if not side:
            event.ignore()
            return
        event.acceptProposedAction()
        paths = [u.toLocalFile() for u in event.mimeData().urls()] if side == "desktop" else []
        self.dropped.emit(side, paths)


class Pane(QWidget):
    """One side: its folder (typed, or chosen from those visited), ↑, ⟳, and the list."""

    def __init__(self, side: str, title: str, subtitle: str = ""):
        super().__init__()
        self.side, self.folder, self.entries = side, "", []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        head = QHBoxLayout()
        self.title = label(f"<b>{title}</b>", "heading")
        self.subtitle = label(subtitle, "dim")
        head.addWidget(self.title)
        head.addWidget(self.subtitle)
        head.addStretch(1)
        lay.addLayout(head)
        bar = QHBoxLayout()
        self.up = button("↑", "", "Up one folder")
        self.up.setFixedWidth(34)
        self.combo = QComboBox()
        self.combo.setEditable(True)
        self.combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.combo.setToolTip("The folder — type one and press Enter, or pick one visited")
        self.again = button("⟳", "", "Read the folder again")
        self.again.setFixedWidth(34)
        bar.addWidget(self.up)
        bar.addWidget(self.combo, 1)
        bar.addWidget(self.again)
        lay.addLayout(bar)
        self.tree = FileTree(side)
        lay.addWidget(self.tree, 1)
        self.state = label("", "caption", wrap=True)
        lay.addWidget(self.state)

    def show_entries(self, folder: str, entries: list[Entry]) -> None:
        """The folder's list; the same folder read again keeps what was chosen in it (after a change)."""
        keep = {e.name for e in self.chosen()} if folder == self.folder else set()
        self.folder, self.entries = folder, entries
        if self.combo.findText(folder) < 0:
            self.combo.insertItem(0, folder)
        self.combo.setCurrentText(folder)
        self.tree.clear()
        for e in entries:
            item = QTreeWidgetItem([("📁  " if e.is_dir else "📄  ") + e.name, "" if e.is_dir else file_size(e.size),
                                    when_text(e.mtime)])
            item.setData(NAME, Qt.ItemDataRole.UserRole, e.name)
            item.setTextAlignment(SIZE, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.tree.addTopLevelItem(item)
            item.setSelected(e.name in keep)
        self.say_count()

    def say_count(self) -> None:
        n = len(self.entries)
        self.state.setText(f"{n} item{'s' if n != 1 else ''}" if self.folder or n else "")

    def chosen(self) -> list[Entry]:
        names = {i.data(NAME, Qt.ItemDataRole.UserRole) for i in self.tree.selectedItems()}
        return [e for e in self.entries if e.name in names]


class _Relay(QObject):
    progressed = Signal(int, object, str)
    ended = Signal(object, object)  # (the way it went, the error) — on the window's thread


class FilesWindow(QDialog):
    """`make_backend` gives the guest's side (guestfiles.VmFiles or ContainerFiles) — called on a worker thread."""

    def __init__(self, parent, title: str, subtitle: str, make_backend: Callable[[], object], runner,
                 local_start: Path | None = None, guest: dict | None = None):
        super().__init__(parent)
        self.setWindowTitle(f"Files — {title}")
        self.setModal(False)
        self.runner, self.make_backend = runner, make_backend
        self.backend = None
        self.cancel: threading.Event | None = None
        self.started_at = 0.0
        self.last_shown = 0.0
        self.done_bytes, self.way = 0, ""
        self.refresh_after: Pane | None = None
        self.busy = False  # (the guest's side reading or changing)
        self.reads = 0  # the guest's folder asked for last: an older answer coming after it is not shown
        self.props_windows: list[PropertiesDialog] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)  # as every window of a guest (widgets.DialogHead)
        lay.setSpacing(12)
        lay.addWidget(DialogHead("folder", "Files" if guest else f"Files — {title}",
                                 "Choose on one side, press Send or Receive — or drag from one side to the other. "
                                 "Folders go whole."))
        if guest:
            lay.addWidget(guest_card(guest))
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        self.local = Pane("local", "This computer")
        self.guest_name = title.split(" (")[0]
        self.remote = Pane("remote", self.guest_name, subtitle)
        mid = QVBoxLayout()
        mid.addStretch(1)
        self.send_btn = button("Send  →", "suggested", "Copy what is chosen on the left into the folder shown on the "
                                                         "right")
        self.receive_btn = button("←  Receive", "", "Copy what is chosen on the right into the folder shown on the "
                                                    "left")
        for b in (self.send_btn, self.receive_btn):
            b.setMinimumWidth(116)
            mid.addWidget(b)
        mid.addStretch(1)
        grid.addWidget(self.local, 0, 0)
        grid.addLayout(mid, 0, 1)
        grid.addWidget(self.remote, 0, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(2, 1)
        lay.addLayout(grid, 1)

        self.what = label("", "")
        self.bar = QProgressBar()
        self.speed = label("", "dim")
        self.stop_btn = button("Cancel")
        prow = QHBoxLayout()
        prow.addWidget(self.what)
        prow.addWidget(self.bar, 1)
        prow.addWidget(self.speed)
        prow.addWidget(self.stop_btn)
        holder = QWidget()
        prow.setContentsMargins(0, 0, 0, 0)
        holder.setLayout(prow)
        self.copying_title = label("Copying", "heading")
        self.progress_card = card(self.copying_title, holder)
        self.progress_card.hide()
        lay.addWidget(self.progress_card)
        self.result = label("", "caption", wrap=True)
        lay.addWidget(self.result)
        lay.addWidget(label("Over the network when the guest can reach this computer (fast); otherwise through "
                            "Proxmox's guest agent (slow — about 1 MB/s). VMs need the QEMU guest agent; containers "
                            "go over the host's SSH.", "caption", wrap=True))
        row = QHBoxLayout()
        row.addStretch(1)
        close = button("Close")
        close.clicked.connect(self.close)
        row.addWidget(close)
        lay.addLayout(row)

        self.relay = _Relay()
        self.relay.progressed.connect(self._progress)
        self.relay.ended.connect(self._ended)
        self.send_btn.clicked.connect(lambda: self.send())  # (clicked passes a bool: not paths)
        self.receive_btn.clicked.connect(lambda: self.receive())
        self.stop_btn.clicked.connect(self._stop)
        self.local.up.clicked.connect(lambda: self.go_local(str(Path(self.local.folder).parent)))
        self.local.again.clicked.connect(lambda: self.go_local(self.local.folder))
        self.local.combo.lineEdit().returnPressed.connect(lambda: self.go_local(self.local.combo.currentText()))
        self.local.combo.activated.connect(lambda *_: self.go_local(self.local.combo.currentText()))
        self.local.tree.itemDoubleClicked.connect(lambda item, _c: self._open(self.local, item))
        self.remote.up.clicked.connect(lambda: self.go_remote(guestfiles.parent(self._os(), self.remote.folder)))
        self.remote.again.clicked.connect(lambda: self.go_remote(self.remote.folder))
        self.remote.combo.lineEdit().returnPressed.connect(lambda: self.go_remote(self.remote.combo.currentText()))
        self.remote.combo.activated.connect(lambda *_: self.go_remote(self.remote.combo.currentText()))
        self.remote.tree.itemDoubleClicked.connect(lambda item, _c: self._open(self.remote, item))
        self.remote.tree.dropped.connect(lambda side, paths: self.send([Path(p) for p in paths] if paths else None))
        self.local.tree.dropped.connect(lambda *_: self.receive())
        for pane in (self.local, self.remote):  # the right click, and FileZilla's keys
            pane.tree.customContextMenuRequested.connect(lambda pos, pane=pane: self._menu(pane, pos))
            for key, act in (("Del", self.delete_items), ("F2", self.rename_item), ("F5", self.refresh),
                             ("Alt+Return", self.properties)):
                sc = QShortcut(QKeySequence(key), pane.tree, context=Qt.ShortcutContext.WidgetShortcut)
                sc.activated.connect(lambda act=act, pane=pane: act(pane))
        self.resize(1060, 640)
        start = local_start or (Path.home() / "Downloads" if (Path.home() / "Downloads").is_dir() else Path.home())
        self.go_local(str(start))
        self._busy(True, "Opening…")
        self.runner.run(self._connect, self._connected)

    # -- the two sides --------------------------------------------------------------------------------

    def _os(self) -> str:
        return getattr(self.backend, "os_name", "linux")

    def _connect(self):
        backend = self.make_backend()
        home = backend.home()
        return backend, home, backend.list(home)

    def _connected(self, result, err) -> None:
        self._busy(False)
        if err is not None:
            self.remote.state.setText(f"⚠ {err}")
            self.send_btn.setEnabled(False)
            self.receive_btn.setEnabled(False)
            return
        self.backend, _home, (folder, entries) = result
        if not self.remote.subtitle.text():
            self.remote.subtitle.setText("Windows · as SYSTEM" if self._os() == "windows" else "Linux · as root")
        self.remote.show_entries(folder, entries)

    def go_local(self, folder: str) -> None:
        path = Path(folder).expanduser()
        try:
            self.local.show_entries(str(path), local_listing(path))
        except OSError as e:
            error(self, "Files", f"{folder}: {e.strerror or e}")

    def go_remote(self, folder: str) -> None:
        if self.backend is None:
            return
        backend = self.backend
        self.reads += 1
        read = self.reads
        self._busy(True, "Reading…")

        def done(result, err):
            if read != self.reads:
                return  # (a folder opened meanwhile: its own answer counts)
            self._busy(False)
            if err is not None:
                error(self, "Files", str(err))
                return
            self.remote.show_entries(*result)

        self.runner.run(lambda: backend.list(folder), done)

    def _open(self, pane: Pane, item: QTreeWidgetItem) -> None:
        name = item.data(NAME, Qt.ItemDataRole.UserRole)
        entry = next((e for e in pane.entries if e.name == name), None)
        if entry is None or not entry.is_dir:
            return
        if pane is self.local:
            self.go_local(str(Path(self.local.folder) / name))
        else:
            self.go_remote(guestfiles.join(self._os(), self.remote.folder, name))

    # -- the right-click menu -------------------------------------------------------------------------

    def _menu(self, pane: Pane, pos) -> None:
        """What FileZilla's right click offers, for what is chosen on that side (the item under the pointer chosen
        first, as file managers do)."""
        item = pane.tree.itemAt(pos)
        if item is None:  # (the empty space: the folder itself)
            pane.tree.clearSelection()
        elif not item.isSelected():
            pane.tree.clearSelection()
            item.setSelected(True)
            pane.tree.setCurrentItem(item)
        menu = self.menu_for(pane)
        menu.exec(pane.tree.viewport().mapToGlobal(pos))

    def menu_for(self, pane: Pane) -> QMenu:
        chosen, local = pane.chosen(), pane is self.local
        ready = self._ready(pane)
        menu = QMenu(self)
        one = chosen[0] if len(chosen) == 1 else None

        def add(text: str, slot, enabled: bool = True, shortcut: str = ""):
            a = menu.addAction(text)
            a.setEnabled(enabled)
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
            a.triggered.connect(slot)
            return a

        if one is not None and (one.is_dir or local):
            add("Open", lambda: self.open_item(pane), ready)
        if chosen:
            if local:
                add("Send  →", lambda: self.send(), ready and self.backend is not None)
            else:
                add("←  Receive", lambda: self.receive(), ready)
            menu.addSeparator()
            add("Rename…", lambda: self.rename_item(pane), ready and one is not None, "F2")
            add("Delete…", lambda: self.delete_items(pane), ready, "Del")
        menu.addSeparator()
        add("New Folder…", lambda: self.new_folder(pane), ready and bool(pane.folder))
        add("Refresh", lambda: self.refresh(pane), ready, "F5")
        add("Copy Path", lambda: self.copy_path(pane), bool(pane.folder))
        menu.addSeparator()
        add("Properties…", lambda: self.properties(pane), self._readable(pane), "Alt+Return")
        if not local and self._os() == "linux":
            add("Permissions…", lambda: self.permissions(pane), ready and bool(chosen))
        return menu

    def _ready(self, pane: Pane) -> bool:
        """Whether that side can be changed now: not while a copy goes on, nor the guest's side while it is read."""
        if self.cancel is not None:
            return False
        return pane is self.local or (self.backend is not None and not self.busy)

    def _readable(self, pane: Pane) -> bool:
        """Properties… reads only: also while a copy goes on (not in Windows' list of drives)."""
        return bool(pane.folder) and (pane is self.local or self.backend is not None)

    def _path(self, pane: Pane, name: str = "") -> str:
        if pane is self.local:
            return str(Path(pane.folder) / name) if name else pane.folder
        return guestfiles.join(self._os(), pane.folder, name) if name else pane.folder

    def open_item(self, pane: Pane) -> None:
        """A folder: into it. On this computer a file opens in its own app."""
        chosen = pane.chosen()
        if len(chosen) != 1 or not self._ready(pane):
            return
        if chosen[0].is_dir:
            (self.go_local if pane is self.local else self.go_remote)(self._path(pane, chosen[0].name))
        elif pane is self.local:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._path(pane, chosen[0].name)))

    def refresh(self, pane: Pane) -> None:
        if not self._ready(pane):
            return
        (self.go_local if pane is self.local else self.go_remote)(pane.folder)

    def copy_path(self, pane: Pane) -> None:
        chosen = pane.chosen()
        paths = [self._path(pane, e.name) for e in chosen] or [pane.folder]
        QGuiApplication.clipboard().setText("\n".join(paths))
        self.result.setText(f"Copied: {_short(paths[0])}" + (f" and {len(paths) - 1} more" if len(paths) > 1 else ""))

    def rename_item(self, pane: Pane) -> None:
        chosen = pane.chosen()
        if len(chosen) != 1 or not self._ready(pane):
            return
        old = chosen[0].name
        os_name = guestfiles.local_os() if pane is self.local else self._os()
        new = ask_name(self, "Rename", f"A new name for {old}.", old, os_name)
        if not new or new == old:
            return
        if new in {e.name for e in pane.entries}:
            error(self, "Rename", f"{new} is already in this folder.")
            return
        if pane is self.local:
            try:
                os.rename(Path(pane.folder) / old, Path(pane.folder) / new)
            except OSError as e:
                error(self, "Rename", e.strerror or str(e))
            self.go_local(pane.folder)
            return
        backend, folder = self.backend, pane.folder
        self._guest_op(lambda: backend.rename(folder, old, new), f"Renamed {old} to {new}.")

    def delete_items(self, pane: Pane) -> None:
        chosen = pane.chosen()
        if not chosen or not self._ready(pane):
            return
        names = [e.name for e in chosen]
        listed = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        count = names[0] if len(names) == 1 else f"{len(names)} items"
        if pane is self.local:
            if not confirm(self, f"Move {count} to the Trash?", f"{listed} — from {pane.folder}. The Trash can give "
                           "them back.", "Move to Trash", True, icon="trash"):
                return
            stuck = [n for n in names if not to_trash(Path(pane.folder) / n)]
            if stuck and confirm(self, "Delete for good?", f"{', '.join(stuck[:5])}: this place has no Trash. "
                                 "Deleted for good, it cannot be undone.", "Delete", True, icon="trash"):
                for n in stuck:
                    p = Path(pane.folder) / n
                    try:
                        shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
                    except OSError as e:
                        error(self, "Delete", f"{n}: {e.strerror or e}")
                        break
            self.go_local(pane.folder)
            return
        where = "the container" if self.remote.subtitle.text().startswith("Container") else "the VM"
        if not confirm(self, f"Delete {count} for good?", f"{listed} — from {pane.folder} in {where}. There is no "
                       "Trash there: this cannot be undone.", "Delete", True, icon="trash"):
            return
        backend, folder = self.backend, pane.folder
        self._guest_op(lambda: backend.delete(folder, names), f"Deleted {listed}.")

    def new_folder(self, pane: Pane) -> None:
        if not pane.folder or not self._ready(pane):
            return
        os_name = guestfiles.local_os() if pane is self.local else self._os()
        name = ask_name(self, "New Folder", f"A folder in {pane.folder}.", "New folder", os_name, icon="folder")
        if not name:
            return
        if name in {e.name for e in pane.entries}:
            error(self, "New Folder", f"{name} is already in this folder.")
            return
        if pane is self.local:
            try:
                (Path(pane.folder) / name).mkdir()
            except OSError as e:
                error(self, "New Folder", e.strerror or str(e))
            self.go_local(pane.folder)
            return
        backend, folder = self.backend, pane.folder
        self._guest_op(lambda: backend.mkdir(folder, name), f"Made the folder {name}.")

    def properties(self, pane: Pane) -> None:
        """What is chosen, or with nothing chosen the folder itself, in a window of its own (one per question)."""
        if not self._readable(pane):
            return
        chosen, folder = pane.chosen(), pane.folder
        names = [e.name for e in chosen] or ["."]
        side = "this computer" if pane is self.local else self.guest_name
        if chosen:
            title = chosen[0].name if len(chosen) == 1 else f"{len(chosen)} items"
            where = f"In {folder} · {side}"
        else:  # the folder itself
            title = folder.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1] or folder
            where = f"{folder} · {side}"
        dlg = PropertiesDialog(self, where, title, not chosen or any(e.is_dir for e in chosen))
        self.props_windows.append(dlg)
        dlg.finished.connect(lambda *_: self.props_windows.remove(dlg) if dlg in self.props_windows else None)
        dlg.show()
        if pane is self.local:
            job = lambda: guestfiles.local_props(Path(folder), names)  # noqa: E731
        else:
            backend = self.backend
            job = lambda: backend.properties(folder, names)  # noqa: E731

        def done(props, err):
            try:
                dlg.failed(err) if err is not None else dlg.fill(props)
            except RuntimeError:  # (the window is gone)
                pass

        self.runner.run(job, done)

    def permissions(self, pane: Pane) -> None:
        """Linux guests: what is chosen read first (its rights, owner, group) with the guest's accounts, then asked,
        then set."""
        chosen = pane.chosen()
        if pane is self.local or self._os() != "linux" or not chosen or not self._ready(pane):
            return
        backend, folder, names = self.backend, pane.folder, [e.name for e in chosen]
        listed = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        self._busy(True, "Reading…")

        def got(result, err):
            self._busy(False)
            self.remote.say_count()
            if err is not None:
                error(self, "Permissions", str(err))
                return
            props, (users, groups) = result
            change = ask_permissions(self, names[0] if len(names) == 1 else f"{len(names)} items",
                                     f"In {folder} · {self.guest_name}", props, users, groups)
            if change:
                self._guest_op(lambda: backend.set_permissions(folder, names, *change), f"Permissions set: {listed}.")

        self.runner.run(lambda: (backend.properties(folder, names), backend.accounts()), got)

    def _guest_op(self, job, done_text: str) -> None:
        """A change in the guest, off the window's thread; then its folder read again."""
        self._busy(True, "Working…")

        def done(_r, err):
            self._busy(False)
            if err is not None:
                error(self, "Files", str(err))
            else:
                self.result.setText(done_text)
            self.go_remote(self.remote.folder)

        self.runner.run(job, done)

    # -- copies -------------------------------------------------------------------------------------

    def send(self, paths: list[Path] | None = None) -> None:
        if self.backend is None or self.cancel is not None:
            return
        if paths is None:
            paths = [Path(self.local.folder) / e.name for e in self.local.chosen()]
        if not paths:
            error(self, "Send", "Choose what to send on the left first.")
            return
        dest = self.remote.folder
        if not dest:
            error(self, "Send", "Open a folder on the right first: the copy goes into it.")
            return
        clash = sorted({p.name for p in paths} & {e.name for e in self.remote.entries})
        if clash and not confirm(self, "Replace?", f"{', '.join(clash)} already in {dest}: replace "
                                 f"{'it' if len(clash) == 1 else 'them'}?", "Replace", True):
            return
        backend = self.backend
        names = ", ".join(p.name for p in paths)
        self._copy(f"{_short(names)}  →  {dest}",
                   lambda progress, cancel: backend.send(paths, dest, progress, cancel), self.remote)

    def receive(self) -> None:
        if self.backend is None or self.cancel is not None:
            return
        chosen = self.remote.chosen()
        if not chosen:
            error(self, "Receive", "Choose what to receive on the right first.")
            return
        dest = Path(self.local.folder)
        clash = sorted({e.name for e in chosen} & {e.name for e in self.local.entries})
        if clash and not confirm(self, "Replace?", f"{', '.join(clash)} already in {dest}: replace "
                                 f"{'it' if len(clash) == 1 else 'them'}?", "Replace", True):
            return
        backend, folder = self.backend, self.remote.folder
        names = [e.name for e in chosen]
        total = sum(e.size for e in chosen) if not any(e.is_dir for e in chosen) else None
        self._copy(f"{_short(', '.join(names))}  →  {dest}",
                   lambda progress, cancel: backend.receive(folder, names, dest, progress, cancel, total), self.local)

    def _copy(self, what: str, job, refresh: Pane) -> None:
        self.cancel = threading.Event()
        cancel = self.cancel
        self.refresh_after = refresh
        self.done_bytes, self.last_shown = 0, 0.0
        self.what.setText(what)
        self.bar.setRange(0, 0)
        self.speed.setText("")
        self.result.setText("")
        self.progress_card.show()
        self._busy(True)
        self.started_at = time.monotonic()
        relay = self.relay

        def run():
            try:
                way = job(lambda done, total, how: relay.progressed.emit(done, total, how), cancel)
                relay.ended.emit(way, None)
            except BaseException as e:  # noqa: BLE001 — shown in the window
                relay.ended.emit(None, e)

        threading.Thread(target=run, daemon=True).start()

    def _progress(self, done: int, total, how: str) -> None:
        now = time.monotonic()
        if now - self.last_shown < 0.1 and (not total or done < total):
            return  # (often enough for the eye)
        self.last_shown = now
        self.done_bytes, self.way = done, how
        if total:
            self.bar.setRange(0, 1000)
            self.bar.setValue(min(1000, int(1000 * done / total)))
            self.bar.setFormat(f"{100 * done // max(total, 1)} %   {file_size(done)} of {file_size(total)}")
        else:
            self.bar.setRange(0, 0)
        secs = max(now - self.started_at, 0.001)
        self.speed.setText(f"{file_size(int(done / secs))}/s · {WAYS.get(how, how)}")

    def _ended(self, way, err) -> None:
        self.cancel = None
        self._busy(False)
        self.progress_card.hide()
        secs = time.monotonic() - self.started_at
        if isinstance(err, Cancelled):
            self.result.setText("Cancelled.")
        elif err is not None:
            self.result.setText("")
            error(self, "Files", str(err) if isinstance(err, (GuestError, PveError, OSError)) else
                  f"{type(err).__name__}: {err}")
        else:
            moved = file_size(getattr(self, "done_bytes", 0))
            self.result.setText(f"Done: {self.what.text()} — {moved} in {secs:.1f} s, {WAYS.get(way, way)}.")
        if self.refresh_after is self.remote:
            self.go_remote(self.remote.folder)
        else:
            self.go_local(self.local.folder)

    def _stop(self) -> None:
        if self.cancel is not None:
            self.cancel.set()
            self.stop_btn.setEnabled(False)

    def _busy(self, on: bool, text: str = "") -> None:
        self.busy = on
        for w in (self.send_btn, self.receive_btn, self.remote.up, self.remote.again, self.remote.combo):
            w.setEnabled(not on)
        self.stop_btn.setEnabled(on and self.cancel is not None)
        if text:
            self.remote.state.setText(text)

    def closeEvent(self, ev) -> None:
        if self.cancel is not None:
            if not confirm(self, "Stop the copy?", "A copy is still going on.", "Stop It", True):
                ev.ignore()
                return
            self.cancel.set()
        super().closeEvent(ev)


def _short(text: str, n: int = 60) -> str:
    return text if len(text) <= n else text[:n - 1] + "…"
