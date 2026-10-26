"""Files…: this computer on the left, a VM or a container on the right. Choose on one side and press Send → or
← Receive — or drag from one side to the other (or files from the desktop's file manager onto the guest). The bar
shows how far, how fast and which way it goes. The copies themselves are core/guestfiles.

A right click on either side opens what FileZilla's does (the user's wish, 26/10): Open, Send / Receive, Rename…
(F2), Delete… (Del — on this computer into the Trash, in the guest for good), New Folder…, Refresh (F5) and Copy
Path."""

from __future__ import annotations

import os
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QFile, QMimeData, QObject, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QGridLayout, QHBoxLayout,
                               QHeaderView, QLineEdit, QMenu, QProgressBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

from ..core import guestfiles
from ..core.guestfiles import Cancelled, Entry, GuestError
from ..core.pve import PveError
from .widgets import DialogHead, button, card, confirm, error, fit_to_width, guest_card, label

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
        n = len(entries)
        self.state.setText(f"{n} item{'s' if n != 1 else ''}" if folder or n else "")

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
        self.remote = Pane("remote", title.split(" (")[0], subtitle)
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
            for key, act in ((QKeySequence.StandardKey.Delete, self.delete_items), ("F2", self.rename_item),
                             (QKeySequence.StandardKey.Refresh, self.refresh)):
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
        return menu

    def _ready(self, pane: Pane) -> bool:
        """Whether that side can be changed now: not while a copy goes on, nor the guest's side while it is read."""
        if self.cancel is not None:
            return False
        return pane is self.local or (self.backend is not None and not self.busy)

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
