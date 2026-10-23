"""Files…: this computer on the left, a VM or a container on the right. Choose on one side and press Send → or
← Receive — or drag from one side to the other (or files from the desktop's file manager onto the guest). The bar
shows how far, how fast and which way it goes. The copies themselves are core/guestfiles."""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QMimeData, QObject, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QGridLayout, QHBoxLayout, QHeaderView,
                               QProgressBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core import guestfiles
from ..core.guestfiles import Cancelled, Entry, GuestError
from ..core.pve import PveError
from .widgets import button, card, confirm, error, label

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
                 local_start: Path | None = None):
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
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(label(f"Files — {title}", "title"))
        lay.addWidget(label("Choose on one side, press Send or Receive — or drag from one side to the other. "
                            "Folders go whole.", "dim", wrap=True))
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
        self._busy(True, "Reading…")

        def done(result, err):
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
