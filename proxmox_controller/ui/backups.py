"""Backups of one guest: back it up now (with the progress Proxmox reports), see every backup of it, restore one —
over the guest or as a new one — protect or delete. The window does not block the app: a backup takes a while.
And the backups of guests deleted since, which Proxmox keeps: restore (the guest comes back), protect or delete."""

from __future__ import annotations

import re
import time
from typing import Callable

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QFormLayout, QHBoxLayout, QHeaderView, QLineEdit, QProgressBar, QRadioButton, QSpinBox,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ..core import jobs
from ..core.pve import Pve, backup_kind, backup_name
from .widgets import button, card, confirm, error, fit_to_width, gib, label, lock_icon
from .worker import Runner

MODES = (("snapshot", "Snapshot — it keeps running"), ("suspend", "Suspend — paused for a moment"),
         ("stop", "Stop — shut down during the backup"))
COMPRESSION = (("zstd", "ZSTD (fast and small)"), ("lzo", "LZO (fastest)"), ("gzip", "GZIP"), ("0", "None"))
NOTE_HELP = "{{guestname}}, {{vmid}}, {{node}} and {{cluster}} are filled in by Proxmox."
BACKUP_TIMEOUT_S = 24 * 3600
PERCENT = re.compile(r"(\d{1,3})%\s*(?:\(([^)]*)\))?")


def progress_of(line: str) -> tuple[int | None, str]:
    """A task log line → (percent or None, what to show). vzdump writes 'INFO:  42% (13.5 GiB of 32.0 GiB) in 1m',
    a VM restore 'progress 42% (read …)'."""
    text = line.removeprefix("INFO:").strip()
    m = PERCENT.search(text)
    if m and ("progress" in text or text.startswith(m.group(0))):
        pct = min(100, int(m.group(1)))
        detail = m.group(2) or ""
        return pct, f"{pct} %" + (f" — {detail}" if detail and "read" not in detail else "")
    return None, text


def kind_name(g: dict) -> str:
    return "container" if g["type"] == "lxc" else "VM"




class _Relay(QObject):
    line = Signal(str)


class RestoreDialog(QDialog):
    """Where a backup goes back to: over the guest (it must be stopped) or as a new guest."""

    def __init__(self, parent: QWidget, guest: dict, backup: dict, next_id: int, storages: list[str],
                 gone: bool = False):
        """gone: the guest was deleted — it can only come back as a new one, and may keep its old MAC addresses."""
        super().__init__(parent)
        self.g, self.b, self.gone = guest, backup, gone
        name = guest.get("name", "")
        self.setWindowTitle("Restore a Backup")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(backup.get("ctime", 0)))
        lay.addWidget(label(f"<b>Restore the backup of {when}</b> ({gib(backup.get('size'))})", wrap=True))
        self.replace = QRadioButton(f"Replace {kind_name(guest)} {guest['vmid']} ({name})")
        self.as_new = QRadioButton(f"As a new {kind_name(guest)}")
        group = QButtonGroup(self)
        group.addButton(self.replace)
        group.addButton(self.as_new)
        running = guest.get("status") == "running"
        self.replace.setEnabled(not running)
        self.replace.setToolTip("Shut it down first." if running else "")
        (self.as_new if running else self.replace).setChecked(True)
        lay.addWidget(self.replace)
        self.replace_note = label(("It is running: shut it down first to replace it. " if running else "") +
                                  "Everything that changed since this backup is lost.", "caption", wrap=True)
        lay.addWidget(self.replace_note)
        self.typed = QLineEdit()
        self.typed.setPlaceholderText(f"Type {name} to confirm")
        lay.addWidget(self.typed)
        lay.addWidget(self.as_new)
        form = QFormLayout()
        self.vmid = QSpinBox()
        self.vmid.setRange(100, 999999999)
        self.vmid.setValue(next_id)
        form.addRow("ID" if gone else "New ID", self.vmid)  # a deleted guest's own ID, while it is free
        self.storage = QComboBox()
        self.storage.addItem("As in the backup", "")
        for st in storages:
            self.storage.addItem(st, st)
        form.addRow("Disks to", self.storage)
        lay.addLayout(form)
        self.start = QCheckBox("Start it when it is restored")
        lay.addWidget(self.start)
        self.keep_mac = QCheckBox("Keep its network addresses (MAC)")
        self.keep_mac.setChecked(True)
        lay.addWidget(self.keep_mac)
        lay.addWidget(label("With its old addresses the router gives it the IP it had. Clear it if a copy of it runs "
                            "elsewhere." if gone else
                            "A new copy gets new network addresses (MAC), so it can run beside the original.",
                            "caption", wrap=True))
        self.keep_mac.setVisible(gone)
        if gone:  # nothing to replace: only "as a new one", said once in the title
            for w in (self.replace, self.replace_note, self.typed, self.as_new):
                w.hide()
            self.as_new.setChecked(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.go = buttons.addButton("Restore", QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("kind", "destructive")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        for w in (self.replace, self.as_new):
            w.toggled.connect(lambda *_: self._update())
        self.typed.textChanged.connect(lambda *_: self._update())
        self._update()
        fit_to_width(self, 500)

    def _update(self) -> None:
        replace = self.replace.isChecked()
        self.typed.setEnabled(replace)
        self.vmid.setEnabled(not replace)
        self.go.setProperty("kind", "destructive" if replace else "suggested")
        self.go.style().unpolish(self.go)
        self.go.style().polish(self.go)
        self.go.setEnabled(not replace or self.typed.text() == self.g.get("name", ""))

    def choice(self) -> dict:
        replace = self.replace.isChecked()
        return {"vmid": self.g["vmid"] if replace else self.vmid.value(), "replace": replace,
                "storage": self.storage.currentData(), "start": self.start.isChecked(),
                "unique": not self.keep_mac.isChecked() if self.gone else None}  # None: as Proxmox would choose


class _BackupList:
    """What both backup windows do with the backup selected in their table — protect, delete — and how they show a
    long task. A window has: client, runner, backups, working, table, progress, status, restore/protect/delete
    buttons, load(select), and says which node a backup is reached through (_node)."""

    def _node(self, b: dict) -> str:
        raise NotImplementedError

    def _busy(self) -> None:
        """More to turn off while a task runs."""

    def _selected_volid(self) -> str:
        items = self.table.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else ""

    def selected(self) -> dict | None:
        volid = self._selected_volid()
        return next((b for b in self.backups if b["volid"] == volid), None)

    def _sel(self) -> None:
        b = self.selected()
        free = not self.working
        self.restore_btn.setEnabled(bool(b) and free)
        self.protect_btn.setEnabled(bool(b) and free)
        self.protect_btn.setText("Unprotect" if b and b.get("protected") else "Protect")
        self.delete_btn.setEnabled(bool(b) and free and not b.get("protected"))
        self.delete_btn.setToolTip("Unprotect it first." if b and b.get("protected") else "")

    def _start(self, text: str) -> None:
        self.working = True
        self._busy()
        self.progress.setRange(0, 0)  # moving until Proxmox reports a percentage
        self.progress.show()
        self.status.setText(text)
        self._sel()

    def _log_line(self, line: str) -> None:
        pct, text = progress_of(line)
        if pct is not None:
            self.progress.setRange(0, 100)
            self.progress.setValue(pct)
        if text:
            self.status.setText(text)

    def _done(self, err, ok_text: str, select: str = "") -> None:
        self.working = False
        self.progress.hide()
        if err is not None:
            self.status.setText("")
            error(self, "Backups", str(err))
        else:
            self.status.setText(ok_text)
        self.load(select)

    def toggle_protect(self) -> None:
        b = self.selected()
        if b is None:
            return
        pve, node, on = self.client(), self._node(b), not b.get("protected")
        self.runner.run(lambda: pve.protect_backup(node, b["storage"], b["volid"], on),
                        lambda _r, err: (error(self, "Backups", str(err)) if err else None, self.load(b["volid"])))

    def delete(self) -> None:
        b = self.selected()
        if b is None or b.get("protected"):
            return
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(b.get("ctime", 0)))
        if not confirm(self, "Delete this backup?", f"The backup of {when} ({gib(b.get('size'))}) is removed from "
                       f"{b['storage']} for good.", "Delete Backup", destructive=True):
            return
        pve, node = self.client(), self._node(b)

        def job():
            upid = pve.delete_backup(node, b["storage"], b["volid"])
            if isinstance(upid, str) and upid.startswith("UPID:"):
                pve.wait_task(node, upid, timeout=600)

        self._start("Deleting the backup…")
        self.runner.run(job, lambda _r, err: self._done(err, "Backup deleted."))

    def _table(self, headers: list[str], stretch: int) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.verticalHeader().setVisible(False)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setShowGrid(False)
        t.setMinimumHeight(180)
        hdr = t.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
        t.itemSelectionChanged.connect(self._sel)
        return t

    def _fill(self, rows: list[tuple[dict, list[str]]], selected: str) -> None:
        """One row a backup: its cells after the lock column, the backup's volid kept in each."""
        t = self.table
        t.setRowCount(len(rows))
        accent = self.palette().color(self.palette().ColorRole.Highlight).name()
        for r, (b, cells) in enumerate(rows):
            for c, text in enumerate([""] + cells):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, b["volid"])
                t.setItem(r, c, item)
            if b.get("protected"):
                t.item(r, 0).setIcon(lock_icon(accent))
                t.item(r, 0).setToolTip("Protected")
            if b["volid"] == selected:
                t.selectRow(r)
        self._sel()

    def _actions(self) -> QHBoxLayout:
        acts = QHBoxLayout()
        self.restore_btn = button("Restore…")
        self.restore_btn.clicked.connect(self.restore)
        self.protect_btn = button("Protect")
        self.protect_btn.clicked.connect(self.toggle_protect)
        self.delete_btn = button("Delete…", "destructive")
        self.delete_btn.clicked.connect(self.delete)
        close = button("Close")
        close.clicked.connect(self.close)
        for b in (self.restore_btn, self.protect_btn, self.delete_btn):
            acts.addWidget(b)
        acts.addStretch(1)
        acts.addWidget(close)
        return acts

    def _progress_widgets(self, lay: QVBoxLayout) -> None:
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.hide()
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.progress)
        lay.addWidget(self.status)
        self.relay = _Relay(self)
        self.relay.line.connect(self._log_line)


class BackupsDialog(_BackupList, QDialog):
    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, guest: dict):
        super().__init__(parent)
        self.client, self.runner, self.g = client, runner, guest
        self.backups: list[dict] = []
        self.working = False
        self.setWindowTitle(f"Backups — {kind_name(guest)} {guest['vmid']} ({guest.get('name', '')})")
        self.setModal(False)  # it can stay open beside the app while a backup runs
        lay = QVBoxLayout(self)
        lay.setSpacing(12)

        # back up now
        self.storage = QComboBox()
        self.mode = QComboBox()
        for key, text in MODES:
            self.mode.addItem(text, key)
        self.compress = QComboBox()
        for key, text in COMPRESSION:
            self.compress.addItem(text, key)
        self.note = QLineEdit("{{guestname}}")
        self.note.setToolTip(NOTE_HELP)
        self.protected = QCheckBox("Protected (never pruned or deleted until unprotected)")
        self.backup_btn = button("Back Up Now", "suggested")
        self.backup_btn.clicked.connect(self.back_up)
        form = QFormLayout()
        form.setVerticalSpacing(8)
        form.addRow("Storage", self.storage)
        form.addRow("Mode", self.mode)
        form.addRow("Compression", self.compress)
        form.addRow("Note", self.note)
        form.addRow("", self.protected)
        go_row = QHBoxLayout()
        go_row.addStretch(1)
        go_row.addWidget(self.backup_btn)
        now_box = card(label("Back up now", "heading"))
        now_box.layout().addLayout(form)
        now_box.layout().addLayout(go_row)
        lay.addWidget(now_box)

        self.schedule = label("", "dim", wrap=True)  # which backup job, if any, covers this guest
        lay.addWidget(self.schedule)

        self._progress_widgets(lay)

        # the backups
        self.heading = label("Backups", "heading")
        lay.addWidget(self.heading)
        self.table = self._table(["", "Date", "Size", "Storage", "Note"], 4)
        lay.addWidget(self.table, 1)
        lay.addLayout(self._actions())
        self.resize(720, 680)
        self.load()

    def _node(self, b: dict) -> str:
        return self.g["node"]

    def _busy(self) -> None:
        self.backup_btn.setEnabled(False)

    # -- reading -----------------------------------------------------------------------------------

    def load(self, select: str = "") -> None:
        pve, g = self.client(), self.g
        self.runner.run(lambda: {"storages": [s["storage"] for s in pve.backup_storages(g["node"])],
                                 "backups": pve.backups(g["node"], g["vmid"]), "jobs": pve.backup_jobs()},
                        lambda data, err: self._loaded(data, err, select))

    def _loaded(self, data, err, select: str = "") -> None:
        if err is not None:
            self.status.setText(str(err))
            return
        keep = self.storage.currentText()
        self.storage.clear()
        self.storage.addItems(data["storages"])
        if keep in data["storages"]:
            self.storage.setCurrentText(keep)
        if not data["storages"]:
            self.status.setText("No storage on this host takes backups. Add one in Proxmox: Datacenter → Storage.")
        self.backup_btn.setEnabled(bool(data["storages"]) and not self.working)
        covering = [j for j in data.get("jobs", []) if str(j.get("enabled", 1)) == "1" and jobs.covers(j, self.g["vmid"])]
        if covering:
            self.schedule.setText("Scheduled: " + "; ".join(
                f"{jobs.describe_schedule(j.get('schedule', ''))} to {j.get('storage', '')}, keeps "
                f"{jobs.describe_keep(j.get('prune-backups'))}" for j in covering))
        else:
            self.schedule.setText("⚠ No backup job covers this guest — Backup Jobs… on the host's page sets one up.")
        selected = select or self._selected_volid()
        self.backups = data["backups"]
        self.heading.setText(f"Backups of {self.g.get('name', '')}  ({len(self.backups)})")
        self._fill([(b, [time.strftime("%Y-%m-%d %H:%M", time.localtime(b.get("ctime", 0))), gib(b.get("size")),
                         b.get("storage", ""), str(b.get("notes") or "")]) for b in self.backups], selected)

    # -- long tasks ----------------------------------------------------------------------------------

    def back_up(self) -> None:
        pve, g = self.client(), self.g
        storage, mode, compress = self.storage.currentText(), self.mode.currentData(), self.compress.currentData()
        note, protected, log = self.note.text().strip(), self.protected.isChecked(), self.relay.line.emit

        def job():
            upid = pve.backup_now(g["node"], g["vmid"], storage, mode, compress, note, protected)
            pve.wait_task(g["node"], upid, timeout=BACKUP_TIMEOUT_S, poll=2.0, on_log=log)

        self._start(f"Backing up to {storage}… It goes on on the host even if this window is closed.")
        self.runner.run(job, lambda _r, err: self._done(err, f"Backup finished at {time.strftime('%H:%M')}."))

    def restore(self) -> None:
        b = self.selected()
        if b is None:
            return
        pve, g = self.client(), self.g
        content = "images" if g["type"] == "qemu" else "rootdir"

        def ask(data, err):
            if err is not None:
                error(self, "Restore", str(err))
                return
            dlg = RestoreDialog(self, g, b, data["id"], data["storages"])
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            c, log = dlg.choice(), self.relay.line.emit

            def job():
                upid = pve.restore(g["node"], g["type"], c["vmid"], b["volid"], c["storage"], c["replace"], c["start"])
                pve.wait_task(g["node"], upid, timeout=BACKUP_TIMEOUT_S, poll=2.0, on_log=log)

            what = f"{kind_name(g)} {c['vmid']}"
            self._start(f"Restoring as {what}…")
            self.runner.run(job, lambda _r, err: self._done(err, f"Restored as {what}.", b["volid"]))

        self.runner.run(lambda: {"id": pve.next_id(), "storages": [s["storage"] for s in
                                                                  pve.storages(g["node"], content=content)]}, ask)


class DeletedBackupsDialog(_BackupList, QDialog):
    """The backups of guests that no longer exist. Proxmox keeps them when a guest is deleted (the protected ones
    always); here one can be restored — the guest comes back, by default with its old ID and network addresses —
    protected or deleted. One window a host, beside the app."""

    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, host_name: str):
        super().__init__(parent)
        self.client, self.runner = client, runner
        self.backups: list[dict] = []
        self.working = False
        self.setWindowTitle(f"Backups of Deleted Guests — {host_name}")
        self.setModal(False)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.addWidget(label("Backups of VMs and containers that no longer exist. Restore one to bring the guest back.",
                            "dim", wrap=True))
        self.heading = label("Backups of deleted guests", "heading")
        lay.addWidget(self.heading)
        self.table = self._table(["", "Guest", "Date", "Size", "Storage", "Note"], 5)
        lay.addWidget(self.table, 1)
        self._progress_widgets(lay)
        lay.addLayout(self._actions())
        self.resize(760, 520)
        self.load()

    def _node(self, b: dict) -> str:
        return b["node"]

    def load(self, select: str = "") -> None:
        pve = self.client()
        self.runner.run(pve.deleted_guests_backups, lambda data, err: self._loaded(data, err, select))

    def _loaded(self, data, err, select: str = "") -> None:
        if err is not None:
            self.status.setText(str(err))
            return
        selected = select or self._selected_volid()
        self.backups = sorted(data, key=lambda b: (int(b["vmid"]), -int(b.get("ctime", 0))))  # a guest's together
        # (the "none" note goes in the heading: the status line keeps what was just done — "Restored as VM 102")
        self.heading.setText(f"Backups of deleted guests  ({len(self.backups)})" if self.backups else
                             "No backups of deleted guests: every backup here belongs to a guest that exists.")
        rows = []
        for b in self.backups:
            name = backup_name(b)
            guest = f"{'VM' if backup_kind(b) == 'qemu' else 'Container'} {b['vmid']}" + (f" ({name})" if name else "")
            rows.append((b, [guest, time.strftime("%Y-%m-%d %H:%M", time.localtime(b.get("ctime", 0))),
                             gib(b.get("size")), b.get("storage", ""), str(b.get("notes") or "")]))
        self._fill(rows, selected)

    def restore(self) -> None:
        b = self.selected()
        if b is None:
            return
        pve, node, kind, old = self.client(), b["node"], backup_kind(b), int(b["vmid"])
        content = "images" if kind == "qemu" else "rootdir"

        def ask(data, err):
            if err is not None:
                error(self, "Restore", str(err))
                return
            guest = {"vmid": old, "type": kind, "name": backup_name(b), "node": node}
            dlg = RestoreDialog(self, guest, b, old if old not in data["ids"] else data["id"], data["storages"],
                                gone=True)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            c, log = dlg.choice(), self.relay.line.emit

            def job():
                upid = pve.restore(node, kind, c["vmid"], b["volid"], c["storage"], False, c["start"], c["unique"])
                pve.wait_task(node, upid, timeout=BACKUP_TIMEOUT_S, poll=2.0, on_log=log)

            what = f"{kind_name(guest)} {c['vmid']}"
            self._start(f"Restoring as {what}…")
            self.runner.run(job, lambda _r, err: self._done(
                err, f"Restored as {what}: it is on the host's page again, and its backups are back with it."))

        self.runner.run(lambda: {"id": pve.next_id(), "ids": {int(g["vmid"]) for g in pve.guests()},
                                 "storages": [s["storage"] for s in pve.storages(node, content=content)]}, ask)
