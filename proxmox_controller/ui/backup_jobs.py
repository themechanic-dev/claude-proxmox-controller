"""Scheduled backups — Proxmox's backup jobs (Datacenter → Backup): the list, a job's settings, Run Now, and which
guests no job covers."""

from __future__ import annotations

import time
from typing import Callable

from PySide6.QtCore import Qt, QTime
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QHeaderView, QLineEdit, QListWidget, QListWidgetItem, QProgressBar,
                               QSpinBox, QTableWidget, QTableWidgetItem, QTimeEdit, QVBoxLayout, QWidget)

from ..core import jobs
from ..core.pve import Pve
from .backups import COMPRESSION, MODES, NOTE_HELP, _Relay, progress_of
from .widgets import button, confirm, error, fit_to_width, label
from .worker import Runner

GUESTS = (("only", "Only the ticked guests"), ("all", "All guests"), ("except", "All guests except the ticked ones"))
RUN_TIMEOUT_S = 24 * 3600


class JobDialog(QDialog):
    """A backup job's settings, new or existing."""

    def __init__(self, parent: QWidget, job: dict | None, guests: list[dict], storages: list[str]):
        super().__init__(parent)
        self.job = job or {}
        self.setWindowTitle("Edit Backup Job" if job else "New Backup Job")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        form = QFormLayout()
        form.setVerticalSpacing(8)
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(str(self.job.get("enabled", 1)) == "1")
        form.addRow("", self.enabled)

        sched = jobs.parse_schedule(self.job.get("schedule", "03:00"))
        self.preset = QComboBox()
        for key, text in jobs.PRESETS:
            self.preset.addItem(text, key)
        self.preset.setCurrentIndex(self.preset.findData(sched["preset"]))
        self.day = QComboBox()
        for d in jobs.DAYS:
            self.day.addItem(jobs.DAY_NAMES[d], d)
        self.day.setCurrentIndex(self.day.findData(sched["day"]))
        self.at = QTimeEdit(QTime(sched["hour"], sched["minute"]))
        self.at.setDisplayFormat("HH:mm")
        self.custom = QLineEdit(sched["custom"] if sched["preset"] == "custom" else "")
        self.custom.setPlaceholderText("e.g. mon,wed,fri 22:00   ·   */6:00 (every 6 hours)")
        when = QHBoxLayout()
        when.setSpacing(8)
        when.addWidget(self.preset, 2)
        when.addWidget(self.day, 1)
        when.addWidget(label("at"))
        when.addWidget(self.at)
        form.addRow("When", when)
        form.addRow("", self.custom)
        self.preset.currentIndexChanged.connect(lambda *_: self._preset_changed())

        self.which = QComboBox()
        for key, text in GUESTS:
            self.which.addItem(text, key)
        everyone = str(self.job.get("all", "0")) in ("1", "true", "True")
        excluded = {int(v) for v in str(self.job.get("exclude") or "").split(",") if v.strip().isdigit()}
        self.which.setCurrentIndex(self.which.findData(("except" if excluded else "all") if everyone else "only"))
        ticked = excluded if everyone else set(jobs.job_vmids(self.job))
        self.guests = QListWidget()
        self.guests.setMinimumHeight(120)
        self.guests.setMaximumHeight(170)
        for g in sorted(guests, key=lambda g: g["vmid"]):
            if g.get("template"):
                continue
            item = QListWidgetItem(f"{g['vmid']}  {g.get('name', '')}  ({'container' if g['type'] == 'lxc' else 'VM'})")
            item.setData(Qt.ItemDataRole.UserRole, g["vmid"])
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if g["vmid"] in ticked else Qt.CheckState.Unchecked)
            self.guests.addItem(item)
        form.addRow("Guests", self.which)
        form.addRow("", self.guests)
        self.which.currentIndexChanged.connect(lambda *_: self.guests.setEnabled(self.which.currentData() != "all"))
        self.guests.setEnabled(self.which.currentData() != "all")

        self.storage = QComboBox()
        self.storage.addItems(storages)
        if self.job.get("storage") in storages:
            self.storage.setCurrentText(self.job["storage"])
        self.mode = QComboBox()
        for key, text in MODES:
            self.mode.addItem(text, key)
        self.mode.setCurrentIndex(max(0, self.mode.findData(self.job.get("mode", "snapshot"))))
        self.compress = QComboBox()
        for key, text in COMPRESSION:
            self.compress.addItem(text, key)
        self.compress.setCurrentIndex(max(0, self.compress.findData(str(self.job.get("compress", "zstd")))))
        self.note = QLineEdit(self.job.get("notes-template", "{{guestname}}"))
        self.note.setToolTip(NOTE_HELP)
        form.addRow("Storage", self.storage)
        form.addRow("Mode", self.mode)
        form.addRow("Compression", self.compress)
        form.addRow("Note", self.note)

        keep = jobs.parse_keep(self.job.get("prune-backups"))
        self.keep = {}
        krow = QHBoxLayout()
        krow.setSpacing(8)
        for key, name in jobs.KEEP:
            spin = QSpinBox()
            spin.setRange(0, 999)
            spin.setSpecialValueText("—")
            spin.setValue(keep.get(key, 0))
            spin.setToolTip(f"How many {name.lower()} backups to keep (— = not this way)")
            self.keep[key] = spin
            krow.addWidget(label(name))
            krow.addWidget(spin, 1)
        form.addRow("Keep", krow)
        self.comment = QLineEdit(self.job.get("comment", ""))
        form.addRow("Comment", self.comment)
        lay.addLayout(form)
        lay.addWidget(label("Keep: older backups of this job beyond these numbers are removed after each run "
                            "(protected ones stay). All “—”: the storage's own rule applies.", "caption", wrap=True))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setProperty("kind", "suggested")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        self._preset_changed()
        fit_to_width(self, 600)

    def _preset_changed(self) -> None:
        preset = self.preset.currentData()
        self.day.setVisible(preset == "weekly")
        self.at.setEnabled(preset != "custom")
        self.custom.setVisible(preset == "custom")

    def ticked(self) -> list[int]:
        return [self.guests.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.guests.count())
                if self.guests.item(i).checkState() == Qt.CheckState.Checked]

    def problem(self) -> str:
        if self.preset.currentData() == "custom" and not self.custom.text().strip():
            return "Write the custom schedule, for example: mon,wed,fri 22:00"
        if self.which.currentData() == "only" and not self.ticked():
            return "Tick the guests this job backs up."
        if not self.storage.currentText():
            return "No storage on this host takes backups."
        return ""

    def params(self) -> dict:
        """The job as Proxmox takes it. For an existing job, settings left empty are removed (delete=…)."""
        t = self.at.time()
        p = {"enabled": self.enabled.isChecked(),
             "schedule": jobs.schedule_value(self.preset.currentData(), t.hour(), t.minute(), self.day.currentData(),
                                             self.custom.text()),
             "storage": self.storage.currentText(), "mode": self.mode.currentData(),
             "compress": self.compress.currentData(), "notes-template": self.note.text().strip(),
             "prune-backups": jobs.keep_value({k: s.value() for k, s in self.keep.items()}),
             "comment": self.comment.text().strip()}
        which = self.which.currentData()
        if which == "only":
            p["vmid"] = ",".join(str(v) for v in self.ticked())
        else:
            p["all"] = True
            p["exclude"] = ",".join(str(v) for v in self.ticked()) if which == "except" else ""
        empty = [k for k in ("notes-template", "prune-backups", "comment", "exclude") if p.get(k) == ""]
        for k in empty:
            del p[k]
        if self.job:  # an edit: say what goes, and switch between "all" and a list cleanly
            gone = [k for k in empty if self.job.get(k) not in (None, "")]
            gone += ["all"] if which == "only" and self.job.get("all") else []
            gone += ["vmid"] if which != "only" and self.job.get("vmid") else []
            if gone:
                p["delete"] = ",".join(gone)
        return p

    def _save(self) -> None:
        problem = self.problem()
        if problem:
            error(self, "Backup Job", problem)
            return
        self.accept()


class BackupJobsDialog(QDialog):
    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, nodes: list[str], host_name: str):
        super().__init__(parent)
        self.client, self.runner, self.nodes = client, runner, nodes
        self.jobs: list[dict] = []
        self.guest_list: list[dict] = []
        self.storages: list[str] = []
        self.working = False
        self.setWindowTitle(f"Backup Jobs — {host_name}")
        self.setModal(False)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(label("Scheduled backups that Proxmox runs by itself (Datacenter → Backup).", "dim", wrap=True))
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["On", "When", "Guests", "Storage", "Keep", "Next run", "Comment"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(180)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._sel)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        lay.addWidget(self.table, 1)
        self.uncovered = label("", "dim", wrap=True)
        lay.addWidget(self.uncovered)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.hide()
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.progress)
        lay.addWidget(self.status)
        acts = QHBoxLayout()
        self.new_btn = button("New Job…", "suggested")
        self.new_btn.clicked.connect(self.new)
        self.edit_btn = button("Edit…")
        self.edit_btn.clicked.connect(self.edit)
        self.run_btn = button("Run Now")
        self.run_btn.clicked.connect(self.run_now)
        self.toggle_btn = button("Disable")
        self.toggle_btn.clicked.connect(self.toggle)
        self.delete_btn = button("Delete…", "destructive")
        self.delete_btn.clicked.connect(self.delete)
        close = button("Close")
        close.clicked.connect(self.close)
        for b in (self.new_btn, self.edit_btn, self.run_btn, self.toggle_btn, self.delete_btn):
            acts.addWidget(b)
        acts.addStretch(1)
        acts.addWidget(close)
        lay.addLayout(acts)
        self.relay = _Relay(self)
        self.relay.line.connect(self._log_line)
        self.resize(900, 520)
        self.load()

    # -- reading -----------------------------------------------------------------------------------

    def load(self, select: str = "") -> None:
        pve, node = self.client(), self.nodes[0]
        self.runner.run(lambda: {"jobs": pve.backup_jobs(), "guests": pve.guests(), "uncovered": pve.not_backed_up(),
                                 "storages": [s["storage"] for s in pve.backup_storages(node)]},
                        lambda data, err: self._loaded(data, err, select))

    def _loaded(self, data, err, select: str = "") -> None:
        if err is not None:
            self.status.setText(str(err))
            return
        select = select or self._selected_id()
        self.jobs = sorted(data["jobs"], key=lambda j: j.get("id", ""))
        self.guest_list, self.storages = data["guests"], data["storages"]
        names = {g["vmid"]: g.get("name", str(g["vmid"])) for g in self.guest_list}
        t = self.table
        t.setRowCount(len(self.jobs))
        for r, j in enumerate(self.jobs):
            on = str(j.get("enabled", 1)) == "1"
            nxt = j.get("next-run")
            cells = ["Yes" if on else "No", jobs.describe_schedule(j.get("schedule", "")),
                     jobs.describe_guests(j, names), j.get("storage", ""), jobs.describe_keep(j.get("prune-backups")),
                     time.strftime("%a %d %b %H:%M", time.localtime(int(nxt))) if on and nxt else "—",
                     j.get("comment", "")]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, j["id"])
                if not on:
                    item.setForeground(self.palette().color(self.palette().ColorRole.PlaceholderText))
                t.setItem(r, c, item)
            if j["id"] == select:
                t.selectRow(r)
        missing = [f"{g['vmid']} {g.get('name', '')}" for g in sorted(data["uncovered"], key=lambda g: g["vmid"])]
        self.uncovered.setText(("⚠ No job backs up: " + ", ".join(missing)) if missing
                               else "Every guest is backed up by a job.")
        if not self.jobs:
            self.status.setText("No backup jobs yet: New Job… makes one.")
        self._sel()

    def _selected_id(self) -> str:
        items = self.table.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else ""

    def selected(self) -> dict | None:
        job_id = self._selected_id()
        return next((j for j in self.jobs if j["id"] == job_id), None)

    def _sel(self) -> None:
        j, free = self.selected(), not self.working
        for b in (self.edit_btn, self.run_btn, self.toggle_btn, self.delete_btn):
            b.setEnabled(bool(j) and free)
        self.toggle_btn.setText("Disable" if j and str(j.get("enabled", 1)) == "1" else "Enable")

    # -- changing ------------------------------------------------------------------------------------

    def _apply(self, fn: Callable[[Pve], None], select: str = "") -> None:
        pve = self.client()
        self.runner.run(lambda: fn(pve), lambda _r, err: (error(self, "Backup Jobs", str(err)) if err else None,
                                                          self.load(select)))

    def new(self) -> None:
        dlg = JobDialog(self, None, self.guest_list, self.storages)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            params = dlg.params()
            self._apply(lambda pve: pve.create_backup_job(params))

    def edit(self) -> None:
        j = self.selected()
        if j is None:
            return
        dlg = JobDialog(self, j, self.guest_list, self.storages)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            params = dlg.params()
            self._apply(lambda pve: pve.update_backup_job(j["id"], params), j["id"])

    def toggle(self) -> None:
        j = self.selected()
        if j is not None:
            on = str(j.get("enabled", 1)) != "1"
            self._apply(lambda pve: pve.update_backup_job(j["id"], {"enabled": on}), j["id"])

    def delete(self) -> None:
        j = self.selected()
        if j is None or not confirm(self, "Delete this backup job?",
                                    f"“{jobs.describe_schedule(j.get('schedule', ''))}” stops. The backups it made "
                                    "stay where they are.", "Delete Job", destructive=True):
            return
        self._apply(lambda pve: pve.delete_backup_job(j["id"]))

    def run_now(self) -> None:
        j = self.selected()
        if j is None:
            return
        pve, node, log = self.client(), self.nodes[0], self.relay.line.emit

        def job():
            upid = pve.run_job_now(node, j)
            pve.wait_task(node, upid, timeout=RUN_TIMEOUT_S, poll=2.0, on_log=log)

        self.working = True
        self.progress.setRange(0, 0)
        self.progress.show()
        self.status.setText("Running the job now… It goes on on the host even if this window is closed.")
        self._sel()
        self.runner.run(job, self._ran)

    def _log_line(self, line: str) -> None:
        pct, text = progress_of(line)
        if pct is not None:
            self.progress.setRange(0, 100)
            self.progress.setValue(pct)
        if text:
            self.status.setText(text)

    def _ran(self, _r, err) -> None:
        self.working = False
        self.progress.hide()
        if err is not None:
            self.status.setText("")
            error(self, "Backup Jobs", str(err))
        else:
            self.status.setText(f"The job ran at {time.strftime('%H:%M')}.")
        self.load()
