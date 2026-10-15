"""Bulk Start and Bulk Shut Down, as in Proxmox's Bulk Actions: the ticked guests in one Proxmox task, one after the
other in their boot order — Proxmox waits each one's "then wait" before it starts the next — and shut down in the
reverse order, so what starts first stops last."""

from __future__ import annotations

import re
from typing import Callable

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QHBoxLayout, QHeaderView, QProgressBar,
                               QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ..core import startup
from ..core.pve import Pve
from .widgets import button, error, label
from .worker import Runner

ACTIONS = {"start": ("Bulk Start", "Start", "started"), "shutdown": ("Bulk Shut Down", "Shut Down", "shut down")}
DEFAULT_TIMEOUT_S = 180  # Proxmox's own default for each guest
GUEST_LINE = re.compile(r"\b(VM|CT) (\d+)\b")
COLUMNS = ["ID", "Name", "Type", "Boot order"]


class _Relay(QObject):
    started = Signal()
    line = Signal(str)


def boot_order(details: dict[int, dict], vmid: int) -> int | None:
    return startup.parse((details.get(vmid) or {}).get("startup", ""))["order"]


def in_order(guests: list[dict], details: dict[int, dict], action: str) -> list[dict]:
    """The order Proxmox goes through them: by boot order (none last), then ID; reversed to shut down."""
    ordered = sorted(guests, key=lambda g: (boot_order(details, g["vmid"]) or 1 << 30, g["vmid"]))
    return ordered if action == "start" else ordered[::-1]


class BulkDialog(QDialog):
    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, guests: list[dict],
                 details: dict[int, dict], action: str, preselect: list[int] | None = None,
                 on_started: Callable[[], None] | None = None, on_done: Callable[[], None] | None = None):
        super().__init__(parent)
        self.client, self.runner, self.action = client, runner, action
        self.details = details
        self.on_started, self.on_done = on_started, on_done
        self.working = False
        self.finished_ok = False
        title, self.verb, self.past = ACTIONS[action]
        want = "stopped" if action == "start" else "running"
        self.guests = in_order([g for g in guests if g.get("status") == want and not g.get("template")],
                               details, action)
        self.setWindowTitle(title)
        self.setModal(False)  # it can stay open beside the app while the guests start one by one
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(label(title, "heading"))
        if action == "start":
            text = ("The ticked guests start one by one, in this order (their boot order). Proxmox waits each one's "
                    "<i>then wait</i> before it starts the next.")
        else:
            text = ("The ticked guests shut down in this order — the reverse of their boot order, so what starts "
                    "first stops last. Guests with the same order shut down together.")
        lay.addWidget(label(text, "dim", wrap=True))

        presets = QHBoxLayout()
        presets.setSpacing(6)
        presets.addWidget(label("Tick:", "dim"))
        self.preset_btns = {}
        for key, text in (("all", "All"), ("none", "None"), ("onboot", "Start at boot")):
            if key == "onboot" and action != "start":
                continue
            b = button(text, "flat")
            b.clicked.connect(lambda _=False, k=key: self.tick(k))
            presets.addWidget(b)
            self.preset_btns[key] = b
        presets.addStretch(1)
        lay.addLayout(presets)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)  # Qt leaves no room for the box beside the ID
        hdr.resizeSection(0, QFontMetrics(self.font()).horizontalAdvance("000000") + 56)
        for col in range(len(COLUMNS)):
            self.table.horizontalHeaderItem(col).setTextAlignment(Qt.AlignmentFlag.AlignLeft |
                                                                  Qt.AlignmentFlag.AlignVCenter)
        self.table.setRowCount(len(self.guests))
        chosen = set(preselect) if preselect is not None else None
        for r, g in enumerate(self.guests):
            order = boot_order(details, g["vmid"])
            onboot = bool((details.get(g["vmid"]) or {}).get("onboot"))
            cells = [str(g["vmid"]), g.get("name", ""), "Container" if g["type"] == "lxc" else "VM",
                     (str(order) if order else "Any") + (" · at boot" if onboot else "")]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, g["vmid"])
                self.table.setItem(r, c, item)
            first = self.table.item(r, 0)
            first.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            if chosen is not None:
                on = g["vmid"] in chosen
            else:  # to start: those that start with the host; to shut down: every running one
                on = onboot if action == "start" else True
            first.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
        self.toggled_row = -1
        self.table.pressed.connect(lambda *_: setattr(self, "toggled_row", -1))  # a new click begins
        self.table.itemChanged.connect(self._ticked)
        self.table.cellClicked.connect(self._row_clicked)
        self.table.setMinimumHeight(min(360, 40 + 32 * max(3, len(self.guests))))
        lay.addWidget(self.table, 1)
        self.empty = label(f"No guest is {'stopped' if action == 'start' else 'running'}.", "dim")
        self.empty.setVisible(not self.guests)
        lay.addWidget(self.empty)

        self.force = QCheckBox("Then stop the ones still running (like pulling the plug)")
        self.force.setChecked(True)  # Proxmox's default; untick to leave a guest that will not shut down running
        self.timeout = QSpinBox()
        self.timeout.setRange(10, 7200)
        self.timeout.setValue(DEFAULT_TIMEOUT_S)
        self.timeout.setSuffix(" s")
        self.timeout.setToolTip("How long each guest may take to shut down by itself.")
        if action == "shutdown":
            wait_row = QHBoxLayout()
            wait_row.setSpacing(8)
            wait_row.addWidget(label("Wait up to"))
            wait_row.addWidget(self.timeout)
            wait_row.addWidget(label("for each guest to shut down"))
            wait_row.addStretch(1)
            lay.addLayout(wait_row)
            lay.addWidget(self.force)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.hide()
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.progress)
        lay.addWidget(self.status)

        acts = QHBoxLayout()
        acts.addStretch(1)
        self.close_btn = button("Cancel")
        self.close_btn.clicked.connect(self.close)
        self.go = button(self.verb, "suggested" if action == "start" else "destructive")
        self.go.clicked.connect(self.run)
        acts.addWidget(self.close_btn)
        acts.addWidget(self.go)
        lay.addLayout(acts)
        self.relay = _Relay(self)
        self.relay.line.connect(self._log_line)
        self.relay.started.connect(lambda: self.on_started() if self.on_started is not None else None)
        self.names = {g["vmid"]: g.get("name", "") for g in guests}
        self.seen: list[int] = []
        self.resize(560, 520)
        self._update()

    # -- choosing ----------------------------------------------------------------------------------

    def _ticked(self, item: QTableWidgetItem) -> None:
        self.toggled_row = item.row()  # when a click on the box itself did it, that click must not undo it
        self._update()

    def _row_clicked(self, row: int, col: int) -> None:
        """A click anywhere on the row ticks it, not only on the small box."""
        if self.toggled_row == row:
            self.toggled_row = -1
            return
        if self.working:
            return
        item = self.table.item(row, 0)
        item.setCheckState(Qt.CheckState.Unchecked if item.checkState() == Qt.CheckState.Checked
                           else Qt.CheckState.Checked)

    def tick(self, which: str) -> None:
        for r, g in enumerate(self.guests):
            on = {"all": True, "none": False}.get(which, bool((self.details.get(g["vmid"]) or {}).get("onboot")))
            self.table.item(r, 0).setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

    def chosen(self) -> list[dict]:
        """The ticked guests, in the order they go."""
        return [g for r, g in enumerate(self.guests) if self.table.item(r, 0).checkState() == Qt.CheckState.Checked]

    def _update(self) -> None:
        n = len(self.chosen())
        if not self.working and not self.finished_ok:
            self.go.setText(f"{self.verb} {n}" if n else self.verb)
            self.go.setEnabled(n > 0)

    # -- running -----------------------------------------------------------------------------------

    def run(self) -> None:
        picked = self.chosen()
        if not picked or self.working:
            return
        by_node: dict[str, list[int]] = {}
        for g in picked:
            by_node.setdefault(g["node"], []).append(g["vmid"])
        pve, action, relay = self.client(), self.action, self.relay
        timeout, force = self.timeout.value(), self.force.isChecked()
        per_guest = timeout + 60 if action == "shutdown" else 600
        self.total = len(picked)

        def job():
            for node, ids in by_node.items():  # one task per node; a single host has one
                upid = pve.start_all(node, ids) if action == "start" else pve.stop_all(node, ids, timeout, force)
                relay.started.emit()
                pve.wait_task(node, upid, timeout=per_guest * len(ids) + 120, poll=1.0, on_log=relay.line.emit)

        self.working = True
        self.seen = []
        for w in (self.table, self.timeout, self.force, *self.preset_btns.values()):
            w.setEnabled(False)
        self.go.setEnabled(False)
        self.close_btn.setText("Close")
        self.progress.setRange(0, self.total)
        self.progress.setValue(0)
        self.progress.show()
        self.status.setText(f"{'Starting' if action == 'start' else 'Shutting down'} {self.total} guest(s)… "
                            "It goes on on the host even if this window is closed.")
        self.runner.run(job, self._done)

    def _log_line(self, line: str) -> None:
        """'Starting VM 201', 'Stopping CT 100 (timeout = 180 seconds)', 'Waiting for 15 seconds (startup delay)'."""
        if line.startswith("TASK "):
            return
        m = GUEST_LINE.search(line)
        if m is not None:
            vmid = int(m.group(2))
            if vmid not in self.seen:
                self.seen.append(vmid)
            self.progress.setValue(min(len(self.seen), self.total))
            name = self.names.get(vmid, "")
            line = line.replace(m.group(0), f"{m.group(0)} ({name})" if name else m.group(0), 1)
        self.status.setText(line)

    def _done(self, _r, err) -> None:
        self.working = False
        self.progress.hide()
        if err is not None:
            self.status.setText("")
            error(self, ACTIONS[self.action][0], str(err))
            for w in (self.table, self.timeout, self.force, *self.preset_btns.values()):
                w.setEnabled(True)
            self._update()
        else:
            self.finished_ok = True
            self.status.setText(f"Done — {self.total} guest(s) {self.past}.")
            self.go.hide()
        if self.on_done is not None:
            self.on_done()
