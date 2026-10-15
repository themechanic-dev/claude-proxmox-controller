"""The host's recent tasks under the guests, as in Proxmox's own Tasks panel — running ones with how long they have
been going — and a task's log in a window of its own, with Stop for one still running."""

from __future__ import annotations

import time
from typing import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFontDatabase, QIcon
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QHeaderView, QMenu, QPlainTextEdit,
                               QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)

from ..core import tasks
from ..core.pve import Pve
from . import theme
from .widgets import button, confirm, dot_icon, error, label
from .worker import Runner

COLUMNS = ["", "Started", "Task", "User", "Took", "Status"]
COL_DOT, COL_START, COL_TASK, COL_USER, COL_TOOK, COL_STATUS = range(len(COLUMNS))
SHOWN = 50          # the newest this many, as Proxmox's panel
ROWS_VISIBLE = 5    # the panel's height, in rows; it scrolls for the rest
LOG_POLL_MS = 1000
LOG_PAGE = 500      # lines read at a time; a long log (a big backup's) comes in several reads
UPID_ROLE = Qt.ItemDataRole.UserRole


def status_color(task: dict) -> str:
    c = theme.colors()
    if tasks.running(task):
        return c.accent
    return c.success if tasks.ok(task) else c.danger


class TasksPanel(QWidget):
    def __init__(self, open_log: Callable[[dict], None], stop: Callable[[dict], None], prefs: dict | None = None,
                 save_prefs: Callable[[], None] | None = None):
        super().__init__()
        self.open_log_cb, self.stop_cb = open_log, stop
        self.prefs = prefs if prefs is not None else {}
        self.save_prefs = save_prefs
        self.tasks: list[dict] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.head = head = QHBoxLayout()  # the page adds its Bulk buttons on the right
        head.setSpacing(10)
        self.toggle = QToolButton()
        self.toggle.setProperty("kind", "flat")
        self.toggle.setText("Tasks")
        self.toggle.setCheckable(True)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.setToolTip("Show or hide the host's recent tasks")
        self.toggle.setStyleSheet("QToolButton { font-size: 11.5pt; font-weight: 700; padding: 2px 6px 2px 2px; }")
        self.toggle.setChecked(bool(self.prefs.get("tasks_open", True)))
        self.toggle.toggled.connect(self._toggled)
        head.addWidget(self.toggle)
        self.summary = label("", "dim")
        head.addWidget(self.summary)
        head.addStretch(1)
        lay.addLayout(head)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setToolTip("Double-click a task for its log")
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(COL_TASK, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(COL_STATUS, QHeaderView.ResizeMode.Interactive)
        hdr.resizeSection(COL_STATUS, 220)  # an error can be long: the rest is in its tooltip and the log
        hdr.setStretchLastSection(False)
        for col in range(len(COLUMNS)):
            hdr_item = self.table.horizontalHeaderItem(col)
            hdr_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.doubleClicked.connect(lambda *_: self.open_selected())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        rows = self.table.verticalHeader().defaultSectionSize() * ROWS_VISIBLE
        self.table.setFixedHeight(hdr.sizeHint().height() + rows + 2 * self.table.frameWidth())
        lay.addWidget(self.table)
        self.ticker = QTimer(self)  # the running tasks' "Took", between refreshes
        self.ticker.timeout.connect(self._tick)
        self._toggled(self.toggle.isChecked())

    def _toggled(self, on: bool) -> None:
        self.toggle.setIcon(QIcon(theme.icon_file("chevron-down" if on else "chevron-right")))
        self.table.setVisible(on)
        if bool(self.prefs.get("tasks_open", True)) != on:
            self.prefs["tasks_open"] = on
            if self.save_prefs is not None:
                self.save_prefs()
        self._update_ticker()

    def show_tasks(self, rows: list[dict] | None, guests: dict[int, dict], problem: str = "") -> None:
        """The newest tasks of every node. rows None: they could not be read (problem says why)."""
        if rows is None:
            self.tasks = []
            self.table.setRowCount(0)
            self.summary.setText(problem)
            self._update_ticker()
            return
        keep = self.selected_upid()
        self.tasks = sorted(rows, key=lambda t: int(t.get("starttime") or 0), reverse=True)[:SHOWN]
        t = self.table
        t.clearSelection()  # the rows move as new tasks come on top: select the same task again below
        t.setRowCount(len(self.tasks))
        dim = QColor(theme.colors().dim)
        danger = QColor(theme.colors().danger)
        now = time.time()
        for r, task in enumerate(self.tasks):
            outcome = tasks.outcome(task)
            cells = ["", tasks.started(task, now), tasks.describe(task, guests), str(task.get("user") or ""),
                     tasks.took(task, now), outcome]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setData(UPID_ROLE, task.get("upid"))
                t.setItem(r, c, item)
            t.item(r, COL_DOT).setIcon(dot_icon(status_color(task)))
            t.item(r, COL_USER).setForeground(dim)
            status = t.item(r, COL_STATUS)
            if not tasks.running(task) and not tasks.ok(task):
                status.setForeground(danger)
            status.setToolTip(outcome if len(outcome) > 30 else "")
            if task.get("upid") == keep:
                t.selectRow(r)
        busy = sum(1 for task in self.tasks if tasks.running(task))
        failed = sum(1 for task in self.tasks if not tasks.running(task) and not tasks.ok(task))
        parts = [f"{busy} running"] if busy else []
        if self.tasks and not busy:
            last = self.tasks[0]
            what = tasks.describe(last, guests)
            what = what if len(what) <= 60 else what[:59] + "…"
            parts.append(f"last: {what} — {'OK' if tasks.ok(last) else 'failed'}")  # the error is in the list
        if failed:
            parts.append(f"{failed} failed")
        self.summary.setText("  ·  ".join(parts) if parts else "No tasks yet")
        self._update_ticker()

    def _update_ticker(self) -> None:
        want = self.table.isVisibleTo(self) and any(tasks.running(task) for task in self.tasks)
        if want and not self.ticker.isActive():
            self.ticker.start(1000)
        elif not want:
            self.ticker.stop()

    def _tick(self) -> None:
        now = time.time()
        for r, task in enumerate(self.tasks):
            if tasks.running(task) and self.table.item(r, COL_TOOK) is not None:
                self.table.item(r, COL_TOOK).setText(tasks.took(task, now))

    def selected_upid(self) -> str:
        items = self.table.selectedItems()
        return items[0].data(UPID_ROLE) if items else ""

    def selected(self) -> dict | None:
        upid = self.selected_upid()
        return next((t for t in self.tasks if t.get("upid") == upid), None)

    def open_selected(self) -> None:
        task = self.selected()
        if task is not None:
            self.open_log_cb(task)

    def _context_menu(self, pos) -> None:
        task = self.selected()
        if task is None:
            return
        menu = QMenu(self)
        menu.addAction("Open Log").triggered.connect(lambda *_: self.open_log_cb(task))
        stop = menu.addAction("Stop Task…")
        stop.setEnabled(tasks.running(task))
        stop.triggered.connect(lambda *_: self.stop_cb(task))
        menu.exec(self.table.viewport().mapToGlobal(pos))


class TaskLogDialog(QDialog):
    """One task's log, followed live while it runs."""

    def __init__(self, parent: QWidget | None, client: Callable[[], Pve], runner: Runner, task: dict, title: str,
                 on_end: Callable[[], None] | None = None):
        super().__init__(parent)
        self.client, self.runner, self.task, self.on_end = client, runner, dict(task), on_end
        self.node, self.upid = task.get("node", ""), task.get("upid", "")
        self.seen = 0
        self.polling = False
        self.ended = not tasks.running(task)
        self.setWindowTitle(f"Task — {title}")
        self.setModal(False)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(label(title, "heading"))
        self.state = label("", "dim", wrap=True)
        lay.addWidget(self.state)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.log.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        lay.addWidget(self.log, 1)
        acts = QHBoxLayout()
        self.stop_btn = button("Stop Task…", "destructive", "Ask Proxmox to stop this task")
        self.stop_btn.clicked.connect(self.stop)
        acts.addWidget(self.stop_btn)
        acts.addStretch(1)
        close = button("Close")
        close.clicked.connect(self.close)
        acts.addWidget(close)
        lay.addLayout(acts)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.resize(760, 460)
        self._show_state()
        self.poll()
        if not self.ended:
            self.timer.start(LOG_POLL_MS)

    def _show_state(self) -> None:
        t = self.task
        who = str(t.get("user") or "")
        if self.ended:
            took = tasks.took(t)
            self.state.setText(f"Started {tasks.started(t)}  ·  {who}  ·  took {took}  ·  {tasks.outcome(t)}")
        else:
            self.state.setText(f"Started {tasks.started(t)}  ·  {who}  ·  running for {tasks.took(t)}")
        self.stop_btn.setVisible(not self.ended)

    def poll(self) -> None:
        if self.polling:
            return
        self.polling = True
        pve, node, upid, seen = self.client(), self.node, self.upid, self.seen

        def job():
            status = pve.task_status(node, upid)  # first: a finished task's last lines are read after it
            return status, pve.task_log(node, upid, start=seen, limit=LOG_PAGE)

        self.runner.run(job, self._polled)

    def _polled(self, data, err) -> None:
        self.polling = False
        if err is not None:
            self.state.setText(f"Could not read the task — {err}")
            self.timer.stop()
            return
        status, entries = data
        lines = []
        for e in entries:
            self.seen = max(self.seen, int(e.get("n", self.seen)))
            if e.get("t") not in (None, "", "no content"):
                lines.append(str(e["t"]))
        if lines:
            bar = self.log.verticalScrollBar()
            at_end = bar.value() >= bar.maximum() - 2
            self.log.appendPlainText("\n".join(lines))
            if at_end:
                bar.setValue(bar.maximum())
        if status.get("status") == "stopped" and not self.ended:
            self.ended = True
            self.timer.stop()
            self.task.update(status=status.get("exitstatus") or "unknown",
                             endtime=int(status.get("endtime") or time.time()))
            if self.on_end is not None:
                self.on_end()
        self._show_state()
        if len(entries) >= LOG_PAGE and self.isVisible():  # more lines than one read gives: the rest at once
            self.poll()

    def resume(self) -> None:
        """Shown again after being closed: follow the task again if it still runs."""
        if not self.ended and not self.timer.isActive():
            self.timer.start(LOG_POLL_MS)
            self.poll()

    def stop(self) -> None:
        if self.ended or not confirm(self, "Stop this task?", "Proxmox stops it where it is. A backup or a copy "
                                     "stopped halfway is left unfinished.", "Stop Task", destructive=True):
            return
        pve, node, upid = self.client(), self.node, self.upid
        self.stop_btn.setEnabled(False)

        def done(_r, err):
            self.stop_btn.setEnabled(True)
            if err is not None:
                error(self, "Stop task", str(err))
            self.poll()

        self.runner.run(lambda: pve.stop_task(node, upid), done)

    def closeEvent(self, ev) -> None:
        self.timer.stop()
        super().closeEvent(ev)
