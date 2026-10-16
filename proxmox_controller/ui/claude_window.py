"""Claude Access: the switch for all, Claude's access per host (Set Up / Remove), the switches of each host, the
connection to the Claude apps, and the log of every request."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QDialog, QFrame, QGridLayout,
                               QHBoxLayout, QHeaderView, QPushButton, QScrollArea, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from ..core import claude_access, claude_connect, claude_policy, connector_log, store
from ..core.claude_policy import ASK, OFF, ON
from .widgets import button, card, confirm, error, label
from .worker import Runner

DECISIONS = {"allowed": "Allowed (On)", "approved": "Approved by you", "denied": "Denied by you",
             "timeout": "No answer", "cancelled": "Cancelled", "off": "Refused (Off)", "not-set-up": "Not set up",
             "error": "Failed"}
LOG_ROWS = 200


class SwitchRow:
    """Off / Ask / On for one kind of request."""

    def __init__(self, grid: QGridLayout, row: int, key: str, title: str, text: str, changed):
        self.key = key
        grid.addWidget(label(f"<b>{title}</b>"), row * 2, 0)
        caption = label(text, "caption")  # one line: wrapped labels in a grid overlapped the next row
        caption.setToolTip(text)
        grid.addWidget(caption, row * 2 + 1, 0)
        box = QHBoxLayout()
        box.setSpacing(4)
        self.group = QButtonGroup()
        self.buttons: dict[str, QPushButton] = {}
        for state, word in ((OFF, "Off"), (ASK, "Ask"), (ON, "On")):
            b = QPushButton(word)
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumWidth(56)
            b.clicked.connect(lambda _=False, s=state: changed(key, s))
            self.group.addButton(b)
            box.addWidget(b)
            self.buttons[state] = b
        holder = QWidget()
        holder.setLayout(box)
        box.setContentsMargins(0, 0, 0, 0)
        grid.addWidget(holder, row * 2, 1, 2, 1, Qt.AlignmentFlag.AlignVCenter)

    def show(self, state: str, enabled: bool) -> None:
        self.buttons[state].setChecked(True)
        for b in self.buttons.values():
            b.setEnabled(enabled)


class ClaudeWindow(QDialog):
    def __init__(self, win, connector, runner: Runner):
        super().__init__(win)
        self.win, self.connector, self.runner = win, connector, runner
        self.setWindowTitle("Claude Access")
        self.setModal(False)
        self.busy = False
        outer = QVBoxLayout(self)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(12)

        head = QHBoxLayout()
        head.addWidget(label("Claude Access", "title"))
        head.addStretch(1)
        self.enabled = QCheckBox("Let Claude use Proxmox Controller")
        self.enabled.setStyleSheet("QCheckBox { font-weight: 700; }")
        self.enabled.toggled.connect(self.set_enabled)
        head.addWidget(self.enabled)
        lay.addLayout(head)
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)

        # the Claude apps
        apps = QGridLayout()
        apps.setHorizontalSpacing(12)
        apps.setVerticalSpacing(6)
        self.code_state, self.desktop_state = label("", "dim"), label("", "dim")
        self.code_btn, self.desktop_btn = button("Connect"), button("Connect")
        self.code_btn.clicked.connect(lambda: self.toggle_app("code"))
        self.desktop_btn.clicked.connect(lambda: self.toggle_app("desktop"))
        for r, (name, state, btn) in enumerate((("Claude Code and the Code tab", self.code_state, self.code_btn),
                                                ("Claude Desktop and Cowork", self.desktop_state, self.desktop_btn))):
            apps.addWidget(label(f"<b>{name}</b>"), r, 0)
            apps.addWidget(state, r, 1)
            apps.addWidget(btn, r, 2)
        apps.setColumnStretch(1, 1)
        apps_box = card(label("Claude apps on this computer", "heading"))
        apps_box.layout().addLayout(apps)
        apps_box.layout().addWidget(label("A new conversation in Claude Code picks the connector up; Claude Desktop "
                                          "reads it when it starts (quit and open it again).", "caption", wrap=True))
        lay.addWidget(apps_box)

        # one host
        host_head = QHBoxLayout()
        host_head.addWidget(label("Host", "heading"))
        self.host = QComboBox()
        self.host.currentIndexChanged.connect(lambda *_: self.show_host())
        host_head.addWidget(self.host, 1)
        lay.addLayout(host_head)
        self.access = label("", wrap=True)
        self.lock_note = label("", "caption", wrap=True)
        self.setup_btn = button("Set Up…", "suggested")
        self.setup_btn.clicked.connect(self.set_up)
        self.remove_btn = button("Remove…", "destructive")
        self.remove_btn.clicked.connect(self.remove)
        access_row = QHBoxLayout()
        access_row.addWidget(self.access, 1)
        access_row.addWidget(self.setup_btn)
        access_row.addWidget(self.remove_btn)
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(2)
        grid.setColumnStretch(0, 1)
        self.rows = [SwitchRow(grid, i, key, title, text, self.set_switch)
                     for i, (key, title, text, _) in enumerate(claude_policy.CATEGORIES)]
        host_box = QFrame()
        host_box.setObjectName("card")
        hb = QVBoxLayout(host_box)
        hb.setContentsMargins(14, 14, 14, 14)
        hb.setSpacing(10)
        hb.addLayout(access_row)
        hb.addWidget(self.lock_note)
        hb.addLayout(grid)
        hb.addWidget(label("Off: refused, by this app and by Proxmox. Ask: you approve each request in a window. "
                           "On: done at once. Claude's token can only read between requests; the app lends it a "
                           "kind's privileges just for a request it allows. Host commands go over SSH with this "
                           "app's key, not through Proxmox: only this app refuses them. Help lists every tool "
                           "under its switch.", "caption", wrap=True))
        lay.addWidget(host_box)

        # the log
        lay.addWidget(label("Requests", "heading"))
        self.log = QTableWidget(0, 6)
        self.log.setHorizontalHeaderLabels(["Time", "From", "Host", "Request", "Decision", "Outcome"])
        self.log.verticalHeader().setVisible(False)
        self.log.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.log.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.log.setShowGrid(False)
        self.log.setWordWrap(False)
        hdr = self.log.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)  # long outcomes end in "…" (whole in the tooltip)
        self.log.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.log.setMinimumHeight(160)
        lay.addWidget(self.log, 1)
        scroll = QScrollArea()  # a small screen scrolls instead of cutting the window off
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        close = button("Close")
        close.clicked.connect(self.close)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close)
        outer.addLayout(row)

        connector.logged.connect(self.add_log)
        self.fill_hosts()
        self.refresh()
        for entry in connector_log.last(LOG_ROWS):
            self.add_log(entry)
        screen = QGuiApplication.primaryScreen()
        room = screen.availableGeometry().height() - 60 if screen is not None else 900
        self.resize(880, max(500, min(940, room)))

    # -- state ---------------------------------------------------------------------------------------

    def settings(self) -> dict:
        return self.win.settings

    def fill_hosts(self) -> None:
        keep = self.host.currentData()
        self.host.blockSignals(True)
        self.host.clear()
        for h in self.win.hosts:
            self.host.addItem(f"{h.name}  —  {h.address}", h.id)
        index = max(0, self.host.findData(keep or self.win.current_id))
        self.host.setCurrentIndex(index)
        self.host.blockSignals(False)
        self.show_host()

    def current_host(self):
        hid = self.host.currentData()
        return next((h for h in self.win.hosts if h.id == hid), None)

    def refresh(self) -> None:
        on = claude_policy.enabled(self.settings())
        self.enabled.blockSignals(True)
        self.enabled.setChecked(on)
        self.enabled.blockSignals(False)
        if self.win.demo:
            text = "Demo mode: the connector is not offered to the Claude apps; the pretend hosts can be tried here."
        elif not self.connector.listening:
            text = "Another Proxmox Controller window already answers Claude's requests."
        elif on:
            text = "Claude's requests are answered while this app runs, as the switches below say."
        else:
            text = "Off: every request from Claude is refused."
        self.status.setText(text)
        for state, btn, connected in ((self.code_state, self.code_btn, claude_connect.code_connected()),
                                      (self.desktop_state, self.desktop_btn, claude_connect.desktop_connected())):
            state.setText("Connected" if connected else "Not connected")
            btn.setText("Disconnect" if connected else "Connect")
            btn.setEnabled(not self.win.demo)
        self.show_host()

    def show_host(self) -> None:
        h = self.current_host()
        ready = bool(h) and bool(self.connector.tokens.get(h.id))
        locked = self.win.demo or store.secrets_state() == "locked"
        if h is None:
            self.access.setText("No hosts yet.")
        elif ready:
            self.access.setText(f"Claude's access on <b>{h.name}</b>: set up<br>"
                                f"<span style='white-space:nowrap'>token <tt>{claude_access.TOKEN_ID}</tt></span>")
        else:
            self.access.setText(f"Claude's access on <b>{h.name}</b>: not set up. Claude cannot use this host.")
        self.setup_btn.setText("Set Up Again…" if ready else "Set Up…")
        self.setup_btn.setEnabled(bool(h) and locked and not self.busy)
        self.remove_btn.setVisible(ready)
        self.remove_btn.setEnabled(not self.busy)
        self.lock_note.setVisible(not locked)
        self.lock_note.setText("⚠ Lock the API tokens with a password first (☰ → Hosts and Settings → Security): "
                               "unlocked, Claude could read your own token and go around these switches.")
        switches = claude_policy.host_switches(self.settings(), h.id) if h else claude_policy.DEFAULTS
        for r in self.rows:
            r.show(switches[r.key], bool(h) and not self.busy)

    # -- changes -------------------------------------------------------------------------------------

    def set_enabled(self, on: bool) -> None:
        self.settings().setdefault("claude", {})["enabled"] = on
        if not on:
            self.connector.allowances.clear()
        self.win._save_settings()
        self.refresh()

    def set_switch(self, key: str, state: str) -> None:
        h = self.current_host()
        if h is None:
            return
        claude_policy.set_switch(self.settings(), h.id, key, state)
        if state != ASK:
            self.connector.allowances.until.pop((h.id, key), None)  # an hour granted no longer applies
        self.win._save_settings()
        self.show_host()
        if self.connector.tokens.get(h.id):
            self.sync_role(h)

    def sync_role(self, h) -> None:
        admin, loans = self.win.make_client(h), self.connector.loans
        switches = claude_policy.host_switches(self.settings(), h.id)

        def job():
            with loans.lock:  # not while a request is borrowing
                return claude_access.sync(admin, switches, loans.lent(h.id))

        self.runner.run(job, lambda _r, err: error(self, "Claude Access", f"The host did not take the change: {err}")
                        if err is not None else None)

    def set_up(self) -> None:
        h = self.current_host()
        if h is None:
            return
        if not confirm(self, f"Set up Claude's access on {h.name}?",
                       "With your API token, this creates on the host:\n"
                       f"• the user {claude_access.USER} — without a password, it cannot log in to the web interface\n"
                       f"• the role {claude_access.ROLE} — between requests it can only read (when Read is On); for "
                       "each request the app allows, it gets that kind's privileges for just that request\n"
                       "• a permission on / for that user\n"
                       f"• the API token {claude_access.TOKEN_ID}, kept with your tokens (locked with your password)\n\n"
                       "Set up again, it gets a new token (the old one stops working). Remove takes it all away.",
                       "Set Up"):
            return
        admin, switches = self.win.make_client(h), claude_policy.host_switches(self.settings(), h.id)
        self._busy(True)

        def done(result, err):
            self._busy(False)
            if err is not None:
                error(self, "Claude Access", f"Setting up failed: {err}")
                return
            secret, given = result
            self.connector.tokens.set(h.id, secret)
            self.win.notify(f"Claude's access is set up on {h.name}")
            self.show_host()

        self.runner.run(lambda: claude_access.setup(admin, switches), done)

    def remove(self) -> None:
        h = self.current_host()
        if h is None or not confirm(self, f"Remove Claude's access from {h.name}?",
                                    f"The token, the user {claude_access.USER} and the role {claude_access.ROLE} are "
                                    "deleted from the host. Claude can no longer use it.", "Remove", destructive=True):
            return
        admin = self.win.make_client(h)
        self._busy(True)

        def done(_r, err):
            self._busy(False)
            if err is not None:
                error(self, "Claude Access", f"Removing failed: {err}")
                return
            self.connector.tokens.set(h.id, "")
            self.show_host()

        self.runner.run(lambda: claude_access.remove(admin), done)

    def toggle_app(self, which: str) -> None:
        connected = claude_connect.code_connected() if which == "code" else claude_connect.desktop_connected()
        fn = {("code", False): claude_connect.connect_code, ("code", True): claude_connect.disconnect_code,
              ("desktop", False): claude_connect.connect_desktop,
              ("desktop", True): claude_connect.disconnect_desktop}[(which, connected)]
        self._busy(True)

        def done(_r, err):
            self._busy(False)
            if err is not None:
                error(self, "Claude Access", str(err))
            self.refresh()

        self.runner.run(fn, done)

    def _busy(self, on: bool) -> None:
        self.busy = on
        for b in (self.code_btn, self.desktop_btn):
            b.setEnabled(not on and not self.win.demo)
        self.show_host()

    # -- the log -------------------------------------------------------------------------------------

    def add_log(self, entry: dict) -> None:
        t = self.log
        t.insertRow(0)
        when = time.strftime("%H:%M:%S", time.localtime(entry.get("time", 0)))
        cells = [when, entry.get("client", ""), entry.get("host", ""), entry.get("what") or entry.get("tool", ""),
                 DECISIONS.get(entry.get("decision", ""), entry.get("decision", "")), entry.get("outcome", "")]
        for c, text in enumerate(cells):
            item = QTableWidgetItem(str(text))
            if c == 3 and entry.get("reason"):
                item.setToolTip(f"Reason: {entry['reason']}")
            elif c == 5 and len(str(text)) > 40:
                item.setToolTip(str(text))
            t.setItem(0, c, item)
        while t.rowCount() > LOG_ROWS:
            t.removeRow(t.rowCount() - 1)
