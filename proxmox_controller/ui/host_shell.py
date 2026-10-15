"""The host's own shell and its upgrade — over SSH, in the computer's terminal (the Proxmox API keeps both for root's
own login, and refuses them to a token). The SSH settings of a host: its user and port, the host key the user
confirmed, and — if wanted — the app's key on the host, so the password is not asked every time. The password keeps
working either way: the host's SSH settings are never changed."""

from __future__ import annotations

import html
import time
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
                               QHeaderView, QLineEdit, QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ..core import apt, ssh
from ..core.pve import Host, Pve, PveError
from .widgets import button, card, confirm, error, fit_to_width, label
from .worker import Runner

UPGRADE = ["pveupgrade"]  # what Proxmox's own Upgrade button runs (it shows what it will do and asks first)


def fingerprint_lines(fp: str) -> str:
    """'SHA256:…' (50 signs, no space) on two lines: on one, a label cuts its end off at the edge without a word —
    and a fingerprint with an end missing looks like another one (the certificate's did, 12/10)."""
    half = (len(fp) + 1) // 2
    return html.escape(fp[:half]) + "<br>" + html.escape(fp[half:])


def settings_of(host: Host) -> dict:
    """The host's SSH settings: {"user", "port", "key": bool, "key_fp"}; empty until set up."""
    return host.extra.get("ssh") if isinstance(host.extra.get("ssh"), dict) else {}


def ready(host: Host) -> bool:
    """Set up, and the host key still the one confirmed — then Console and Upgrade open at once."""
    s = settings_of(host)
    return bool(s) and bool(ssh.trusted_host_key(host.hostname, int(s.get("port", 22))))


def open_shell(host: Host, command: list[str] | tuple = (), what: str = "Console") -> None:
    """The terminal with ssh to the host (and the command, if any), titled «Proxmox Console — Home». SshError if it
    cannot open."""
    s = settings_of(host)
    ssh.open_terminal(ssh.ssh_argv(host.hostname, int(s.get("port", 22)), s.get("user", "root"),
                                   bool(s.get("key")), list(command)), f"Proxmox {what} — {host.name}")


class SshDialog(QDialog):
    """«SSH» for one host: shown the first time Console or Upgrade is pressed, and from the Console button's menu."""

    def __init__(self, parent: QWidget | None, host: Host, runner: Runner, saved: Callable[[], None],
                 first_time: bool = False):
        super().__init__(parent)
        self.host, self.runner, self.saved = host, runner, saved
        self.s = dict(settings_of(host))
        self.scanned = ""  # the host key as found now
        self.setWindowTitle(f"SSH — {host.name}")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.addWidget(label("<b>Console</b> and <b>Upgrade</b> open this computer's terminal with SSH to the host — "
                            "Proxmox keeps its shell for root's own login. Your password always works; a key only "
                            "saves typing it.", wrap=True))
        missing = ssh.missing_tools()
        form = QFormLayout()
        form.setVerticalSpacing(8)
        self.user = QLineEdit(self.s.get("user", "root"))
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(self.s.get("port", 22)))
        form.addRow("User", self.user)
        form.addRow("Port", self.port)
        lay.addLayout(form)
        # (not a form row: a form gives a row the height of its first text, and the fingerprint's lines were cut off)
        self.hostkey = label("Asking the host for its key…", "dim", wrap=True, selectable=True)
        self.hostkey.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(label("<b>Host key</b>"))
        lay.addWidget(self.hostkey)
        lay.addWidget(label("The first time, SSH asks whether this is really your host. On the host, <i>ssh-keygen "
                            "-lf /etc/ssh/ssh_host_ed25519_key.pub</i> shows the same fingerprint.", "caption",
                            wrap=True))

        self.use_key = QCheckBox("Set up a key (no password each time)")
        self.use_key.setToolTip("The app makes its own key and adds it beside root's password on the host. "
                                "The password keeps working.")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("root's password on the host — used once, not kept")
        self.key_state = label("", "caption", wrap=True)
        self.remove_btn = button("Remove Key", "destructive", "Take the app's key off the host again")
        self.remove_btn.clicked.connect(self.remove_key)
        key_row = QHBoxLayout()
        key_row.addWidget(self.use_key, 1)
        key_row.addWidget(self.remove_btn)
        lay.addLayout(key_row)
        lay.addWidget(self.password)
        lay.addWidget(self.key_state)
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.go = buttons.addButton("Continue" if first_time else "Save", QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("kind", "suggested")
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

        has_key = bool(self.s.get("key"))
        self.use_key.setChecked(has_key or not self.s)  # offered at first; as it is afterwards
        self.use_key.setEnabled(not has_key)
        self.remove_btn.setVisible(has_key)
        if has_key:
            self.key_state.setText(f"The app's key is on the host ({self.s.get('key_fp', '')}). It is kept in "
                                   f"{ssh.key_path()}.")
        self.use_key.toggled.connect(lambda *_: self._update())
        self.password.textChanged.connect(lambda *_: self._update())
        self.port.valueChanged.connect(lambda *_: self.scan())
        self._update()
        fit_to_width(self, 520)
        if missing:
            self.status.setText("This computer lacks " + ", ".join(missing) + " (Ubuntu: sudo apt install "
                                "openssh-client).")
            self.go.setEnabled(False)
        else:
            self.scan()

    def _update(self) -> None:
        needs_password = self.use_key.isChecked() and not self.s.get("key")
        self.password.setVisible(needs_password)
        self.go.setEnabled(bool(self.scanned) and bool(self.user.text().strip())
                           and (not needs_password or bool(self.password.text())))
        for w in (self.hostkey, self.key_state, self.status):  # their text changed just now: measured afresh, or
            w.updateGeometry()                                  # the window keeps the old height and cuts lines off
        self.layout().invalidate()
        fit_to_width(self, 520)

    def scan(self) -> None:
        host, port = self.host.hostname, self.port.value()
        self.scanned = ""
        self.hostkey.setText("Asking the host for its key…")
        self._update()

        def done(key, err):
            if err is not None:
                self.hostkey.setText(f"<span style='color:#e5484d'>{html.escape(str(err))}</span>")
                return
            self.scanned = key
            fp, kind = ssh.fingerprint(key), key.split()[0].removeprefix("ssh-").upper()
            before = ssh.trusted_host_key(host, port)
            text = f"{html.escape(kind)}<br><b>{fingerprint_lines(fp)}</b>"
            if before and before != key:
                text += ("<br><span style='color:#e5484d'>Not the key confirmed before — expected only if the "
                         "host was reinstalled. Before:<br>" + fingerprint_lines(ssh.fingerprint(before)) + "</span>")
            elif before:
                text += "<br>The one confirmed before."
            self.hostkey.setText(text)
            self._update()

        self.runner.run(lambda: ssh.scan_host_key(host, port), done)

    def save(self) -> None:
        host, port, user = self.host.hostname, self.port.value(), self.user.text().strip()
        key_wanted = self.use_key.isChecked() and not self.s.get("key")
        password, scanned = self.password.text(), self.scanned
        self.password.clear()  # (held only for the job below)

        def job():
            ssh.trust_host_key(host, port, scanned)
            if not key_wanted:
                return None
            line = ssh.ensure_key()
            ssh.run_with_password(host, port, user, password, ssh.install_key_script(line))
            ssh.run_with_key(host, port, user, "true")  # the key works now
            return ssh.fingerprint(line)

        def finished(key_fp, err):
            self.setEnabled(True)
            if err is not None:
                self.status.setText(str(err))
                self._update()
                return
            self.s.update(user=user, port=port)
            if key_fp:
                self.s.update(key=True, key_fp=key_fp, key_since=time.strftime("%Y-%m-%d"))
            self.s.setdefault("key", False)
            self.host.extra["ssh"] = self.s
            self.saved()
            self.accept()

        self.setEnabled(False)
        self.status.setText("Adding the key…" if key_wanted else "Saving…")
        self.runner.run(job, finished)

    def remove_key(self) -> None:
        host, port, user = self.host.hostname, self.port.value(), self.user.text().strip()

        def job():
            ssh.run_with_key(host, port, user, ssh.remove_key_script(ssh.public_line()))

        def finished(_r, err):
            self.setEnabled(True)
            if err is not None:
                self.status.setText(f"The key could not be removed: {err}")
                return
            self.s.update(key=False)
            self.s.pop("key_fp", None)
            self.s.pop("key_since", None)
            self.host.extra["ssh"] = self.s
            self.saved()
            self.remove_btn.hide()
            self.use_key.setEnabled(True)
            self.use_key.setChecked(False)
            self.key_state.setText("The key is off the host. The password is asked each time.")
            self.status.setText("")
            self._update()

        self.setEnabled(False)
        self.status.setText("Removing the key…")
        self.runner.run(job, finished)


class UpgradeDialog(QDialog):
    """What waits to be upgraded on the host (as Proxmox found at its last check), and the upgrade itself — in the
    terminal, as Proxmox's own Upgrade button does it."""

    def __init__(self, parent: QWidget | None, client: Callable[[], Pve], runner: Runner, host: Host, node: str,
                 upgrade: Callable[[], None]):
        super().__init__(parent)
        self.client, self.runner, self.host, self.node, self.upgrade = client, runner, host, node, upgrade
        self.setWindowTitle(f"Upgrade — {host.name}")
        self.setModal(False)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        self.heading = label("Looking for updates…", "heading")
        lay.addWidget(self.heading)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Package", "Installed", "New"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(200)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.table, 1)
        # where the updates come from: without a subscription Proxmox's enterprise repository refuses the host, and
        # Proxmox's own updates never show — the free No-Subscription one gives them (as Updates → Repositories does)
        self.sources = label("Package sources…", "dim", wrap=True)
        self.switch_btn = button("Use No-Subscription", "suggested",
                                 "Take Proxmox's updates from its free repository instead of the enterprise one")
        self.switch_btn.clicked.connect(self.use_no_subscription)
        self.switch_btn.hide()
        src_row = QHBoxLayout()
        src_row.addWidget(self.sources, 1)
        src_row.addWidget(self.switch_btn, 0, Qt.AlignmentFlag.AlignTop)
        src_box = card(label("Package sources", "heading"))
        src_box.layout().addLayout(src_row)
        lay.addWidget(src_box)
        lay.addWidget(label("<b>Upgrade…</b> opens this computer's terminal with SSH to the host and runs "
                            "<i>pveupgrade</i> — what Proxmox's own Upgrade button runs: it shows what it will do and "
                            "asks before installing. A new kernel needs the host rebooted afterwards.", "caption",
                            wrap=True))
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)
        row = QHBoxLayout()
        self.check_btn = button("Check Now", "", "Ask the package sources for updates now (Proxmox does it daily)")
        self.check_btn.clicked.connect(self.check_now)
        self.go = button("Upgrade…", "suggested")
        self.go.clicked.connect(self.upgrade)
        close = button("Close")
        close.clicked.connect(self.close)
        row.addWidget(self.check_btn)
        row.addStretch(1)
        row.addWidget(self.go)
        row.addWidget(close)
        lay.addLayout(row)
        self.resize(640, 560)
        self.load()

    def load(self) -> None:
        pve, node = self.client(), self.node
        self.runner.run(lambda: pve.apt_updates(node), self._loaded)
        self.runner.run(lambda: pve.apt_repositories(node), self._sources)

    def _sources(self, info, err) -> None:
        if err is not None:
            self.sources.setText(f"Could not be read: {err}")
            self.switch_btn.hide()
            return
        lines = apt.describe(info)
        needs = bool(apt.plan_no_subscription(info))
        if needs:
            lines.append("<b>Without a Proxmox subscription the enterprise repository refuses this host, so Proxmox's "
                         "own updates never show.</b> The free No-Subscription repository gives them.")
        self.sources.setText("<br>".join(lines) if lines else "Debian's only.")
        self.switch_btn.setVisible(needs)

    def use_no_subscription(self) -> None:
        if not confirm(self, "Use the No-Subscription repository?",
                       "On the host, Proxmox's free No-Subscription repository is added (Ceph's too, where its "
                       "enterprise one is on) and the enterprise ones are switched off — as Updates → Repositories "
                       "does it in the web UI. Then the updates are checked again. A subscription bought later can "
                       "switch it back.", "Use No-Subscription"):
            return
        pve, node = self.client(), self.node

        def finished(done, err):
            self.switch_btn.setEnabled(True)
            if err is not None:
                error(self, "Package sources", str(err))
                self.load()
                return
            self.status.setText("Package sources: " + "; ".join(done) + "." if done else "Nothing to change.")
            self.check_now()

        self.switch_btn.setEnabled(False)
        self.status.setText("Changing the package sources…")
        self.runner.run(lambda: apt.switch_to_no_subscription(pve, node), finished)

    def _loaded(self, updates, err) -> None:
        if err is not None:
            self.heading.setText("Updates could not be read")
            self.status.setText(str(err))
            return
        n = len(updates)
        self.heading.setText(f"{n} update{'' if n == 1 else 's'} waiting on {self.node}" if n else
                             f"No updates waiting on {self.node}")
        self.table.setRowCount(n)
        for r, u in enumerate(updates):
            for c, text in enumerate((u.get("Package", ""), u.get("OldVersion", ""), u.get("Version", ""))):
                item = QTableWidgetItem(str(text))
                item.setToolTip(str(u.get("Title", "")))
                self.table.setItem(r, c, item)

    def check_now(self) -> None:
        pve, node = self.client(), self.node

        def job():
            """None when all went well; the sources that refused (from the task's log) when apt-get update failed —
            on a host without a subscription it always does, though the other sources were checked."""
            upid = pve.apt_refresh(node)
            if not (isinstance(upid, str) and upid.startswith("UPID:")):
                return None
            try:
                pve.wait_task(node, upid, timeout=600)
                return None
            except PveError as e:
                lines = [str(x.get("t", "")) for x in pve.task_log(node, upid)]
                return {"failed": str(e), "refused": apt.refused(lines)}

        def finished(result, err):
            self.check_btn.setEnabled(True)
            when = time.strftime("%H:%M")
            if err is not None:  # the check could not even start
                error(self, "Check Now", str(err))
                self.status.setText("")
            elif result is None:
                self.status.setText(f"Checked at {when}: every source answered.")
            elif result["refused"]:
                rest = " The other sources were checked." if apt.only_enterprise(result["refused"]) else ""
                self.status.setText(f"Checked at {when}. Refused: {apt.explain(result['refused'])}.{rest}")
            else:
                self.status.setText(f"Checked at {when}, but the check failed: {result['failed']}")
            self.load()

        self.check_btn.setEnabled(False)
        self.status.setText("Asking the package sources…")
        self.runner.run(job, finished)
