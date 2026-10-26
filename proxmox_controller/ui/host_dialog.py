"""Add or edit a Proxmox host: address, API token, certificate confirmation, Wake-on-LAN."""

from __future__ import annotations

import html
from typing import Callable

from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLineEdit,
                               QVBoxLayout, QWidget)

from ..core import netinfo, wol
from ..core.pve import Host, Pve, fetch_fingerprint, normalize_fingerprint, split_address
from ..core.store import new_host_id
from .widgets import button, error, fit_to_width, label
from .worker import Runner

TOKEN_HELP = ("In the Proxmox web UI: <b>Datacenter → Permissions → API Tokens → Add</b>. User <b>root@pam</b>, "
              "a Token ID such as <b>controller</b>, and untick <b>Privilege Separation</b> so the token has the "
              "user's rights. Proxmox shows the secret only once — copy it here.")
CERT_HELP = ("Compare it with the Proxmox web UI: <b>&lt;node&gt; → System → Certificates</b>, the "
             "<b>pve-ssl.pem</b> line, <b>Fingerprint</b>. If they match, nobody is pretending to be your server.")


def fingerprint_html(fp: str) -> str:
    """The 32 bytes on two lines of 16. On one line the text has no place to wrap, so the end was cut off at the
    dialog's edge and the fingerprint looked different from the one in Proxmox (it was the same)."""
    parts = fp.split(":")
    if len(parts) != 32:
        return f"<b>{html.escape(fp)}</b>"
    return "<b>" + ":".join(parts[:16]) + ":<br>" + ":".join(parts[16:]) + "</b>"


class HostDialog(QDialog):
    def __init__(self, parent: QWidget, runner: Runner, make_client: Callable[[Host], Pve], host: Host | None = None):
        super().__init__(parent)
        self.runner = runner
        self.make_client = make_client
        self.host = host
        self.result_host: Host | None = None
        self.setWindowTitle("Edit Host" if host else "Add a Proxmox Host")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        form = QFormLayout()
        form.setVerticalSpacing(8)
        self.name = QLineEdit(host.name if host else "")
        self.name.setPlaceholderText("Home server")
        self.address = QLineEdit(host.address if host else "")
        self.address.setPlaceholderText("192.168.1.10  (port 8006 unless you add :port)")
        self.token_id = QLineEdit(host.token_id if host else "root@pam!controller")
        self.secret = QLineEdit(host.token_secret if host else "")
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret.setPlaceholderText("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        form.addRow("Name", self.name)
        form.addRow("Address", self.address)
        form.addRow("API token ID", self.token_id)
        form.addRow("API token secret", self.secret)
        lay.addLayout(form)
        lay.addWidget(label(TOKEN_HELP, "caption", wrap=True))

        lay.addWidget(label("Certificate", "heading"))
        self.fingerprint = label(fingerprint_html(host.fingerprint) if host and host.fingerprint else "Not fetched yet.",
                                 "dim", wrap=True, selectable=True)
        self.fp_value = host.fingerprint if host else ""
        fetch = button("Get Certificate")
        fetch.clicked.connect(self.fetch)
        lay.addWidget(self.fingerprint)
        lay.addWidget(label(CERT_HELP, "caption", wrap=True))
        self.fp_ok = QCheckBox("I compared it — it is the same as in Proxmox")
        self.fp_ok.setChecked(bool(host and host.fingerprint))
        frow = QHBoxLayout()
        frow.setSpacing(12)
        frow.addWidget(fetch)
        frow.addWidget(self.fp_ok)
        frow.addStretch(1)
        lay.addLayout(frow)

        lay.addWidget(label("Wake-on-LAN (optional)", "heading"))
        wform = QFormLayout()
        wform.setVerticalSpacing(8)
        self.mac = QLineEdit(host.mac if host else "")
        self.mac.setPlaceholderText("a0:b1:c2:d3:e4:f5")
        detect = button("Detect", tooltip="Read it from this computer's network table (open the host's web page "
                                          "first if it is not found)")
        detect.clicked.connect(self.detect_mac)
        mrow = QHBoxLayout()
        mrow.setSpacing(8)
        mrow.addWidget(self.mac, 1)
        mrow.addWidget(detect)
        self.broadcast = QLineEdit(host.broadcast if host else "255.255.255.255")
        wform.addRow("MAC address", mrow)
        wform.addRow("Broadcast address", self.broadcast)
        lay.addLayout(wform)
        lay.addWidget(label("Lets the app turn the host on. Wake-on-LAN must also be turned on in the host's "
                            "BIOS/UEFI and on its network card — see Help.", "caption", wrap=True))

        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        test = buttons.addButton("Test Connection", QDialogButtonBox.ButtonRole.ActionRole)
        test.clicked.connect(lambda: self.test(save_after=False))
        save = buttons.addButton("Save", QDialogButtonBox.ButtonRole.AcceptRole)
        save.setProperty("kind", "suggested")
        buttons.accepted.connect(lambda: self.test(save_after=True))
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        fit_to_width(self, 560)
        self.address.textChanged.connect(self._address_changed)

    def _address_changed(self, *_):
        if self.host is None or self.address.text().strip() != self.host.address:
            self.fp_value = ""
            self.fingerprint.setText("Not fetched yet.")
            self.fp_ok.setChecked(False)

    def fetch(self) -> None:
        addr = self.address.text().strip()
        if not addr:
            error(self, "Certificate", "Write the host's address first.")
            return
        self.status.setText(f"Connecting to {addr}…")

        def done(fp, err):
            if err is not None:
                self.status.setText(str(err))
                return
            old = normalize_fingerprint(self.host.fingerprint) if self.host and self.host.fingerprint else ""
            self.fp_value = fp
            if old and old == fp:
                self.fingerprint.setText(f"{fingerprint_html(fp)}<br>Same as the one you confirmed before.")
            else:
                self.fp_ok.setChecked(False)
                warn = "<br><b>This is a different certificate than before.</b>" if old else ""
                self.fingerprint.setText(f"{fingerprint_html(fp)}{warn}")
            self.status.setText("")

        self.runner.run(lambda: fetch_fingerprint(addr), done)

    def detect_mac(self) -> None:
        addr = self.address.text().strip()
        if not addr:
            return
        host = split_address(addr)[0]
        self.status.setText("Looking in this computer's network table…")

        def done(mac, err):
            if mac:
                self.mac.setText(mac)
                self.status.setText(f"Found {mac} for {host}.")
            else:
                self.status.setText(f"No MAC address known for {host} yet. Open its web page once, then try again.")

        self.runner.run(lambda: netinfo.mac_for(host), done)

    def build(self) -> Host | str:
        name, addr = self.name.text().strip(), self.address.text().strip()
        if not addr:
            return "Write the host's address."
        if not self.token_id.text().strip() or "!" not in self.token_id.text():
            return "The token ID looks like root@pam!controller."
        if not self.secret.text().strip():
            return "Paste the token secret."
        if not self.fp_value:
            return "Press Get Certificate and compare the fingerprint."
        if not self.fp_ok.isChecked():
            return "Compare the fingerprint with the one in Proxmox and tick the box."
        mac = self.mac.text().strip()
        if mac:
            try:
                mac = wol.normalize_mac(mac)
            except ValueError:
                return "The MAC address looks like a0:b1:c2:d3:e4:f5."
        return Host(id=self.host.id if self.host else new_host_id(), name=name or addr, address=addr,
                    token_id=self.token_id.text().strip(), token_secret=self.secret.text().strip(),
                    fingerprint=self.fp_value, mac=mac, broadcast=self.broadcast.text().strip() or "255.255.255.255",
                    extra=self.host.extra if self.host else {})

    def test(self, save_after: bool) -> None:
        h = self.build()
        if isinstance(h, str):
            error(self, "Host", h)
            return
        pve = self.make_client(h)
        self.status.setText("Testing the connection…")
        self.setEnabled(False)

        def done(data, err):
            self.setEnabled(True)
            if err is not None:
                self.status.setText(f"✗ {err}")
                return
            version, nodes = data
            self.status.setText(f"✓ Connected — Proxmox VE {version.get('version', '?')}, "
                                f"node{'s' if len(nodes) != 1 else ''}: {', '.join(n['node'] for n in nodes)}")
            if save_after:
                self.result_host = h
                self.accept()

        self.runner.run(lambda: (pve.version(), pve.nodes()), done)
