"""Install Guest Agent…: a VM whose QEMU guest agent does not answer gets it — the app types the installation into the
VM's console, as the user would (without the agent nothing else reaches inside). Shown for a running VM only.

Linux: the agent turned on in the VM's settings; in the console `sudo …` installs and starts qemu-guest-agent (apt,
dnf or zypper) — sudo's password is typed by the user in this window and passed on by the app. Windows: the agent
turned on; the VirtIO drivers disc (downloaded onto the host if it is not there) in a CD drive; Win+R runs its
guest-tools installer, and Yes on Windows' question is pressed from here. A VM that had the agent off needs one restart
for the agent's channel. Then the app waits until the agent answers. The console must show a signed-in terminal or
desktop, with the English (US) keyboard; a live picture of it is in the window."""

from __future__ import annotations

import time
from typing import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout

from ..core import guestfiles, screen
from ..core.pve import Pve, PveError, agent_enabled
from . import theme
from .widgets import DialogHead, button, card, error, fit_to_width, guest_card, label

VIRTIO_URL = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
LINUX_COMMAND = ("sudo sh -c 'if command -v apt-get >/dev/null; then apt-get install -y qemu-guest-agent; "
                 "elif command -v dnf >/dev/null; then dnf install -y qemu-guest-agent; "
                 "elif command -v zypper >/dev/null; then zypper -n install qemu-guest-agent; "
                 "else echo NO-PACKAGE-MANAGER; fi; systemctl enable --now qemu-guest-agent; echo AGENT-SETUP-DONE'")
# typed into Win+R (at most 259 characters): finds the VirtIO disc by its label and runs its installer as administrator
WINDOWS_COMMAND = ("powershell -c \"$d=(Get-Volume|?{$_.FileSystemLabel -like 'virtio-win*'}).DriveLetter;"
                   "saps \\\"${d}:\\virtio-win-guest-tools.exe\\\" '/install /quiet /norestart' -Verb RunAs\"")
CD_KEYS = [f"ide{i}" for i in range(4)] + [f"sata{i}" for i in range(6)] + [f"scsi{i}" for i in range(31)]
WAIT_S = 300
POLL_S = 5.0
START_WAIT_S = 45.0  # after a restart for a new CD drive: Windows signs in before the installer is typed
PICTURE_H = 200  # the console's picture, scaled into this height: the window fits a 768-pixel screen (~730)
WIDTH = 660
PENDING, RUNNING, DONE, FAILED, SKIPPED = "○", "…", "✓", "✗", "—"


def cd_drives(cfg: dict) -> dict[str, str]:
    """{drive key: its value} of the VM's CD drives."""
    return {k: str(cfg[k]) for k in CD_KEYS if k in cfg and "media=cdrom" in str(cfg[k])}


def virtio_iso(isos: list[dict]) -> str:
    return next((i["volid"] for i in isos if "virtio-win" in (i.get("volid") or "").lower()), "")


class AgentSetupDialog(QDialog):
    def __init__(self, parent, client: Callable[[], Pve], runner, g: dict):
        super().__init__(parent)
        self.client, self.runner, self.g = client, runner, g
        self.node, self.vmid = g["node"], g["vmid"]
        self.os_name, self.agent_was_on, self.restart_needed, self.closing = "linux", False, False, False
        self.after_restart = "wait"  # what the Restart VM button goes on with: "type" (a new CD drive) or "wait"
        self.setWindowTitle(f"Install the guest agent — VM {self.vmid}")
        self.setModal(False)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)  # as every window of a guest (widgets.DialogHead)
        lay.setSpacing(12)
        lay.addWidget(DialogHead("agent", "Install the QEMU guest agent",
                                 "The guest agent lets this app copy files, show the VM's addresses and run commands "
                                 "in it. Without it nothing can reach inside, so the app types the installation into "
                                 "the VM's console — as you would."))
        lay.addWidget(guest_card(g))
        self.who = label("Inside: …", "dim")
        lay.addWidget(self.who)
        self.steps_box = QVBoxLayout()
        self.steps: list[QLabel] = []
        holder = card(spacing=6)
        holder.layout().addLayout(self.steps_box)
        lay.addWidget(holder)
        self.picture = QLabel()
        self.picture.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.picture.setFixedHeight(PICTURE_H)  # (the screen scaled into it: it never runs over what is below)
        self.shot = QPixmap()
        self.picture.setStyleSheet(f"border: 1px solid {theme.colors().border};")
        self.picture.setToolTip("The VM's screen, every few seconds")
        lay.addWidget(self.picture)
        # Linux: sudo's password, typed here and passed on by the app — never by Claude
        self.password_row = QHBoxLayout()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("sudo's password, when the console asks for it")
        self.type_password = button("Type Password", "", "Types it into the console and presses Enter")
        self.type_password.clicked.connect(self._type_password)
        self.password.returnPressed.connect(self._type_password)
        self.password_row.addWidget(self.password, 1)
        self.password_row.addWidget(self.type_password)
        lay.addLayout(self.password_row)
        # Windows: Yes on "Do you want to allow this app to make changes?"
        self.yes_btn = button("Press Yes on Windows' question", "", "Answers Windows' question (Alt+Y) when the "
                                                                    "picture shows it")
        self.yes_btn.clicked.connect(lambda: self._keys(["alt+y"]))
        lay.addWidget(self.yes_btn)
        self.need = label("", "caption", wrap=True)
        lay.addWidget(self.need)
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)
        row = QHBoxLayout()
        self.restart_btn = button("Restart VM", "", "Restarts the VM from Proxmox, so it gets the agent's channel")
        self.restart_btn.clicked.connect(self._restart)
        row.addWidget(self.restart_btn)
        row.addStretch(1)
        self.close_btn = button("Close")
        self.close_btn.clicked.connect(self.close)
        self.install_btn = button("Install", "suggested")
        self.install_btn.clicked.connect(self.install)
        row.addWidget(self.close_btn)
        row.addWidget(self.install_btn)
        lay.addLayout(row)
        for w in (self.password, self.type_password, self.yes_btn, self.restart_btn):
            w.hide()
        self.install_btn.setEnabled(False)
        self.setMinimumWidth(WIDTH)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh_picture)
        self.timer.start(3000)
        self._refresh_picture()
        self.status.setText("Reading the VM's settings…")
        pve = client()
        self.runner.run(lambda: (pve.guest_config(self.node, "qemu", self.vmid), pve.agent_ping(self.node, self.vmid)),
                        self._loaded)

    # -- what is shown ---------------------------------------------------------------------------------

    def _loaded(self, result, err) -> None:
        if err is not None:
            self.status.setText(f"⚠ {err}")
            return
        cfg, answers = result
        self.os_name = guestfiles.os_of(cfg)
        self.agent_was_on = agent_enabled(cfg)
        # (the VM itself is on the card above: here, what is inside, which decides the steps)
        self.who.setText(f"Inside: {'Windows' if self.os_name == 'windows' else 'Linux'}")
        if self.os_name == "windows":
            texts = ["Turn the agent on in the VM's settings (agent: 1)",
                     "Put the VirtIO drivers disc in a CD drive (downloaded onto the host first, if it is not there)",
                     "In the console: Win+R → the disc's virtio-win-guest-tools.exe /install /quiet /norestart — then "
                     "Yes on Windows' question",
                     "Restart the VM (the agent's channel needs it), then wait until the agent answers"]
            self.need.setText("⚠ The console must show the Windows desktop, signed in, with the English (US) keyboard.")
        else:
            texts = ["Turn the agent on in the VM's settings (agent: 1)",
                     "In the console: sudo installs and starts qemu-guest-agent (apt, dnf or zypper) — you type "
                     "sudo's password here, never Claude",
                     "Restart the VM (the agent's channel needs it), then wait until the agent answers"]
            self.need.setText("⚠ The console must show a signed-in terminal (or a terminal on the desktop), with the "
                              "English (US) keyboard.")
        for t in texts:
            lbl = label(f"{PENDING}  {t}", wrap=True)
            self.steps.append(lbl)
            self.steps_box.addWidget(lbl)
            lbl.show()  # (now: a widget added to an open window shows only later, and the height is measured now)
        fit_to_width(self, WIDTH)  # taller now — not squeezed, nothing over the picture (the live test of 26/10)
        if self.agent_was_on:
            self._mark(0, SKIPPED, "already on")
        if answers:
            for i in range(len(self.steps)):
                self._mark(i, DONE)
            self.need.hide()
            self.status.setText("✓ The agent already answers — nothing to install.")
            return
        self.install_btn.setEnabled(True)
        self.status.setText("Press Install when the console shows a signed-in desktop or terminal (see the picture).")

    def _mark(self, i: int, sign: str, note: str = "") -> None:
        text = self.steps[i].text()[3:]
        text = text.split("  (")[0]
        self.steps[i].setText(f"{sign}  {text}" + (f"  ({note})" if note else ""))

    def _refresh_picture(self) -> None:
        if not self.isVisible() and not self.shot.isNull():
            return
        pve = self.client()

        def grab():
            w, h, pixels = screen.capture(lambda: pve.open_vnc(self.node, "qemu", self.vmid))
            return screen.png(w, h, pixels, max_width=600)[0]

        def show(png, err):
            if err is None and png:
                self.shot.loadFromData(png)
                self._fit_picture()

        self.runner.run(grab, show)

    def _fit_picture(self) -> None:
        """The last picture, as large as the box allows, its proportions kept."""
        if self.shot.isNull():
            return
        box = self.picture.contentsRect().size()
        w, h = max(1, box.width() - 2), max(1, box.height() - 2)
        self.picture.setPixmap(self.shot.scaled(min(w, self.shot.width()), min(h, self.shot.height()),
                                                Qt.AspectRatioMode.KeepAspectRatio,
                                                Qt.TransformationMode.SmoothTransformation))

    def resizeEvent(self, ev) -> None:
        super().resizeEvent(ev)
        self._fit_picture()

    def _opener(self):
        pve = self.client()
        return lambda: pve.open_vnc(self.node, "qemu", self.vmid)

    # -- the steps -------------------------------------------------------------------------------------

    def install(self) -> None:
        self.install_btn.setEnabled(False)
        pve, opener, os_name = self.client(), self._opener(), self.os_name
        node, vmid, agent_was_on = self.node, self.vmid, self.agent_was_on
        self.status.setText("Working…")
        if not agent_was_on:
            self._mark(0, RUNNING)

        def prepare():
            restart, disc_waits = False, False
            if not agent_was_on:
                pve.update_config(node, "qemu", vmid, {"agent": "1"})
                restart = "agent" in pve.pending(node, vmid)
            disc = ""
            if os_name == "windows":
                cfg = pve.guest_config(node, "qemu", vmid)
                drives = cd_drives(cfg)
                disc = next((k for k, v in drives.items() if "virtio-win" in v.lower()), "")
                if not disc:
                    iso = virtio_iso(pve.isos(node))
                    if not iso:
                        storage = next((s["storage"] for s in pve.storages(node, content="iso")), "")
                        if not storage:
                            raise PveError("No storage on the host takes ISO images, for the VirtIO drivers disc.")
                        pve.wait_task(node, pve.download_url(node, storage, VIRTIO_URL, "virtio-win.iso"), timeout=3600)
                        iso = virtio_iso(pve.isos(node))
                    disc = next(iter(drives), "ide0")  # an existing drive takes the disc at once
                    pve.update_config(node, "qemu", vmid, {disc: f"{iso},media=cdrom"})
                    disc_waits = disc not in drives and disc in pve.pending(node, vmid)  # a new one: the next start
            return restart, disc_waits, disc

        def prepared(result, err):
            if err is not None:
                self._failed(0 if not agent_was_on else 1, err)
                return
            self.restart_needed, disc_waits, disc = result
            if not agent_was_on:
                self._mark(0, DONE, "at the next start" if self.restart_needed else "")
            if os_name == "windows":
                self._mark(1, DONE, disc + (", at the next start" if disc_waits else ""))
            if disc_waits:  # the installer is typed once the VM sees the disc
                self.after_restart = "type"
                self.restart_btn.show()
                self.status.setText("The VM had no CD drive: the new one comes with a restart. Press Restart VM — the "
                                    "app goes on after it.")
                return
            self._type_command()

        self.runner.run(prepare, prepared)

    def _type_command(self) -> None:
        step = 2 if self.os_name == "windows" else 1
        self._mark(step, RUNNING)
        opener, os_name = self._opener(), self.os_name

        def type_it():
            if os_name == "windows":
                screen.send(opener, "", ["win+r"])
                time.sleep(1.5)
                screen.send(opener, WINDOWS_COMMAND, ["enter"])
            else:
                screen.send(opener, LINUX_COMMAND, ["enter"])

        def typed(_r, err):
            if err is not None:
                self._failed(step, err)
                return
            self._mark(step, DONE, "typed")
            if os_name == "windows":
                self.yes_btn.show()
                self.status.setText("When the picture shows Windows asking “Do you want to allow this app to make "
                                    "changes?”, press “Press Yes on Windows' question”. The installation takes about "
                                    "a minute.")
            else:
                for w in (self.password, self.type_password):
                    w.show()
                self.password.setFocus()
                self.status.setText("If the console asks for sudo's password, type it above and press Type Password. "
                                    "The installation takes a minute or two (AGENT-SETUP-DONE when it has finished).")
            if self.restart_needed:
                self.after_restart = "wait"
                self.restart_btn.setEnabled(True)
                self.restart_btn.show()
                self.status.setText(self.status.text() + " Then press Restart VM: the agent's channel comes with a "
                                    "restart.")
            else:
                self._wait()

        self.runner.run(type_it, typed)

    def _type_password(self) -> None:
        secret = self.password.text()
        self.password.clear()
        if not secret:
            return
        if any(not " " <= c <= "~" for c in secret):
            error(self, "Password", "Only characters of an English (US) keyboard can be typed into the console.")
            return
        opener = self._opener()
        self.runner.run(lambda: screen.send(opener, secret, ["enter"]),
                        lambda _r, err: error(self, "Password", str(err)) if err is not None else None)

    def _keys(self, keys: list[str]) -> None:
        opener = self._opener()
        self.runner.run(lambda: screen.send(opener, "", keys),
                        lambda _r, err: error(self, "Console", str(err)) if err is not None else None)

    def _restart(self) -> None:
        self.restart_btn.setEnabled(False)
        pve = self.client()
        self.status.setText("Restarting the VM…")

        def reboot():
            pve.wait_task(self.node, pve.guest_action(self.node, "qemu", self.vmid, "reboot"), timeout=600)

        def done(_r, err):
            if err is not None:
                self.restart_btn.setEnabled(True)
                error(self, "Restart", str(err))
                return
            self.restart_btn.hide()
            if self.after_restart == "type":  # (the restart brought the agent's channel too)
                self.restart_needed, self.after_restart = False, "wait"
                QTimer.singleShot(int(START_WAIT_S * 1000), self._type_command)  # Windows starts first
                self.status.setText("The VM is starting; the installer is typed in 45 seconds — have it signed in.")
                return
            self._wait()

        self.runner.run(reboot, done)

    def _wait(self) -> None:
        last = len(self.steps) - 1
        self._mark(last, RUNNING)
        self.status.setText("Waiting for the agent to answer…")
        pve = self.client()

        def wait():
            end = time.monotonic() + WAIT_S
            while time.monotonic() < end and not self.closing:
                if pve.agent_ping(self.node, self.vmid):
                    return True
                time.sleep(POLL_S)
            return False

        def done(ok, err):
            if err is not None or not ok:
                self._failed(last, err or "The agent did not answer within five minutes: look at the picture — "
                                          "did the installation finish? (press Install again to retry)")
                return
            self._mark(last, DONE)
            for w in (self.password, self.type_password, self.yes_btn, self.restart_btn, self.need):
                w.hide()  # (what the console must show is past: the agent answers)
            self.status.setText("✓ The agent answers. Files, the VM's addresses and commands work now.")

        self.runner.run(wait, done)

    def _failed(self, step: int, err) -> None:
        self._mark(step, FAILED)
        self.status.setText(f"⚠ {err}")
        self.install_btn.setEnabled(True)

    def closeEvent(self, ev) -> None:
        self.closing = True
        self.timer.stop()
        super().closeEvent(ev)
