"""The connector inside the app: it hears Claude's requests (through the bridge), decides with the switches — asking
the user in a window of its own when a switch says Ask — lends Claude's token the privileges for just that request,
runs it on the request's own thread, logs it, and refreshes the host's page.

Threads: each request arrives on a thread of the link server. Whatever touches the app's state (settings, hosts,
windows) is done on the window's thread through on_gui(); the Proxmox calls stay on the request's thread."""

from __future__ import annotations

import html
import json
import sys
from concurrent.futures import Future
from typing import Callable

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QApplication, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout

from ..core import claude_access, claude_policy, connector_log, store
from ..core.claude_policy import ASK, OFF, ON, Allowances
from ..core.connector_link import LinkServer
from ..core.connector_tools import TOOLS, Context, Image, ToolError, check
from ..core.pve import Host, Pve, PveError
from . import theme
from .widgets import button, label

ASK_TIMEOUT_S = 120
REFUSED_403 = ("Proxmox refused it: Claude's token has no privilege for this. The switch for it may be Off, or "
               "Claude's access on this host needs Set Up again (Proxmox Controller → Claude Access).")


def not_off(switches: dict) -> frozenset:
    return frozenset(k for k in claude_policy.KEYS if switches.get(k, OFF) != OFF)


def refused_403(e: PveError) -> str:
    """REFUSED_403 with what Proxmox said — the privilege and the path it checked — so the cause can be found."""
    return f"{REFUSED_403} Proxmox said: {e.reason}" if e.reason else REFUSED_403


class Refused(Exception):
    """The switches (or the app's state) say no: logged with the decision that made it."""

    def __init__(self, message: str, decision: str = "off"):
        super().__init__(message)
        self.decision = decision


def ok_result(value) -> dict:
    if isinstance(value, Image):
        return {"content": [{"type": "image", "data": value.b64(), "mimeType": "image/png"},
                            {"type": "text", "text": value.text}], "isError": False}
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False, indent=1, default=str)}],
            "isError": False}


def error_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


class Tokens:
    """Where Claude's token secrets live: the (lockable) secrets file — or, in demo mode, nowhere but memory."""

    def __init__(self, demo: bool = False):
        self.demo = demo
        self.memory: dict[str, str] = {}

    def get(self, host_id: str) -> str:
        return self.memory.get(host_id, "") if self.demo else store.claude_token(host_id)

    def set(self, host_id: str, secret: str) -> None:
        if self.demo:
            if secret:
                self.memory[host_id] = secret
            else:
                self.memory.pop(host_id, None)
        else:
            store.save_claude_token(host_id, secret)


class ApprovalDialog(QDialog):
    """"Claude asks to …" — Allow, Allow this kind for 1 hour, or Deny. No answer in two minutes is Deny.

    A request that needs a password (a new VM's user, a container's root, typing at a console prompt) asks the user
    for it here — always, even when its kind is On — and only the app ever holds it: Claude is told it was set."""

    decided = Signal(str)  # allow | allow-hour | deny | timeout | cancelled

    def __init__(self, client: str, host: Host, kind: str, what: str, details: list[str], reason: str,
                 timeout_s: int = ASK_TIMEOUT_S, secret_prompt: str = "", secret_repeat: bool = True,
                 secret_min: int = 1, picture: bytes | None = None, state: str = ASK):
        super().__init__(None, Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowTitle("Claude asks — Proxmox Controller")
        self.setModal(False)
        self.answer = ""
        self.left = timeout_s
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(label(f"{html.escape(client)} asks to:", "dim"))
        self.what = label(html.escape(what), "title", wrap=True)
        lay.addWidget(self.what)
        why = "this kind is set to Ask" if state == ASK else "a password is needed"
        lay.addWidget(label(f"on <b>{html.escape(host.name)}</b> · {claude_policy.TITLES.get(kind, kind)} ({why})",
                            "dim", wrap=True))
        if details:
            lay.addWidget(label("<br>".join("• " + html.escape(d) for d in details), wrap=True))
        if picture:
            shot = QLabel()
            pm = QPixmap()
            pm.loadFromData(picture)
            shot.setPixmap(pm.scaledToWidth(min(pm.width(), 480), Qt.TransformationMode.SmoothTransformation))
            shot.setToolTip("The guest's screen now")
            shot.setStyleSheet(f"border: 1px solid {theme.colors().border};")
            lay.addWidget(shot, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(label(f"<i>Reason given: {html.escape(reason) or '—'}</i>", wrap=True))
        self.secret_min = secret_min
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.again = QLineEdit()
        self.again.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_note = label("", "caption", wrap=True)
        self.needs_secret = bool(secret_prompt)
        if self.needs_secret:
            form = QFormLayout()
            form.addRow(label(f"<b>{html.escape(secret_prompt)}</b>", wrap=True))
            form.addRow("Password", self.password)
            if secret_repeat:
                form.addRow("Repeat it", self.again)
            lay.addLayout(form)
            lay.addWidget(self.secret_note)
            self.again.setVisible(secret_repeat)
            for f in (self.password, self.again):
                f.textChanged.connect(lambda *_: self._check_secret())
        self.countdown = label("", "caption")
        lay.addWidget(self.countdown)
        row = QHBoxLayout()
        self.deny_btn = button("Deny")
        self.hour_btn = button("Allow This Kind for 1 Hour", "", f"Further {claude_policy.TITLES.get(kind, kind)} "
                               f"requests on {host.name} are allowed without asking for the next hour (while the app "
                               "runs).")
        self.allow_btn = button("Allow", "destructive" if kind in ("destroy", "host", "host_commands") else "suggested")
        self.deny_btn.clicked.connect(lambda: self.finish("deny"))
        self.hour_btn.clicked.connect(lambda: self.finish("allow-hour"))
        self.allow_btn.clicked.connect(lambda: self.finish("allow"))
        row.addWidget(self.deny_btn)
        row.addStretch(1)
        row.addWidget(self.hour_btn)
        row.addWidget(self.allow_btn)
        lay.addLayout(row)
        for b in (self.deny_btn, self.hour_btn, self.allow_btn):
            b.setAutoDefault(False)  # Enter must not answer by accident
        self.repeat = secret_repeat
        if self.needs_secret:
            self.hour_btn.hide()  # a password is given each time
            self._check_secret()
            self.password.setFocus()
        else:
            self.deny_btn.setFocus()
        if kind in claude_policy.NOT_HOUR:
            self.hour_btn.hide()  # each command on the host is seen before it runs
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)
        self._tick(first=True)
        self.setMinimumWidth(520)

    def _check_secret(self) -> None:
        text = self.password.text()
        problem = ""
        if len(text) < self.secret_min:
            problem = f"Proxmox needs at least {self.secret_min} characters here." if self.secret_min > 1 else ""
        elif self.repeat and text != self.again.text():
            problem = "The two passwords are not the same." if self.again.text() else ""
        self.secret_note.setText(problem)
        self.allow_btn.setEnabled(bool(text) and len(text) >= self.secret_min and
                                  (not self.repeat or text == self.again.text()))

    def secret_value(self) -> str:
        return self.password.text() if self.needs_secret else ""

    def forget_secret(self) -> None:
        self.password.clear()
        self.again.clear()

    def _tick(self, first: bool = False) -> None:
        if not first:
            self.left -= 1
        if self.left <= 0:
            self.finish("timeout")
            return
        self.countdown.setText(f"No answer in {self.left // 60}:{self.left % 60:02d} counts as Deny.")

    def finish(self, answer: str) -> None:
        if self.answer:
            return
        self.answer = answer
        self.timer.stop()
        self.decided.emit(answer)
        # QDialog.done hides it. (Not close(): QDialog's close calls reject(), which here means Deny — and with the
        # answer already given it did nothing and kept the window open.)
        QDialog.done(self, QDialog.DialogCode.Accepted if answer.startswith("allow") else QDialog.DialogCode.Rejected)

    def closeEvent(self, ev) -> None:  # the window's X: no
        self.finish("deny")
        ev.accept()

    def reject(self) -> None:  # Escape: no
        self.finish("deny")


_TRAY: dict = {}  # Windows: the icon a toast comes from, and the timer that takes it away again


def notify_windows(title: str, body: str) -> None:
    """Windows: a toast — it comes from an icon in the notification area, shown only while the toast is up."""
    from PySide6.QtWidgets import QSystemTrayIcon
    if not QSystemTrayIcon.isSystemTrayAvailable():
        return
    if not _TRAY:
        _TRAY["icon"] = QSystemTrayIcon(QApplication.windowIcon())
        _TRAY["icon"].setToolTip("Proxmox Controller")
        _TRAY["timer"] = QTimer()
        _TRAY["timer"].setSingleShot(True)
        _TRAY["timer"].timeout.connect(_TRAY["icon"].hide)
    _TRAY["icon"].show()
    _TRAY["icon"].showMessage(title, body, QSystemTrayIcon.MessageIcon.Information, 20000)
    _TRAY["timer"].start(25000)


def notify_desktop(title: str, body: str) -> None:
    """A desktop notification (GNOME's; on Windows a toast), so a request waiting for the user is seen even with the
    app behind other windows."""
    try:
        if sys.platform.startswith("win"):
            notify_windows(title, body)
            return
        from PySide6.QtDBus import QDBusConnection, QDBusInterface
        bus = QDBusConnection.sessionBus()
        if not bus.isConnected():
            return
        iface = QDBusInterface("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                               "org.freedesktop.Notifications", bus)
        if iface.isValid():
            iface.call("Notify", "Proxmox Controller", 0, "store.themechanic.ProxmoxController", title, body, [],
                       {"urgency": 2}, 20000)
    except Exception:
        pass  # a notification is a courtesy: the approval window is what counts


class Connector(QObject):
    to_gui = Signal(object)
    acted = Signal(str)       # host id: a request changed something there
    logged = Signal(dict)     # a log entry, for the Claude Access window
    asking = Signal(object)   # an approval window was opened (tests watch it)

    def __init__(self, win, make_client: Callable[[Host], Pve], tokens: Tokens, notify=notify_desktop):
        super().__init__()
        self.win, self.make_client, self.tokens, self.notify_desktop = win, make_client, tokens, notify
        self.allowances = Allowances()
        self.loans = claude_access.Loans()
        self.approvals: dict[str, ApprovalDialog] = {}
        self.server: LinkServer | None = None
        self.listening = False
        self.to_gui.connect(self._on_gui, Qt.ConnectionType.QueuedConnection)

    # -- the link ----------------------------------------------------------------------------------

    def start(self) -> bool:
        self.server = LinkServer(self.handle)
        self.listening = self.server.start()
        return self.listening

    def stop(self) -> None:
        if self.server is not None:
            self.server.stop()
        for dlg in list(self.approvals.values()):
            dlg.finish("cancelled")

    def on_gui(self, fn, timeout: float = 60):
        """Runs fn on the window's thread and returns what it returns (from a request's thread)."""
        fut: Future = Future()
        self.to_gui.emit((fn, fut))
        return fut.result(timeout)

    def _on_gui(self, item) -> None:
        fn, fut = item
        if fut.set_running_or_notify_cancel():
            try:
                fut.set_result(fn())
            except BaseException as e:  # handed back to the request's thread
                fut.set_exception(e)

    # -- one request (on its own thread) -----------------------------------------------------------

    def handle(self, msg: dict) -> dict:
        if "cancel" in msg:
            self.on_gui(lambda: self._cancel(str(msg["cancel"])))
            return {"result": ok_result({"cancelled": True})}
        key, name, client = str(msg.get("key", "")), str(msg.get("tool", "")), str(msg.get("client", "Claude"))
        args = msg.get("args") if isinstance(msg.get("args"), dict) else {}
        entry = {"client": client, "tool": name, "kind": "", "host": "", "what": "", "reason": args.get("reason", ""),
                 "args": {k: v for k, v in args.items() if k != "reason"}}
        try:
            tool = TOOLS.get(name)
            if tool is None:
                raise ToolError(f"There is no tool '{name}'.")
            check(tool, args)
            if name == "list_hosts":
                return self._done(entry, "allowed", ok_result(self.on_gui(self._hosts_info)))
            kind = tool.kind_of(args)
            entry["kind"] = kind
            info = self.on_gui(lambda: self._prepare(args.get("host", ""), kind))
            host = info["host"]
            entry["host"] = host.name
            ctx = Context(host=host, pve=self.make_client(info["claude"]), admin=self.make_client(host),
                          kinds=not_off(info["switches"]))  # (before the words: they say what will be done)
            if info["state"] == OFF:  # refused — but the log says what was tried, in words, when it can
                try:
                    entry["what"] = tool.words(ctx, args)[0] if tool.words else ""
                except Exception:
                    pass
                raise Refused(f"{claude_policy.TITLES[kind]} requests are Off for {host.name} in Proxmox Controller. "
                              "Tell the user instead of trying another way.")
            prompt = tool.secret_prompt(args)
            ctx.showing = info["state"] == ASK or bool(prompt)  # a window will show the request
            words = tool.words(ctx, args) if tool.words else (name.replace("_", " ").capitalize(), [])
            what, details = words[0], words[1]
            picture = words[2] if len(words) > 2 else None
            entry["what"] = what
            decision = "allowed"
            if info["state"] == ASK or prompt:  # a password is always asked of the user, whatever the switch
                repeat = tool.repeat_secret(args)
                fut = self.on_gui(lambda: self._ask(key, client, host, kind, what, details, args.get("reason", ""),
                                                    prompt, tool, picture, info["state"], repeat))
                answer, ctx.secret = fut.result(ASK_TIMEOUT_S + 30)
                if answer == "allow-hour":
                    self.on_gui(lambda: self.allowances.grant(host.id, kind))
                if answer not in ("allow", "allow-hour"):
                    raise Refused({"deny": "The user denied it.",
                                   "timeout": f"No answer from the user within {ASK_TIMEOUT_S // 60} minutes: not done.",
                                   "cancelled": "Cancelled before the user answered."}.get(answer, "Not allowed."),
                                  {"deny": "denied"}.get(answer, answer))
                decision = "approved"
            if kind != "read":
                self.on_gui(lambda: self._tell_user(f"Claude: {what}"))
            try:
                result = self._run(tool, ctx, args, host, kind, info["switches"])
            finally:
                ctx.secret = ""  # held only for the request
            if kind != "read":
                self.acted.emit(host.id)
            return self._done(entry, decision, ok_result(result))
        except Refused as e:
            return self._done(entry, e.decision, error_result(str(e)))
        except ToolError as e:
            return self._done(entry, "error", error_result(str(e)))
        except PveError as e:
            return self._done(entry, "error", error_result(refused_403(e) if e.status == 403 else str(e)))
        except TimeoutError as e:
            return self._done(entry, "error", error_result(str(e) or "Timed out."))
        except Exception as e:  # never leave Claude without an answer
            return self._done(entry, "error", error_result(f"Unexpected error: {type(e).__name__}: {e}"))

    def _run(self, tool, ctx: Context, args: dict, host: Host, kind: str, switches: dict):
        """Lends this kind's privileges for the length of the request (reading is standing when Read is On)."""
        ctx.kinds = not_off(switches)
        lend = [] if not tool_uses_api(tool) or (kind == "read" and switches.get("read") == ON) \
            else list(claude_policy.PRIVILEGES[kind])
        for other in tool.also_of(args):  # used in passing (a new guest's start), lent only if its switch is not Off
            if other in ctx.kinds:
                lend += [p for p in claude_policy.PRIVILEGES[other] if p not in lend]
        if not lend:
            return tool.run(ctx, args)
        current = lambda: self.on_gui(lambda: claude_policy.host_switches(self.win.settings, host.id))  # noqa: E731
        with self.loans.lend(host.id, ctx.admin, current, lend):
            return tool.run(ctx, args)

    def _done(self, entry: dict, decision: str, result: dict) -> dict:
        text = result["content"][-1].get("text", "") if result.get("isError") else "ok"
        entry = connector_log.add({**entry, "decision": decision, "outcome": text[:300]})
        self.logged.emit(entry)
        return {"result": result}

    # -- on the window's thread --------------------------------------------------------------------

    def _hosts_info(self) -> dict:
        if not claude_policy.enabled(self.win.settings):
            raise Refused("Claude's access is turned off in Proxmox Controller (Claude Access → the switch at the "
                          "top). Ask the user to turn it on.")
        out = []
        for h in self.win.hosts:
            ready = bool(self.tokens.get(h.id))
            out.append({"host": h.id, "name": h.name, "address": h.address,
                        "online": {"online": True, "offline": False}.get(self.win.state.get(h.id, "")),
                        "claude_access_set_up": ready,
                        "allowed": claude_policy.host_switches(self.win.settings, h.id) if ready else None})
        return {"hosts": out, "note": "off: refused · ask: the user approves each request · on: done at once. A host "
                                      "whose Claude access is not set up cannot be used (the user sets it up in "
                                      "Proxmox Controller → Claude Access)."}

    def _prepare(self, host_id: str, kind: str) -> dict:
        if not claude_policy.enabled(self.win.settings):
            raise Refused("Claude's access is turned off in Proxmox Controller (Claude Access → the switch at the "
                          "top).")
        host = next((h for h in self.win.hosts if h.id == host_id), None)
        if host is None:
            raise ToolError(f"There is no host '{host_id}'. list_hosts gives the hosts' ids.")
        secret = self.tokens.get(host.id)
        if not secret:
            raise Refused(f"Claude's access is not set up on {host.name} (Proxmox Controller → Claude Access → Set "
                          "Up).", "not-set-up")
        state = claude_policy.decide(self.win.settings, host.id, kind, self.allowances)
        claude = Host(id=host.id, name=host.name, address=host.address, token_id=claude_access.TOKEN_ID,
                      token_secret=secret, fingerprint=host.fingerprint, mac=host.mac, broadcast=host.broadcast)
        return {"state": state, "host": host, "claude": claude,
                "switches": claude_policy.host_switches(self.win.settings, host.id)}

    def _ask(self, key: str, client: str, host: Host, kind: str, what: str, details: list[str], reason: str,
             prompt: str = "", tool=None, picture: bytes | None = None, state: str = ASK,
             repeat: bool = True) -> Future:
        """The approval window; the future gets (answer, the password typed — or "")."""
        fut: Future = Future()
        dlg = ApprovalDialog(client, host, kind, what, details, reason, secret_prompt=prompt,
                             secret_repeat=repeat, secret_min=getattr(tool, "secret_min", 1),
                             picture=picture, state=state)
        self.approvals[key] = dlg

        def decided(answer: str) -> None:
            self.approvals.pop(key, None)
            secret = dlg.secret_value() if answer.startswith("allow") else ""
            dlg.forget_secret()
            if not fut.done():
                fut.set_result((answer, secret))

        dlg.decided.connect(decided)
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()
        QApplication.alert(dlg)
        self.notify_desktop("Claude asks", f"{what} — on {host.name}")
        self.asking.emit(dlg)
        return fut

    def _cancel(self, key: str) -> None:
        dlg = self.approvals.pop(key, None)
        if dlg is not None:
            dlg.finish("cancelled")

    def _tell_user(self, text: str) -> None:
        notify = getattr(self.win, "notify", None)
        if notify is not None:
            notify(text)


def tool_uses_api(tool) -> bool:
    """Wake-on-LAN is sent from this computer (and the host may be off); a host command — and a container's new root
    password, set through one — goes over SSH: no Proxmox privilege to lend for any of them."""
    return tool.name not in ("wake_host", "host_command", "set_container_root_password")
