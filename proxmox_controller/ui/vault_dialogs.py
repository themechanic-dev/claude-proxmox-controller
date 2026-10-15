"""The password that locks the API tokens: unlocking when the app starts, setting, changing and removing it."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout, QLineEdit, QVBoxLayout, QWidget

from ..core import store, vault
from .widgets import confirm, fit_to_width, label

NO_RECOVERY = ("There is no way to recover a forgotten password: the tokens would be entered again (each host's "
               "Edit…) and Claude's access set up again.")


def _password_field(placeholder: str = "") -> QLineEdit:
    f = QLineEdit()
    f.setEchoMode(QLineEdit.EchoMode.Password)
    f.setPlaceholderText(placeholder)
    return f


def _busy(fn):
    """The key takes about 0.4 s to work out: a busy pointer meanwhile."""
    QGuiApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    try:
        return fn()
    finally:
        QGuiApplication.restoreOverrideCursor()


class UnlockDialog(QDialog):
    """Shown when the app starts with locked tokens. Rejected: the app does not start."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Unlock Proxmox Controller")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(label("Unlock Proxmox Controller", "heading"))
        lay.addWidget(label("The API tokens of your hosts are locked with your password.", "dim", wrap=True))
        self.password = _password_field("Password")
        lay.addWidget(self.password)
        self.problem = label("", "caption")
        lay.addWidget(self.problem)
        buttons = QDialogButtonBox()
        self.forgot = buttons.addButton("Forgot Password…", QDialogButtonBox.ButtonRole.ResetRole)
        buttons.addButton("Quit", QDialogButtonBox.ButtonRole.RejectRole)
        self.go = buttons.addButton("Unlock", QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("kind", "suggested")
        self.go.setDefault(True)
        buttons.accepted.connect(self.try_unlock)
        buttons.rejected.connect(self.reject)
        self.forgot.clicked.connect(self.forget)
        lay.addWidget(buttons)
        fit_to_width(self, 420)

    def try_unlock(self) -> None:
        try:
            _busy(lambda: store.unlock(self.password.text()))
        except vault.WrongPassword:
            self.problem.setText("Wrong password.")
            self.password.clear()
            self.password.setFocus()
            return
        self.accept()

    def forget(self) -> None:
        if confirm(self, "Forget the API tokens?", "The hosts stay, without their tokens: give each one its token "
                   "again with Edit… on its page. Claude's access is set up again too.", "Forget Tokens",
                   destructive=True):
            store.forget_secrets()
            self.accept()


class PasswordDialog(QDialog):
    """Set a password (unlocked tokens), change it, or remove it."""

    def __init__(self, parent: QWidget | None, mode: str):
        super().__init__(parent)
        self.mode = mode  # "set" | "change" | "remove"
        titles = {"set": "Lock the API Tokens", "change": "Change the Password", "remove": "Remove the Password"}
        self.setWindowTitle(titles[mode])
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.addWidget(label(titles[mode], "heading"))
        texts = {"set": "Your hosts' API tokens (and Claude's) are kept locked with this password, typed each time "
                        "the app starts. Nothing else on this computer — Claude included — can then read them. "
                        + NO_RECOVERY,
                 "change": "A new password for the API tokens. " + NO_RECOVERY,
                 "remove": "The API tokens are kept unlocked again, readable by programs running as you."}
        lay.addWidget(label(texts[mode], "dim", wrap=True))
        form = QFormLayout()
        self.current = _password_field()
        self.new = _password_field()
        self.again = _password_field()
        if mode in ("change", "remove"):
            form.addRow("Current password", self.current)
        if mode in ("set", "change"):
            form.addRow("New password", self.new)
            form.addRow("Repeat it", self.again)
        lay.addLayout(form)
        self.problem = label("", "caption", wrap=True)
        lay.addWidget(self.problem)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.go = buttons.addButton({"set": "Lock", "change": "Change", "remove": "Remove Password"}[mode],
                                    QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("kind", "destructive" if mode == "remove" else "suggested")
        buttons.accepted.connect(self.apply)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        fit_to_width(self, 460)

    def apply(self) -> None:
        if self.mode in ("set", "change"):
            if not self.new.text():
                self.problem.setText("Type a password.")
                return
            if self.new.text() != self.again.text():
                self.problem.setText("The two passwords are not the same.")
                return
        try:
            if self.mode == "change":  # the current one first: a session left open is not enough to change it
                _busy(lambda: store.check_password(self.current.text()))
            if self.mode == "remove":
                _busy(lambda: store.remove_password(self.current.text()))
            else:
                _busy(lambda: store.set_password(self.new.text()))
        except vault.WrongPassword:
            self.problem.setText("The current password is wrong.")
            self.current.clear()
            return
        self.accept()
