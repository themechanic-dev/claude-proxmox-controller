"""Settings: the Proxmox hosts the app knows (add, edit, remove) and how often it reads them."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame, QHBoxLayout,
                               QListWidget, QListWidgetItem, QScrollArea, QVBoxLayout, QWidget)

from .. import APP_NAME, VERSION
from ..core import autostart, store
from .widgets import button, label

if TYPE_CHECKING:
    from .main_window import MainWindow


class SettingsDialog(QDialog):
    def __init__(self, win: "MainWindow"):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Settings")
        self.setModal(True)
        outer = QVBoxLayout(self)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(12)

        lay.addWidget(label("Proxmox hosts", "heading"))
        self.list = QListWidget()
        self.list.setMinimumHeight(150)
        self.list.setIconSize(QSize(16, 16))  # the same small status dots as in the table and the ☰ menu
        self.list.itemSelectionChanged.connect(self._sel)
        self.list.itemDoubleClicked.connect(lambda *_: self.edit())
        lay.addWidget(self.list)
        add = button("Add Host…", "suggested")
        add.clicked.connect(self.add)
        self.edit_btn = button("Edit…")
        self.edit_btn.clicked.connect(self.edit)
        self.remove_btn = button("Remove…")
        self.remove_btn.clicked.connect(self.remove)
        row = QHBoxLayout()
        row.setSpacing(8)
        for b in (add, self.edit_btn, self.remove_btn):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addWidget(label("The window shows one host at a time. With more than one, switch between them from the "
                            "☰ menu or with Ctrl+1 … Ctrl+9.", "caption", wrap=True))

        lay.addWidget(label("Refresh", "heading"))
        form = QFormLayout()
        self.refresh = QComboBox()
        for s in store.REFRESH_CHOICES:
            self.refresh.addItem(f"{s} seconds", s)
        self.refresh.setCurrentIndex(store.REFRESH_CHOICES.index(win.settings["refresh_seconds"]))
        self.refresh.currentIndexChanged.connect(lambda *_: win.set_refresh(self.refresh.currentData()))
        form.addRow("Read the host every", self.refresh)
        lay.addLayout(form)

        lay.addWidget(label("Console", "heading"))
        cform = QFormLayout()
        self.console = QComboBox()
        for key, text in (("auto", "Automatic: SPICE if the VM has it"),
                          ("spice", "SPICE — sound, clipboard, USB"),
                          ("vnc", "Built-in console"), ("browser", "In the browser")):
            self.console.addItem(text, key)
        self.console.setCurrentIndex(max(0, self.console.findData(win.settings.get("console", "auto"))))
        self.console.currentIndexChanged.connect(lambda *_: win.set_console(self.console.currentData()))
        cform.addRow("Console opens", self.console)
        lay.addLayout(cform)
        lay.addWidget(label("Automatic opens SPICE (remote-viewer) for VMs that have a SPICE display and the "
                            "built-in console for everything else. The arrow next to the Console button always "
                            "offers every kind.", "caption", wrap=True))

        lay.addWidget(label("Windows and startup", "heading"))
        self.place = QCheckBox("Reopen windows where they were (size and screen)")
        self.place.setChecked(bool(win.settings.get("remember_place", True)))
        self.place.toggled.connect(win.set_remember_place)
        lay.addWidget(self.place)
        self.place_note = label("GNOME does not let apps place their own windows, so for this the app runs through "
                                "XWayland. Takes effect the next time the app starts.", "caption", wrap=True)
        if sys.platform.startswith("linux"):  # (Windows lets an app place its windows: nothing to explain)
            lay.addWidget(self.place_note)
        self.login = QCheckBox("Start with the computer")
        self.login.setChecked(autostart.is_enabled())
        self.login.toggled.connect(autostart.set_enabled)
        self.login_note = label("Opens the app when you log in, so after a restart or a power cut it comes back by "
                                "itself.", "caption", wrap=True)
        if autostart.supported():
            lay.addWidget(self.login)
            lay.addWidget(self.login_note)

        self.lock_state = label("", "dim", wrap=True)
        self.lock_btn = button("Lock with a Password…")
        self.lock_btn.clicked.connect(lambda: self.password("set"))
        self.change_btn = button("Change Password…")
        self.change_btn.clicked.connect(lambda: self.password("change"))
        self.unlock_btn = button("Remove Password…")
        self.unlock_btn.clicked.connect(lambda: self.password("remove"))
        if not win.demo:  # the pretend hosts have nothing to lock
            lay.addWidget(label("Security", "heading"))
            lay.addWidget(self.lock_state)
            lock_row = QHBoxLayout()
            lock_row.setSpacing(8)
            for b in (self.lock_btn, self.change_btn, self.unlock_btn):
                lock_row.addWidget(b)
            lock_row.addStretch(1)
            lay.addLayout(lock_row)
        self._show_lock()

        lay.addSpacing(6)
        line = QFrame()
        line.setObjectName("signatureRule")
        line.setFixedHeight(1)
        lay.addWidget(line)
        for text, name in (("HOME LAB", "signatureMark"), ("by the mechanic", "signatureLine"),
                           (f"{APP_NAME} {VERSION}", "caption")):
            lay.addWidget(label(text, name), 0, Qt.AlignmentFlag.AlignHCenter)
        scroll = QScrollArea()  # taller than a 1080p screen leaves room for: it scrolls there
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)
        self.fill(win.current_id)
        self.setMinimumWidth(520)
        body.setMinimumWidth(480)
        need = body.heightForWidth(480) if lay.hasHeightForWidth() else body.sizeHint().height()
        screen = QGuiApplication.primaryScreen()
        room = screen.availableGeometry().height() - 60 if screen is not None else 900
        self.resize(540, max(420, min(need + buttons.sizeHint().height() + 40, room)))

    def _show_lock(self) -> None:
        locked = store.secrets_state() == "locked"
        self.lock_state.setText("The API tokens are locked with your password." if locked else
                                "The API tokens are kept unlocked: programs running as you — Claude included — "
                                "could read them.")
        self.lock_btn.setVisible(not locked)
        self.change_btn.setVisible(locked)
        self.unlock_btn.setVisible(locked)

    def password(self, mode: str) -> None:
        from .vault_dialogs import PasswordDialog
        PasswordDialog(self, mode).exec()
        self._show_lock()

    def fill(self, select: str = "") -> None:
        self.list.clear()
        for h in self.win.hosts:
            item = QListWidgetItem(self.win.icon_for(h.id), f"{h.name}    —    {h.address}")
            item.setData(Qt.ItemDataRole.UserRole, h.id)
            self.list.addItem(item)
            if h.id == select:
                self.list.setCurrentItem(item)
        self._sel()

    def _sel(self) -> None:
        has = self.selected() is not None
        self.edit_btn.setEnabled(has)
        self.remove_btn.setEnabled(has)

    def selected(self):
        items = self.list.selectedItems()
        hid = items[0].data(Qt.ItemDataRole.UserRole) if items else None
        return next((h for h in self.win.hosts if h.id == hid), None)

    def add(self) -> None:
        host = self.win.add_host(self)
        if host is not None:
            self.fill(host.id)

    def edit(self) -> None:
        host = self.selected()
        if host is not None:
            new = self.win.edit_host(host, self)
            self.fill((new or host).id)

    def remove(self) -> None:
        host = self.selected()
        if host is not None and self.win.remove_host(host, self):
            self.fill(self.win.current_id)
