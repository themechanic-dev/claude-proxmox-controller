"""The main window: one Proxmox host at a time, filling the window. The hosts themselves live in Settings;
with more than one, the ☰ menu (top right) switches between them."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QPointF, Qt, QTimer
from PySide6.QtGui import QAction, QFont, QIcon, QKeySequence, QPainter, QPalette, QPen
from PySide6.QtWidgets import QDialog, QHBoxLayout, QMainWindow, QMenu, QStackedWidget, QToolButton, QVBoxLayout, QWidget

from .. import APP_NAME
from ..core import store
from ..core.pve import Host, Pve
from . import geometry, theme
from .help import HelpDialog
from .host_dialog import HostDialog
from .host_view import HostView
from .settings import SettingsDialog
from .widgets import button, card, confirm, dot_icon, label
from .worker import Runner

PING_EVERY_MS = 30_000
MAX_HOST_KEYS = 9  # Ctrl+1 … Ctrl+9


class MenuButton(QToolButton):
    """The ☰ button. The three lines are drawn in the theme's text colour, so they follow light and dark."""

    def __init__(self, menu: QMenu):
        super().__init__()
        self.setObjectName("menuButton")
        self.setMenu(menu)
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.setFixedSize(36, 32)
        self.setToolTip("Hosts, settings and help")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def paintEvent(self, ev) -> None:
        super().paintEvent(ev)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self.palette().color(QPalette.ColorRole.ButtonText), 2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        cx, cy = self.width() / 2, self.height() / 2
        for dy in (-5, 0, 5):
            p.drawLine(QPointF(cx - 7, cy + dy), QPointF(cx + 7, cy + dy))
        p.end()


class MainWindow(QMainWindow):
    def __init__(self, hosts: list[Host], make_client: Callable[[Host], Pve], demo: bool = False):
        super().__init__()
        self.resize(1060, 760)  # one host, its cards, guests with long names; reopened as it was left after that
        self.demo = demo
        self.hosts = hosts
        self.make_client = make_client
        self.settings = store.load_settings() if not demo else dict(store.SETTINGS_DEFAULTS)
        self.runner = Runner()
        self.views: dict[str, HostView] = {}
        self.state: dict[str, str] = {}
        self.tidied: set[str] = set()   # hosts whose Claude role was put back to rest since the app started
        self.tidying: set[str] = set()
        self.current_id = ""
        self.help_dialog: HelpDialog | None = None
        self.claude_window = None
        from .connector import Connector, Tokens
        self.connector = Connector(self, make_client, Tokens(demo=demo))
        self.connector.acted.connect(self._claude_acted)

        self.pages = QStackedWidget()
        self.setCentralWidget(self.pages)

        self.menu = QMenu(self)
        self.menu.aboutToShow.connect(self._fill_menu)
        self.actions_: dict[str, QAction] = {}
        for key, text, shortcut, slot in (("settings", "Hosts and Settings…", "Ctrl+,", self.show_settings),
                                          ("claude", "Claude Access…", "Ctrl+Shift+C", self.show_claude),
                                          ("help", "Help", "F1", self.show_help),
                                          ("refresh", "Refresh", "F5", self.refresh),
                                          ("quit", "Quit", "Ctrl+Q", self.close)):
            a = QAction(text, self)
            a.setShortcut(QKeySequence(shortcut))
            a.triggered.connect(slot)
            self.addAction(a)  # the shortcut works even while the menu is closed
            self.actions_[key] = a
        for i in range(MAX_HOST_KEYS):
            a = QAction(self)
            a.setShortcut(QKeySequence(f"Ctrl+{i + 1}"))
            a.triggered.connect(lambda _=False, i=i: self.show_host_index(i))
            self.addAction(a)

        self.empty = self._empty_page()
        self.pages.addWidget(self.empty)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.ping_timer = QTimer(self)
        self.ping_timer.timeout.connect(self.ping_all)
        self.ping_timer.start(PING_EVERY_MS)
        self._restart_timer()
        self.show_host(self.settings.get("selected_host", ""))
        geometry.restore(self, "main", self.settings)  # the size and screen it was closed on
        QTimer.singleShot(200, self.ping_all)
        if not demo:
            self.connector.start()
            QTimer.singleShot(1500, self._claude_tidy)

    # -- pages -------------------------------------------------------------------------------------

    def _empty_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(24, 20, 24, 24)
        top = QHBoxLayout()
        top.addStretch(1)
        top.addWidget(MenuButton(self.menu))
        lay.addLayout(top)
        lay.addStretch(1)
        box = card(label("No Proxmox hosts yet", "title"),
                   label("Add your first host: you need its address and an API token. Help explains how to make "
                         "the token in the Proxmox web interface.", "dim", wrap=True))
        add = button("Add Host…", "suggested")
        add.clicked.connect(lambda: self.add_host())
        box.layout().addWidget(add, 0, Qt.AlignmentFlag.AlignLeft)
        box.setMaximumWidth(560)
        lay.addWidget(box, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addStretch(2)
        return w

    def _fill_menu(self) -> None:
        """Built each time it opens, so host names and their dots are current."""
        self.menu.clear()
        if len(self.hosts) > 1:
            for i, h in enumerate(self.hosts):
                keys = f"\tCtrl+{i + 1}" if i < MAX_HOST_KEYS else ""  # text after a tab shows as the shortcut
                a = self.menu.addAction(self.icon_for(h.id), h.name + keys)
                if h.id == self.current_id:
                    f = QFont(a.font())
                    f.setBold(True)
                    a.setFont(f)
                a.triggered.connect(lambda _=False, hid=h.id: self.show_host(hid))
            self.menu.addSeparator()
        self.menu.addAction(self.actions_["settings"])
        self.menu.addAction(self.actions_["claude"])
        self.menu.addAction(self.actions_["help"])
        self.menu.addSeparator()
        self.menu.addAction(self.actions_["quit"])

    # -- hosts -------------------------------------------------------------------------------------

    def icon_for(self, host_id: str) -> QIcon:
        c = theme.colors()
        return dot_icon({"online": c.success, "offline": c.dim, "error": c.danger}.get(self.state.get(host_id), c.warning))

    def show_host(self, host_id: str = "") -> None:
        ids = [h.id for h in self.hosts]
        suffix = " (demo)" if self.demo else ""
        if not ids:
            self.current_id = ""
            self.pages.setCurrentWidget(self.empty)
            self.setWindowTitle(APP_NAME + suffix)
            return
        h = self.hosts[ids.index(host_id) if host_id in ids else 0]
        view = self.views.get(h.id)
        if view is None:
            view = HostView(h, self.make_client, self.runner, self.notify, self.edit_host, self._set_state,
                            corner=MenuButton(self.menu), prefs=self.settings, on_prefs_changed=self._save_settings,
                            on_host_changed=self._save_hosts)
            self.views[h.id] = view
            self.pages.addWidget(view)
        if h.id != self.current_id:
            view.refresh()
        self.pages.setCurrentWidget(view)
        self.current_id = h.id
        self.setWindowTitle(f"{h.name} — {APP_NAME}{suffix}")
        if self.settings.get("selected_host") != h.id:
            self.settings["selected_host"] = h.id
            self._save_settings()

    def show_host_index(self, i: int) -> None:
        if 0 <= i < len(self.hosts):
            self.show_host(self.hosts[i].id)

    def current_view(self) -> HostView | None:
        w = self.pages.currentWidget()
        return w if isinstance(w, HostView) else None

    def refresh(self) -> None:
        view = self.current_view()
        if view is not None:
            view.refresh()

    def ping_all(self) -> None:
        """Keeps the dots in the ☰ menu current. The shown host reports its own state when it loads."""
        for h in self.hosts:
            if h.id == self.current_id:
                continue
            pve = self.make_client(h)
            self.runner.run(lambda pve=pve: pve.version(),
                            lambda _r, err, hid=h.id: self._set_state(hid, "offline" if err else "online"))

    def _set_state(self, host_id: str, state: str) -> None:
        if state:
            self.state[host_id] = state
            if state == "online":
                self._claude_tidy_host(host_id)

    def add_host(self, parent: QWidget | None = None) -> Host | None:
        dlg = HostDialog(parent or self, self.runner, self.make_client)
        if dlg.exec() != QDialog.DialogCode.Accepted or not dlg.result_host:
            return None
        self.hosts.append(dlg.result_host)
        self._save_hosts()
        self.show_host(dlg.result_host.id)
        self.notify(f"Added {dlg.result_host.name}")
        return dlg.result_host

    def edit_host(self, host: Host, parent: QWidget | None = None) -> Host | None:
        dlg = HostDialog(parent or self, self.runner, self.make_client, host)
        if dlg.exec() != QDialog.DialogCode.Accepted or not dlg.result_host:
            return None
        new = dlg.result_host
        self.hosts = [new if h.id == host.id else h for h in self.hosts]
        self._save_hosts()
        if host.id in self.views:
            self.views[host.id].set_host(new)
        if self.current_id == new.id:
            self.setWindowTitle(f"{new.name} — {APP_NAME}{' (demo)' if self.demo else ''}")
        self.notify(f"Saved {new.name}")
        return new

    def remove_host(self, host: Host, parent: QWidget | None = None) -> bool:
        if not confirm(parent or self, "Remove this host from the app?",
                       f"{host.name} ({host.address}) disappears from the app and its token is forgotten here. "
                       "Nothing changes on the host itself.", "Remove", destructive=True):
            return False
        self.hosts = [h for h in self.hosts if h.id != host.id]
        self.state.pop(host.id, None)
        view = self.views.pop(host.id, None)
        if view is not None:
            self.pages.removeWidget(view)
            view.deleteLater()
        self._save_hosts()
        self.show_host(self.current_id)
        return True

    def _save_hosts(self) -> None:
        if not self.demo:
            store.save_hosts(self.hosts)

    def remember_setup_disc(self, disc: dict) -> None:
        """A new VM's setup disc, made through the connector: kept until its host's page takes it away."""
        self.settings.setdefault("setup_discs", []).append(disc)
        self._save_settings()

    def _save_settings(self) -> None:
        if not self.demo:
            store.save_settings(self.settings)

    # -- misc --------------------------------------------------------------------------------------

    def notify(self, text: str) -> None:
        self.statusBar().showMessage(text, 6000)

    def show_help(self) -> None:
        if self.help_dialog is None:
            self.help_dialog = HelpDialog(self)
        self.help_dialog.show()
        self.help_dialog.raise_()
        self.help_dialog.activateWindow()

    def show_settings(self) -> None:
        SettingsDialog(self).exec()

    def show_claude(self) -> None:
        if self.claude_window is None:
            from .claude_window import ClaudeWindow
            self.claude_window = ClaudeWindow(self, self.connector, self.runner)
        else:
            self.claude_window.fill_hosts()
            self.claude_window.refresh()
        self.claude_window.show()
        self.claude_window.raise_()
        self.claude_window.activateWindow()

    def _claude_acted(self, host_id: str) -> None:
        """Claude changed something on a host: its page shows it at once."""
        view = self.views.get(host_id)
        if view is not None:
            view.details_at = 0.0
            view.refresh()

    def _claude_tidy(self) -> None:
        """Claude's role back to what the switches say at rest, on every host where it is set up: privileges lent
        to a request are not left behind if the app ended in the middle of one (a power cut), and what reading needs
        follows this version of the app."""
        for h in self.hosts:
            self._claude_tidy_host(h.id)

    def _claude_tidy_host(self, host_id: str) -> None:
        """Once a run of the app, per host — tried at the start and again each time the host is seen online until it
        worked: the computer is often up before the server, and a host still starting refuses it (measured 14/10:
        the app at 21:27:37, the host a minute later — the role stayed as it was, and nothing said so)."""
        from ..core import claude_policy
        h = next((h for h in self.hosts if h.id == host_id), None)
        if (self.demo or h is None or host_id in self.tidied or host_id in self.tidying
                or not self.connector.tokens.get(host_id)):
            return
        self.tidying.add(host_id)
        admin, switches, loans = self.make_client(h), claude_policy.host_switches(self.settings, host_id), \
            self.connector.loans

        def done(_r, err) -> None:
            self.tidying.discard(host_id)
            if err is None:
                self.tidied.add(host_id)

        self.runner.run(lambda: loans.tidy(host_id, admin, switches), done)

    def set_remember_place(self, on: bool) -> None:
        self.settings["remember_place"] = bool(on)
        self._save_settings()

    def set_console(self, how: str) -> None:
        self.settings["console"] = how
        self._save_settings()

    def set_refresh(self, seconds: int) -> None:
        self.settings["refresh_seconds"] = seconds
        self._save_settings()
        self._restart_timer()

    def _restart_timer(self) -> None:
        self.timer.start(int(self.settings["refresh_seconds"]) * 1000)

    def closeEvent(self, ev) -> None:
        geometry.remember(self, "main", self.settings, self._save_settings)
        self.timer.stop()
        self.ping_timer.stop()
        self.runner.close()
        self.connector.stop()
        if self.help_dialog is not None:
            self.help_dialog.close()
        if self.claude_window is not None:
            self.claude_window.close()
        from . import console, graph_wall, guest_dialogs
        console.close_all()
        guest_dialogs.close_all_graphs()
        graph_wall.close_all()
        super().closeEvent(ev)
