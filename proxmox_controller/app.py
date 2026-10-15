"""Starting the app.

    proxmox-controller            the app
    proxmox-controller --demo     two pretend hosts; nothing touches the network or the real settings
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import QApplication

from . import APP_ID, APP_NAME, VERSION
from .core import store
from .core.demo import DEMO_HOSTS, DemoPve
from .core.pve import Pve
from .ui import theme
from .ui.main_window import MainWindow

ROOT = Path(__file__).resolve().parents[1]
ICON = ROOT / "data" / "icons" / f"{APP_ID}.svg"


def choose_platform(settings: dict, env=os.environ, platform: str = sys.platform) -> str | None:
    """On GNOME's Wayland an app is not allowed to place its own windows, so "reopen where it was" needs XWayland
    (measured on GNOME 50: same dark theme, same four screens). Nothing is changed when the user set QT_QPA_PLATFORM
    or turned the option off."""
    if (platform.startswith("linux") and settings.get("remember_place", True)
            and env.get("XDG_SESSION_TYPE") == "wayland" and env.get("DISPLAY") and "QT_QPA_PLATFORM" not in env):
        return "xcb"
    return None


def escape_startup_id(env=os.environ) -> None:
    """The desktop shows a busy pointer from a launch until the app says it has started. GNOME names the launch after
    the app — "gnome-shell/Proxmox Controller/3110-18-…", with a space — and Qt's X11 side hands it back unescaped,
    so the desktop reads "gnome-shell/Proxmox", never hears of the start and keeps the busy pointer until it gives up
    (about 10 s; measured with libstartup-notification, which mutter uses). Escaped with backslashes, as that library
    writes it itself, it matches. Only for X11/XWayland: on Wayland Qt answers with XDG_ACTIVATION_TOKEN instead."""
    sid = env.get("DESKTOP_STARTUP_ID", "")
    qpa = env.get("QT_QPA_PLATFORM", "")
    x11 = qpa.split(";")[0].startswith("xcb") if qpa else (env.get("XDG_SESSION_TYPE") != "wayland"
                                                           and bool(env.get("DISPLAY")))
    if sid and x11:
        env["DESKTOP_STARTUP_ID"] = "".join("\\" + ch if ch in ' "\\' else ch for ch in sid)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    demo = "--demo" in argv
    chosen = choose_platform(store.load_settings())
    if chosen:
        os.environ["QT_QPA_PLATFORM"] = chosen
    if sys.platform.startswith("linux"):
        escape_startup_id()  # before Qt reads it
    app = QApplication([a for a in argv if a != "--demo"])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setDesktopFileName(APP_ID)  # lets GNOME (Wayland) match the window to its launcher and icon
    if ICON.exists():
        app.setWindowIcon(QIcon(str(ICON)))
    theme.apply(app)
    QGuiApplication.styleHints().colorSchemeChanged.connect(lambda *_: theme.apply(app))
    if not demo and store.secrets_state() == "locked":
        from .ui.vault_dialogs import UnlockDialog
        if UnlockDialog().exec() != UnlockDialog.DialogCode.Accepted:
            return 0  # without the password the hosts cannot be reached
    if demo:
        window = MainWindow([h for h in DEMO_HOSTS], DemoPve, demo=True)
    else:
        window = MainWindow(store.load_hosts(), Pve)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
