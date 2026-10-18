"""Start with the computer: one entry that opens the app when the user logs in — on Linux a file in
~/.config/autostart, on Windows a value under HKEY_CURRENT_USER\\…\\CurrentVersion\\Run (what Settings → Apps → Startup
lists). The entry itself is the setting: removed or turned off in GNOME's Startup Applications or in Windows' own list,
the switch in Settings shows it off."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .. import APP_ID, APP_NAME

ROOT = Path(__file__).resolve().parents[2]
DELAY_S = 10  # after the desktop appears: the network is up by then, and the first read of the host answers
WINDOWS = sys.platform.startswith("win")
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"  # Windows' own switch
VALUE = APP_NAME
registry = None  # winreg, or the tests' pretend registry


def supported() -> bool:
    return sys.platform.startswith("linux") or WINDOWS


def _reg():
    if registry is not None:
        return registry
    import winreg
    return winreg


def windows_command() -> str:
    """What the Run value starts: the installed app, or (from the source tree) its windowless Python with the
    launcher."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    python = Path(sys.executable)
    windowless = python.with_name("pythonw.exe")
    return f'"{windowless if windowless.exists() else python}" -I "{ROOT / "bin" / "launch.py"}"'


def _windows_enabled() -> bool:
    reg = _reg()
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, RUN_KEY) as key:
            reg.QueryValueEx(key, VALUE)
    except OSError:
        return False
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, APPROVED_KEY) as key:
            approved, _ = reg.QueryValueEx(key, VALUE)
    except OSError:
        return True  # never switched in Windows' list: on
    return not (isinstance(approved, bytes) and approved[:1] and approved[0] & 1)  # 03… = turned off there


def _windows_set(enabled: bool) -> None:
    reg = _reg()
    if enabled:
        with reg.CreateKey(reg.HKEY_CURRENT_USER, RUN_KEY) as key:
            reg.SetValueEx(key, VALUE, 0, reg.REG_SZ, windows_command())
    else:
        try:
            with reg.OpenKey(reg.HKEY_CURRENT_USER, RUN_KEY, 0, reg.KEY_SET_VALUE) as key:
                reg.DeleteValue(key, VALUE)
        except OSError:
            pass
    try:  # Windows' own on/off for it goes too: turned on here means on there
        with reg.OpenKey(reg.HKEY_CURRENT_USER, APPROVED_KEY, 0, reg.KEY_SET_VALUE) as key:
            reg.DeleteValue(key, VALUE)
    except OSError:
        pass


def entry_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "autostart" / f"{APP_ID}.desktop"


def is_enabled() -> bool:
    if WINDOWS:
        return _windows_enabled()
    try:
        text = entry_path().read_text(encoding="utf-8")
    except OSError:
        return False
    return not any(line.strip().lower() in ("hidden=true", "x-gnome-autostart-enabled=false")
                   for line in text.splitlines())


def entry_text() -> str:
    return ("[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={APP_NAME}\n"
            "Comment=Containers, virtual machines and Wake-on-LAN for your Proxmox VE hosts\n"
            f'Exec="{ROOT}/bin/proxmox-controller"\n'
            f"Icon={APP_ID}\n"
            "Terminal=false\n"
            "X-GNOME-Autostart-enabled=true\n"
            f"X-GNOME-Autostart-Delay={DELAY_S}\n")


def set_enabled(enabled: bool) -> None:
    if WINDOWS:
        _windows_set(enabled)
        return
    path = entry_path()
    if not enabled:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(entry_text(), encoding="utf-8")
    os.replace(tmp, path)
