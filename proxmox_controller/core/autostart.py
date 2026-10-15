"""Start with the computer: one entry in ~/.config/autostart that opens the app when the user logs in (Linux).
The entry itself is the setting — removed in GNOME's own Startup Applications, the switch in Settings shows it off."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .. import APP_ID, APP_NAME

ROOT = Path(__file__).resolve().parents[2]
DELAY_S = 10  # after the desktop appears: the network is up by then, and the first read of the host answers


def supported() -> bool:
    return sys.platform.startswith("linux")  # Windows: with the Windows version


def entry_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "autostart" / f"{APP_ID}.desktop"


def is_enabled() -> bool:
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
