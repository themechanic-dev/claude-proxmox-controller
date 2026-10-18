"""Running this computer's own programs (ssh, arp, claude) from the app."""

from __future__ import annotations

import subprocess
import sys

WINDOWS = sys.platform.startswith("win")


def hidden() -> dict:
    """What keeps a console program's window from flashing up on Windows: started from an app that has windows only,
    it would get a console window of its own. (Nothing elsewhere.)"""
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if WINDOWS else {}
