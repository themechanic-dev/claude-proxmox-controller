"""Opening a VM's SPICE console in remote-viewer (virt-viewer), the viewer Proxmox itself hands out .vv files for.
SPICE brings sound, a shared clipboard, USB devices from this computer and a screen that follows the window."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

INSTALL_HINT = {
    "linux": "Install virt-viewer (Ubuntu / Debian: sudo apt install virt-viewer).",
    "win32": "Install virt-viewer for Windows from virt-manager.org (it brings remote-viewer.exe).",
}


def viewer() -> str | None:
    """The path of remote-viewer, or None."""
    found = shutil.which("remote-viewer")
    if found or not sys.platform.startswith("win"):
        return found
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", "")):
        for folder in sorted(Path(base).glob("VirtViewer*"), reverse=True) if base else []:
            exe = folder / "bin" / "remote-viewer.exe"
            if exe.exists():
                return str(exe)
    return None


def install_hint() -> str:
    return INSTALL_HINT.get("win32" if sys.platform.startswith("win") else "linux")


def vv_text(cfg: dict) -> str:
    """A .vv file, written the way the Proxmox web UI writes it (values as Proxmox sends them)."""
    lines = ["[virt-viewer]"] + [f"{k}={v}" for k, v in cfg.items()]
    return "\n".join(lines) + "\n"


def launch(cfg: dict, program: str | None = None) -> subprocess.Popen:
    """Write the connection file where only this user can read it and start the viewer on it. The viewer deletes
    the file once read (delete-this-file=1); a timer removes it anyway if the viewer never gets that far."""
    program = program or viewer()
    if not program:
        raise FileNotFoundError(install_hint())
    folder = tempfile.mkdtemp(prefix="pvc-spice-")
    path = os.path.join(folder, "console.vv")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(vv_text(cfg))
    proc = subprocess.Popen([program, path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    timer = threading.Timer(60.0, lambda: shutil.rmtree(folder, ignore_errors=True))
    timer.daemon = True
    timer.start()
    return proc
