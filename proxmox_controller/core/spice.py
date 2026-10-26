"""Opening a VM's SPICE console in remote-viewer (virt-viewer), the viewer Proxmox itself hands out .vv files for.
SPICE brings sound, a shared clipboard, USB devices from this computer and a screen that follows the window.

Until the VM's system starts its USB tablet, SPICE has only the relative PS/2 mouse, and remote-viewer captures the
pointer — on GNOME Wayland it did not give it back with Ctrl+Alt+R (the user, 24/10: freed only through the power
button's dialog). Measured 26/10 on a Windows 11 VM's restart, QEMU's 'info mice' each second: the PS/2 mouse from
QEMU's start for 24 s, then the tablet; at a first boot from an ISO, minutes (the firmware, "Press any key", the
installer loading). would_capture() tells it before the window opens. (QEMU's 'info spice' is no help: its
mouse-mode reads "server" until a viewer connects and asks for "client" — read 26/10, tablet on.)"""

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


def would_capture(pve, node: str, vmid: int) -> bool:
    """Whether remote-viewer would capture the pointer now: the VM has a USB tablet that its system has not started
    yet (firmware, a boot from an ISO, an installation). A VM without a tablet (Proxmox leaves it out with SPICE)
    goes as before: it is used with SPICE's agent. Not readable: False (SPICE as before)."""
    from . import vmhw
    try:
        if not vmhw.tablet_of(pve.guest_config(node, "qemu", vmid)):
            return False
        return vmhw.pointer_state(pve.monitor(node, vmid, "info mice"))[0] == "relative"
    except Exception:  # noqa: BLE001 — an older Proxmox, a token without Sys.Audit: SPICE as it always opened
        return False


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
