"""Builds the Linux package, on Linux (built on the oldest Ubuntu LTS it is for — 24.04 — so it runs there and on
everything newer), with the Python environment that runs it:

    <venv>/bin/python -I packaging/linux/build_deb.py

It needs PyInstaller in that environment (pip install pyinstaller, beside requirements.txt) and dpkg-deb. Steps:
  1. PyInstaller: dist/linux/pyinstaller/proxmox-controller/ — the app with its own Python and Qt;
  2. the package's tree: /opt/proxmox-controller (the app), /usr/bin/proxmox-controller, the menu entry and icons;
  3. dpkg-deb: dist/linux/proxmox-controller_<version>_amd64.deb, and its SHA-256.

The package needs virt-viewer (the SPICE console: apt installs it with the app) and the few system libraries Qt
draws with; it is what the app's own updates install (core/updates: pkexec apt-get install)."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = ROOT / "build" / "linux"
DIST = ROOT / "dist" / "linux"
PACKAGE = "proxmox-controller"
ICON_SIZES = (48, 64, 128, 256)

sys.path.insert(0, str(ROOT))
from proxmox_controller import APP_ID, APP_NAME, VERSION  # noqa: E402

DEPENDS = ["virt-viewer", "libegl1", "libgl1", "libxkbcommon0", "libfontconfig1", "libdbus-1-3",
           # Qt's X11 side, which the app uses on GNOME's Wayland too (through XWayland: windows reopen where they
           # were). Ubuntu Desktop 26.04 has few of these: the app did not start from its menu there (26/10, VM 109).
           # Listed with ldd over the whole package.
           "libxcb1", "libxcb-icccm4", "libxcb-keysyms1", "libxcb-shape0", "libxcb-xkb1", "libxkbcommon-x11-0",
           "libwayland-client0", "libwayland-cursor0", "libwayland-egl1",
           # ... and the X11 libraries the package no longer carries (the spec's DROP: one version, the system's)
           "libx11-6", "libx11-xcb1", "libxcb-cursor0", "libxcb-glx0", "libxcb-image0", "libxcb-randr0",
           "libxcb-render0", "libxcb-render-util0", "libxcb-shm0", "libxcb-sync1", "libxcb-util1", "libxcb-xfixes0"]
RECOMMENDS = ["openssh-client"]  # (the host's Console and Upgrade)


def control_text(installed_kb: int, version: str = VERSION) -> str:
    return "\n".join([
        f"Package: {PACKAGE}",
        f"Version: {version}",
        "Section: admin",
        "Priority: optional",
        "Architecture: amd64",
        f"Installed-Size: {installed_kb}",
        f"Depends: {', '.join(DEPENDS)}",
        f"Recommends: {', '.join(RECOMMENDS)}",
        "Maintainer: the mechanic <support@themechanic.store>",
        "Homepage: https://themechanic.store/controller",
        f"Description: {APP_NAME} — your Proxmox VE hosts in one window, with Claude",
        " Containers and virtual machines of one or more Proxmox VE hosts: start, stop, consoles, files, snapshots,",
        " backups, new VMs that set themselves up, Wake-on-LAN — and Claude Access, which lets Claude work on them",
        " through switches you set and requests you approve.",
        "",
    ])


def desktop_text() -> str:
    template = (ROOT / "packaging" / f"{APP_ID}.desktop.in").read_text(encoding="utf-8")
    return template.replace('"@ROOT@/bin/proxmox-controller"', f"/usr/bin/{PACKAGE}")


def icons(target: Path) -> None:
    """The SVG, and PNGs at the sizes docks and menus look for (drawn by Qt)."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtGui import QGuiApplication, QIcon
    app = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841 (Qt draws only with an application)
    svg = ROOT / "data" / "icons" / f"{APP_ID}.svg"
    scalable = target / "scalable" / "apps"
    scalable.mkdir(parents=True, exist_ok=True)
    shutil.copy2(svg, scalable / svg.name)
    icon = QIcon(str(svg))
    for size in ICON_SIZES:
        folder = target / f"{size}x{size}" / "apps"
        folder.mkdir(parents=True, exist_ok=True)
        if not icon.pixmap(size, size).save(str(folder / f"{APP_ID}.png"), "PNG"):
            sys.exit(f"Could not draw the {size}×{size} icon.")


def tree(frozen: Path, stage: Path) -> None:
    if stage.exists():
        shutil.rmtree(stage)
    shutil.copytree(frozen, stage / "opt" / PACKAGE, symlinks=True)
    (stage / "usr" / "bin").mkdir(parents=True)
    os.symlink(f"../../opt/{PACKAGE}/{PACKAGE}", stage / "usr" / "bin" / PACKAGE)
    apps = stage / "usr" / "share" / "applications"
    apps.mkdir(parents=True)
    (apps / f"{APP_ID}.desktop").write_text(desktop_text(), encoding="utf-8")
    icons(stage / "usr" / "share" / "icons" / "hicolor")
    doc = stage / "usr" / "share" / "doc" / PACKAGE
    doc.mkdir(parents=True)
    shutil.copy2(ROOT / "LICENSE", doc / "copyright")
    for path in stage.rglob("*"):  # (as dpkg wants them: readable by all; programs and folders runnable)
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or os.access(path, os.X_OK) else 0o644)
    size_kb = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file() and not p.is_symlink()) // 1024 + 1
    (stage / "DEBIAN").mkdir()
    (stage / "DEBIAN" / "control").write_text(control_text(size_kb), encoding="utf-8")


def main() -> int:
    if not sys.platform.startswith("linux"):
        sys.exit("The Linux package is built on Linux.")
    if not shutil.which("dpkg-deb"):
        sys.exit("dpkg-deb was not found (Ubuntu / Debian: sudo apt install dpkg-dev).")
    BUILD.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(DIST / "pyinstaller"), "--workpath", str(BUILD / "pyinstaller"),
                    str(HERE / "proxmox-controller.spec")], check=True)
    stage = BUILD / f"{PACKAGE}_{VERSION}_amd64"
    tree(DIST / "pyinstaller" / PACKAGE, stage)
    deb = DIST / f"{PACKAGE}_{VERSION}_amd64.deb"
    subprocess.run(["dpkg-deb", "--build", "--root-owner-group", "-Zxz", str(stage), str(deb)], check=True)
    digest = hashlib.sha256(deb.read_bytes()).hexdigest()
    (DIST / "SHA256SUMS").write_text(f"{digest}  {deb.name}\n", encoding="utf-8")
    print(deb)
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
