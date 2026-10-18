"""Builds the Windows installer, on Windows, with the Python environment that runs it:

    <venv>\\Scripts\\python -I packaging\\windows\\build.py

It needs PyInstaller in that environment (pip install pyinstaller, beside requirements.txt) and Inno Setup 6
(jrsoftware.org; per user or for all users). Steps:
  1. app.ico from data/icons/<app id>.svg, drawn by Qt at the sizes Windows asks for;
  2. the version details Windows shows in the programs' Properties;
  3. PyInstaller: dist\\pyinstaller\\Proxmox Controller\\ — the app and its console program, sharing one folder;
  4. Inno Setup: dist\\windows\\ProxmoxController-<version>-setup.exe.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / "build"
DIST = ROOT / "dist"
ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)

sys.path.insert(0, str(ROOT))
from proxmox_controller import APP_ID, APP_NAME, VERSION  # noqa: E402


def ico_bytes(pngs: list[tuple[int, bytes]]) -> bytes:
    """An .ico of PNG images (Windows Vista and later read PNG inside an .ico): the header, one entry per size, then
    the images."""
    head = struct.pack("<HHH", 0, 1, len(pngs))
    offset, entries, blobs = 6 + 16 * len(pngs), b"", b""
    for size, png in pngs:
        side = 0 if size >= 256 else size  # (0 means 256)
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)
    return head + entries + blobs


def make_icon(target: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    from PySide6.QtGui import QGuiApplication, QIcon
    app = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841 (Qt draws only with an application)
    icon = QIcon(str(ROOT / "data" / "icons" / f"{APP_ID}.svg"))
    pngs = []
    for size in ICON_SIZES:
        data = QByteArray()
        buf = QBuffer(data)
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        if not icon.pixmap(size, size).save(buf, "PNG"):
            sys.exit(f"Could not draw the {size}×{size} icon.")
        pngs.append((size, bytes(data)))
    target.write_bytes(ico_bytes(pngs))


def version_tuple(version: str) -> tuple[int, int, int, int]:
    parts = [int(p) for p in version.split(".")[:4] if p.isdigit()]
    return tuple((parts + [0, 0, 0, 0])[:4])


def version_file(target: Path) -> None:
    """PyInstaller's form of the version resource: what Properties → Details shows."""
    v = version_tuple(VERSION)
    strings = {"CompanyName": "the mechanic", "FileDescription": APP_NAME, "FileVersion": VERSION,
               "InternalName": APP_NAME, "LegalCopyright": "the mechanic", "OriginalFilename": f"{APP_NAME}.exe",
               "ProductName": APP_NAME, "ProductVersion": VERSION}
    items = ",\n            ".join(f"StringStruct({k!r}, {s!r})" for k, s in strings.items())
    target.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
                    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
            {items}])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")


def find_iscc() -> str:
    found = shutil.which("ISCC")
    if found:
        return found
    for base in (os.environ.get("LOCALAPPDATA", ""), os.environ.get("ProgramFiles(x86)", ""),
                 os.environ.get("ProgramFiles", "")):
        for sub in ("Programs\\Inno Setup 6", "Inno Setup 6"):
            exe = Path(base) / sub / "ISCC.exe"
            if base and exe.exists():
                return str(exe)
    sys.exit("Inno Setup 6 (ISCC.exe) was not found: install it from jrsoftware.org.")


def main() -> int:
    if not sys.platform.startswith("win"):
        sys.exit("The Windows installer is built on Windows.")
    BUILD.mkdir(exist_ok=True)
    make_icon(BUILD / "app.ico")
    version_file(BUILD / "version_info.txt")
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(DIST / "pyinstaller"), "--workpath", str(BUILD / "pyinstaller"),
                    str(HERE / "proxmox-controller.spec")], check=True)
    subprocess.run([find_iscc(), f"/DAppVersion={VERSION}", f"/DAppIdName={APP_ID}",
                    f"/O{DIST / 'windows'}", str(HERE / "installer.iss")], check=True)
    print(DIST / "windows" / f"ProxmoxController-{VERSION}-setup.exe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
