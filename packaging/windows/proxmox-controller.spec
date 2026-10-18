# PyInstaller spec for the Windows build (run by build.py): two programs sharing one folder —
#   Proxmox Controller.exe        the app (no console window)
#   proxmox-controller-mcp.exe    a console program: the connector's bridge for Claude (--mcp), what ssh asks for a
#                                 password (--askpass), and the uninstaller's tidy-up (--uninstall)
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
BUILD = os.path.join(SPECPATH, "build")

a = Analysis(
    [os.path.join(ROOT, "bin", "launch.py")],
    pathex=[ROOT],
    datas=[(os.path.join(ROOT, "data"), "data")],  # icons; the app finds them beside its modules
    hiddenimports=["multiprocessing.connection"],  # the connector's pipe (imported where it is used)
    excludes=["tkinter", "PySide6.QtDBus"],  # (D-Bus: Linux's notifications only)
)
pyz = PYZ(a.pure)
common = dict(exclude_binaries=True, icon=os.path.join(BUILD, "app.ico"),
              version=os.path.join(BUILD, "version_info.txt"), upx=False)
app = EXE(pyz, a.scripts, [], name="Proxmox Controller", console=False, **common)
bridge = EXE(pyz, a.scripts, [], name="proxmox-controller-mcp", console=True, **common)
COLLECT(app, bridge, a.binaries, a.datas, name="Proxmox Controller", upx=False)
