# PyInstaller spec for the Linux package (run by build_deb.py): one program, in /opt/proxmox-controller —
#   proxmox-controller         the app; with --mcp the connector's bridge for Claude (no console windows on Linux, so
#                              the same program serves both, where Windows needs a console program of its own)
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))

a = Analysis(
    [os.path.join(ROOT, "bin", "launch.py")],
    pathex=[ROOT],
    datas=[(os.path.join(ROOT, "data"), "data")],  # icons; the app finds them beside its modules
    hiddenimports=["multiprocessing.connection"],
    excludes=["tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], name="proxmox-controller", exclude_binaries=True, console=True, upx=False, strip=False)
COLLECT(exe, a.binaries, a.datas, name="proxmox-controller", upx=False)
