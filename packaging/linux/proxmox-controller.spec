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
# Qt's GTK 3 theme plugin would bring the build machine's whole GTK stack along (it did, once virt-viewer was on the
# build VM: 26/10) — old libraries that would meet a newer system's GTK modules at run time. The app draws with its own
# style and colours (Fusion), so the plugin and its stack stay out; the rest is what PyInstaller always takes.
DROP = ("libqgtk3.so", "libgtk-3.", "libgdk-3.", "libgdk_pixbuf", "libatk-", "libatspi.", "libcairo", "libpango",
        "libharfbuzz.", "libepoxy.", "libfribidi.", "libdatrie.", "libthai.", "libgraphite2.", "libpixman-", "libjpeg.",
        "libXcomposite.", "libXdamage.", "libXi.", "libXinerama.", "libXrandr.", "libXcursor.", "libXfixes.",
        "libXext.", "libXrender.",
        # The X11 side (xcb, xkb, X11) comes from the system too, all of it: those libraries must be one version.
        # The package carried 24.04's libxkbcommon while 26.04's libxkbcommon-x11 came from the system; the two share
        # their structures, and the first key pressed after a dialog closed crashed the app (SIGSEGV in
        # xkb_state_key_get_layout, measured with gdb on Ubuntu Desktop 26.04, 27/10). build_deb's Depends name them.
        "libxkbcommon", "libX11.", "libX11-xcb.", "libXau.", "libXdmcp.", "libxcb")
a.binaries = [b for b in a.binaries if not os.path.basename(b[0]).startswith(DROP)]
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], name="proxmox-controller", exclude_binaries=True, console=True, upx=False, strip=False)
COLLECT(exe, a.binaries, a.datas, name="proxmox-controller", upx=False)
