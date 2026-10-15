#!/usr/bin/env bash
# Installs Proxmox Controller for this user:
#   1. checks for Python 3.10–3.14 with its venv module,
#   2. creates the app's own Python environment in ./.venv and installs Qt for Python (PySide6) into it,
#   3. adds the launcher and the icon to the app menu (~/.local/share).
# No system packages are installed, nothing runs in the background and nothing starts at login.
# Undo with ./uninstall.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
APP_ID="store.themechanic.ProxmoxController"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
APPS="$DATA/applications"
ICONS="$DATA/icons/hicolor"
PY="$(command -v python3 || true)"

# --- 1. Python ----------------------------------------------------------------------------------
if [ -z "$PY" ]; then
  echo "python3 was not found. Install Python 3.10 or newer, then run ./install.sh again." >&2
  exit 1
fi
if ! "$PY" -I - <<'PY'
import sys
if not (3, 10) <= sys.version_info[:2] <= (3, 14):
    sys.exit("Python 3.10 to 3.14 is needed (found %d.%d)." % sys.version_info[:2])
try:
    import ensurepip, venv  # noqa: F401
except ImportError:
    sys.exit("Python's venv module is missing.")
PY
then
  cat >&2 <<'EOF'

Install it first, then run ./install.sh again:
  Ubuntu / Debian:  sudo apt install python3-venv
  Fedora:           Python's venv module is part of python3
EOF
  exit 1
fi

# --- 2. the app's Python environment ------------------------------------------------------------
if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "Creating the Python environment in $ROOT/.venv …"
  "$PY" -m venv "$ROOT/.venv"
fi
echo "Installing Qt for Python into $ROOT/.venv (about 80 MB the first time) …"
"$ROOT/.venv/bin/python" -m pip install --disable-pip-version-check --quiet -r "$ROOT/requirements.txt"
if ! QT_QPA_PLATFORM=offscreen "$ROOT/.venv/bin/python" -I -c 'from PySide6.QtWidgets import QApplication'; then
  cat >&2 <<'EOF'

Qt could not start: a system library is missing (its name is in the error above).
  Ubuntu / Debian:  sudo apt install libegl1 libgl1 libxkbcommon0 libfontconfig1
EOF
  exit 1
fi
if [ "${XDG_SESSION_TYPE:-}" = "x11" ] && ! /sbin/ldconfig -p 2>/dev/null | grep -q 'libxcb-cursor\.so\.0'; then
  echo "Note: on an X11 session Qt also needs libxcb-cursor0 (Ubuntu / Debian: sudo apt install libxcb-cursor0)." >&2
fi

# --- 3. launcher and icon -----------------------------------------------------------------------
mkdir -p "$APPS" "$ICONS/scalable/apps"
sed "s|@ROOT@|$ROOT|g" "$ROOT/packaging/$APP_ID.desktop.in" > "$APPS/$APP_ID.desktop"
cp "$ROOT/data/icons/$APP_ID.svg" "$ICONS/scalable/apps/$APP_ID.svg"

# PNG sizes for docks that prefer bitmaps, drawn by Qt's own SVG renderer.
QT_QPA_PLATFORM=offscreen "$ROOT/.venv/bin/python" -I - "$ROOT/data/icons/$APP_ID.svg" "$ICONS" "$APP_ID" <<'PY'
import os, sys
from PySide6.QtGui import QGuiApplication, QIcon
svg, icons, app_id = sys.argv[1:4]
app = QGuiApplication([])
icon = QIcon(svg)
for n in (16, 24, 32, 48, 64, 128, 256, 512):
    folder = os.path.join(icons, f"{n}x{n}", "apps")
    os.makedirs(folder, exist_ok=True)
    if not icon.pixmap(n, n).save(os.path.join(folder, app_id + ".png"), "PNG"):
        sys.exit(f"Could not write the {n}x{n} icon.")
PY

command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -f -t "$ICONS" || true
command -v update-desktop-database >/dev/null && update-desktop-database -q "$APPS" || true
echo "Installed. Open \"Proxmox Controller\" from the app menu and press Add Host…"
echo "To look around first without a server:  $ROOT/bin/proxmox-controller --demo"
