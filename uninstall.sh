#!/usr/bin/env bash
# Removes what ./install.sh added for this user.
#   ./uninstall.sh          launcher and icons; your hosts and settings are kept
#   ./uninstall.sh --all    also the hosts, their API token secrets and the settings
# Quit the app first (Ctrl+Q in the window).
# The app's own Python environment is the .venv folder next to this script: delete the folder to remove it.
set -euo pipefail
APP_ID="store.themechanic.ProxmoxController"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}"
ICONS="$DATA/icons/hicolor"

rm -f "$DATA/applications/$APP_ID.desktop" "$ICONS/scalable/apps/$APP_ID.svg" "$CONFIG/autostart/$APP_ID.desktop"
for n in 16 24 32 48 64 128 256 512; do
  rm -f "$ICONS/${n}x${n}/apps/$APP_ID.png"
done
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -f -t "$ICONS" || true
command -v update-desktop-database >/dev/null && update-desktop-database -q "$DATA/applications" || true

if [ "${1:-}" = "--all" ]; then
  rm -rf "$CONFIG/proxmox-controller" "$DATA/proxmox-controller"
  echo "Removed the launcher, the icons, the start with the computer, the hosts, their token secrets and the settings."
else
  echo "Removed the launcher, the icons and the start with the computer (hosts and settings kept)."
fi
