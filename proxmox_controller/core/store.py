"""Where the app keeps its settings, per operating system.

    Linux    ~/.config/proxmox-controller/   (XDG_CONFIG_HOME)     ~/.local/share/proxmox-controller/
    Windows  %APPDATA%\\ProxmoxController\\                         %LOCALAPPDATA%\\ProxmoxController\\

hosts.json holds the hosts without their secrets; secrets.json holds the API token secrets (the user's, and
Claude's own tokens for the connector), kept apart so they can be locked with a password (core/vault.py). Both are
written owner-only (0600) where the OS supports it.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import asdict
from pathlib import Path

from . import vault
from .pve import Host

SETTINGS_DEFAULTS = {
    "refresh_seconds": 10,
    "selected_host": "",
    "hide_stopped": False,
    "console": "auto",
    "remember_place": True,  # reopen windows where they were (on GNOME Wayland this needs XWayland)
    "geometry": {},          # window → its saved size and place
    "claude": {},            # the connector: {"enabled": bool, "hosts": {host id: {kind: off|ask|on}}}
}
CONSOLE_CHOICES = ("auto", "spice", "vnc", "browser")
REFRESH_CHOICES = (5, 10, 30, 60)


def _windows() -> bool:
    return sys.platform.startswith("win")


def config_dir() -> Path:
    if _windows():
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "ProxmoxController"
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "proxmox-controller"


def data_dir() -> Path:
    if _windows():
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "ProxmoxController"
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "proxmox-controller"


def _write_private(path: Path, payload: dict) -> None:
    """Written whole or not at all, even if the power goes: a new file beside the old one, forced onto the disk, then
    put in its place. (ext4 does this by itself for a renamed file; other file systems, NTFS too, need the fsync.)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not _windows():
        os.chmod(path.parent, 0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    if not _windows():
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    if not _windows():  # the rename itself, kept in the folder's entry
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# -- secrets ---------------------------------------------------------------------------------------

class Locked(Exception):
    """The secrets are locked and the app was not unlocked with the password."""


_key: vault.Key | None = None  # set by unlock() or set_password(); only in this running app


def check_password(password: str) -> None:
    """vault.WrongPassword unless it is the password the tokens are locked with."""
    vault.open_with(_read(_secrets_path()), password)


def _secrets_path() -> Path:
    return config_dir() / "secrets.json"


def secrets_state() -> str:
    """'none' (no file), 'plain' or 'locked'."""
    path = _secrets_path()
    if not path.exists():
        return "none"
    return "locked" if vault.is_locked(_read(path)) else "plain"


def is_unlocked() -> bool:
    return _key is not None


def read_secrets() -> dict:
    """{"tokens": {host id: secret}, "claude": {host id: secret}}. Locked: needs unlock() first."""
    blob = _read(_secrets_path())
    if not vault.is_locked(blob):
        return blob
    if _key is None:
        raise Locked("The API tokens are locked.")
    try:
        return vault.open_with_key(blob, _key)
    except vault.WrongPassword as e:  # changed on disk by something else since it was unlocked
        raise Locked("The locked tokens could not be opened.") from e


def write_secrets(payload: dict) -> None:
    if secrets_state() == "locked" and _key is None:
        raise Locked("Unlock the API tokens first.")
    _write_private(_secrets_path(), vault.seal(payload, _key) if _key is not None else payload)


def unlock(password: str) -> None:
    """Opens the locked secrets for this run. vault.WrongPassword if the password is wrong."""
    global _key
    _, _key = vault.open_with(_read(_secrets_path()), password)


def set_password(password: str) -> None:
    """Lock the secrets with a (new) password."""
    global _key
    if not password:  # any password the user likes — only not none at all
        raise ValueError("Type a password.")
    payload = read_secrets() if secrets_state() != "none" else {}
    _key = vault.derive(password)
    write_secrets(payload)


def remove_password(password: str) -> None:
    """Back to a plain file, after the current password is typed again."""
    global _key
    payload, _ = vault.open_with(_read(_secrets_path()), password)
    _write_private(_secrets_path(), payload)  # (write_secrets would refuse: the file on disk is still locked)
    _key = None


def forget_secrets() -> None:
    """A forgotten password: the tokens go (the hosts stay, and get their tokens again with Edit…)."""
    global _key
    _key = None
    try:
        _secrets_path().unlink()
    except FileNotFoundError:
        pass


def lock_session() -> None:
    """Forget the key in this run (tests; quitting)."""
    global _key
    _key = None


# -- hosts ---------------------------------------------------------------------------------------

def load_hosts() -> list[Host]:
    folder = config_dir()
    raw = _read(folder / "hosts.json").get("hosts", [])
    try:
        secrets = read_secrets().get("tokens", {})
    except Locked:
        secrets = {}
    hosts = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict) or not item.get("id") or not item.get("address"):
            continue
        hosts.append(Host(
            id=str(item["id"]), name=str(item.get("name") or item["address"]), address=str(item["address"]),
            token_id=str(item.get("token_id", "")), token_secret=str(secrets.get(item["id"], "")),
            fingerprint=str(item.get("fingerprint", "")), mac=str(item.get("mac", "")),
            broadcast=str(item.get("broadcast") or "255.255.255.255"),
            extra=item.get("extra") if isinstance(item.get("extra"), dict) else {}))
    return hosts


def save_hosts(hosts: list[Host]) -> None:
    folder = config_dir()
    public = []
    for h in hosts:
        item = asdict(h)
        item.pop("token_secret")
        public.append(item)
    # secrets first: cut off in between, a new host's secret waits unused — never a host without its token secret
    payload = read_secrets() if secrets_state() != "none" else {}
    payload["tokens"] = {h.id: h.token_secret for h in hosts if h.token_secret}
    known = {h.id for h in hosts}
    payload["claude"] = {k: v for k, v in (payload.get("claude") or {}).items() if k in known}  # removed host: gone
    write_secrets(payload)
    _write_private(folder / "hosts.json", {"hosts": public})


def claude_token(host_id: str) -> str:
    """Claude's own API token secret for a host (the connector), or ""."""
    try:
        return str((read_secrets().get("claude") or {}).get(host_id, ""))
    except Locked:
        return ""


def save_claude_token(host_id: str, secret: str) -> None:
    payload = read_secrets() if secrets_state() != "none" else {}
    tokens = dict(payload.get("claude") or {})
    if secret:
        tokens[host_id] = secret
    else:
        tokens.pop(host_id, None)
    payload["claude"] = tokens
    write_secrets(payload)


def new_host_id() -> str:
    return uuid.uuid4().hex[:12]


# -- app settings --------------------------------------------------------------------------------

def load_settings() -> dict:
    cfg = dict(SETTINGS_DEFAULTS)
    data = _read(config_dir() / "settings.json")
    for key, default in SETTINGS_DEFAULTS.items():
        value = data.get(key)
        if isinstance(default, bool):
            ok = isinstance(value, bool)
        else:  # True/False would pass as an int, so they are kept out of number settings
            ok = isinstance(value, type(default)) and not isinstance(value, bool)
        if ok:
            cfg[key] = value
    if cfg["refresh_seconds"] not in REFRESH_CHOICES:
        cfg["refresh_seconds"] = SETTINGS_DEFAULTS["refresh_seconds"]
    if cfg["console"] not in CONSOLE_CHOICES:
        cfg["console"] = SETTINGS_DEFAULTS["console"]
    return cfg


def save_settings(cfg: dict) -> None:
    _write_private(config_dir() / "settings.json", {k: cfg.get(k, v) for k, v in SETTINGS_DEFAULTS.items()})
