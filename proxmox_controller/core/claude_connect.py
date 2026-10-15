"""Connecting the connector to the Claude apps on this computer, so the user needs no terminal:

    Claude Code (and the Claude desktop app's Code tab)   `claude mcp add --scope user …` — Claude Code's own
                                                          command, which writes its settings safely even while it runs
    Claude Desktop (and Cowork)                           an entry in claude_desktop_config.json (read when it starts)

Both start the same bridge: `<this folder>/bin/proxmox-controller --mcp`."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

NAME = "proxmox-controller"
ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "bin" / "proxmox-controller"


def claude_cli() -> str:
    """The `claude` program: on PATH, or where its installer puts it (an app started from the desktop may not have
    ~/.local/bin on its PATH)."""
    found = shutil.which("claude")
    if found:
        return found
    for candidate in (Path.home() / ".local" / "bin" / "claude", Path.home() / ".claude" / "local" / "claude"):
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return ""


def code_config() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home()) / ".claude.json"


def desktop_config() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "Claude" / "claude_desktop_config.json"


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def code_connected() -> bool:
    return NAME in (_read(code_config()).get("mcpServers") or {})


def desktop_connected() -> bool:
    return NAME in (_read(desktop_config()).get("mcpServers") or {})


def _run(args: list[str]) -> str:
    done = subprocess.run(args, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    if done.returncode != 0:
        raise RuntimeError((done.stderr or done.stdout or f"exit code {done.returncode}").strip())
    return done.stdout


def connect_code() -> None:
    cli = claude_cli()
    if not cli:
        raise FileNotFoundError("Claude Code (the `claude` program) was not found on this computer.")
    if code_connected():
        _run([cli, "mcp", "remove", "--scope", "user", NAME])  # made again: the folder may have moved
    _run([cli, "mcp", "add", "--scope", "user", NAME, "--", str(BRIDGE), "--mcp"])


def disconnect_code() -> None:
    cli = claude_cli()
    if cli and code_connected():
        _run([cli, "mcp", "remove", "--scope", "user", NAME])


def _write_desktop(change) -> None:
    path = desktop_config()
    data = _read(path)
    change(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def connect_desktop() -> None:
    _write_desktop(lambda d: d.setdefault("mcpServers", {}).update(
        {NAME: {"command": str(BRIDGE), "args": ["--mcp"]}}))


def disconnect_desktop() -> None:
    _write_desktop(lambda d: (d.get("mcpServers") or {}).pop(NAME, None))
