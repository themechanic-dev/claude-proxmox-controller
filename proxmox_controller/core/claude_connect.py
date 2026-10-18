"""Connecting the connector to the Claude apps on this computer, so the user needs no terminal:

    Claude Code (and the Claude desktop app's Code tab)   `claude mcp add --scope user …` — Claude Code's own
                                                          command, which writes its settings safely even while it runs
    Claude Desktop (and Cowork)                           an entry in claude_desktop_config.json (read when it starts)

Both start the same bridge: `<this folder>/bin/proxmox-controller --mcp` — on Windows, the installed app's console
program `proxmox-controller-mcp.exe` (or, from the source tree, its Python with bin/launch.py)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import procs

NAME = "proxmox-controller"
ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "bin" / "proxmox-controller"
WINDOWS = sys.platform.startswith("win")
MCP_EXE = "proxmox-controller-mcp.exe"  # the Windows build's console program: the bridge talks on stdin and stdout


def bridge_command() -> list[str]:
    """The program (and its first arguments) that starts the bridge; Claude adds nothing but --mcp."""
    if getattr(sys, "frozen", False):  # the Windows installer's build: its console program beside the app
        return [str(Path(sys.executable).with_name(MCP_EXE))]
    if WINDOWS:  # the source tree on Windows: its own Python — the console one, not pythonw
        python = Path(sys.executable)
        if python.name.lower() == "pythonw.exe":
            python = python.with_name("python.exe")
        return [str(python), "-I", str(ROOT / "bin" / "launch.py")]
    return [str(BRIDGE)]


def claude_cli() -> str:
    """The `claude` program: on PATH, or where its installer puts it (an app started from the desktop may not have
    ~/.local/bin on its PATH)."""
    found = shutil.which("claude")
    if found:
        return found
    candidates = [Path.home() / ".local" / "bin" / "claude", Path.home() / ".claude" / "local" / "claude"]
    if WINDOWS:  # its native installer's claude.exe; npm's claude.cmd
        candidates = [Path.home() / ".local" / "bin" / "claude.exe",
                      Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "npm" / "claude.cmd"]
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return ""


def code_config() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home()) / ".claude.json"


def desktop_config() -> Path:
    if WINDOWS:  # %APPDATA%\\Claude, where Claude Desktop for Windows keeps it
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "Claude" / "claude_desktop_config.json"


def _read(path: Path, strict: bool = False) -> dict:
    """A Claude app's settings file. utf-8-sig: Windows' Notepad and PowerShell 5 write a BOM, and plain utf-8 took
    the file for empty (measured). strict (before writing): a file that is there but cannot be read raises — written
    over, it would lose the user's other servers and settings."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}
    except OSError:
        if strict:
            raise
        return {}
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError as e:
        if strict:
            raise RuntimeError(f"{path} is not valid JSON ({e}); it was left as it is.") from e
        return {}
    if not isinstance(data, dict):
        if strict:
            raise RuntimeError(f"{path} does not hold settings; it was left as it is.")
        return {}
    return data


def code_connected() -> bool:
    return NAME in (_read(code_config()).get("mcpServers") or {})


def desktop_connected() -> bool:
    return NAME in (_read(desktop_config()).get("mcpServers") or {})


def _run(args: list[str]) -> str:
    done = subprocess.run(args, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                          **procs.hidden())
    if done.returncode != 0:
        raise RuntimeError((done.stderr or done.stdout or f"exit code {done.returncode}").strip())
    return done.stdout


def connect_code() -> None:
    cli = claude_cli()
    if not cli:
        raise FileNotFoundError("Claude Code (the `claude` program) was not found on this computer.")
    if code_connected():
        _run([cli, "mcp", "remove", "--scope", "user", NAME])  # made again: the folder may have moved
    _run([cli, "mcp", "add", "--scope", "user", NAME, "--", *bridge_command(), "--mcp"])


def disconnect_code() -> None:
    cli = claude_cli()
    if cli and code_connected():
        _run([cli, "mcp", "remove", "--scope", "user", NAME])


def _write_desktop(change) -> None:
    path = desktop_config()
    data = _read(path, strict=True)
    change(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def connect_desktop() -> None:
    command = bridge_command()
    _write_desktop(lambda d: d.setdefault("mcpServers", {}).update(
        {NAME: {"command": command[0], "args": [*command[1:], "--mcp"]}}))


def disconnect_desktop() -> None:
    _write_desktop(lambda d: (d.get("mcpServers") or {}).pop(NAME, None))
