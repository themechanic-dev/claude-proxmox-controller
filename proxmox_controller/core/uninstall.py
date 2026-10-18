"""What the Windows uninstaller asks the app to tidy before its files go — what points at the program and would be
left behind: the start-at-login entry, and the connector's entries in the Claude apps (they would try to start a
program that is gone). The hosts and settings are the user's: removed only when the user says so (the uninstaller
asks)."""

from __future__ import annotations

import shutil

from . import autostart, claude_connect, store


def _start_with_the_computer() -> bool:
    if not autostart.is_enabled():
        return False
    autostart.set_enabled(False)
    return True


def _claude_desktop() -> bool:
    if not claude_connect.desktop_connected():
        return False
    claude_connect.disconnect_desktop()
    return True


def _claude_code() -> bool:
    if not claude_connect.code_connected():
        return False
    claude_connect.disconnect_code()
    return True


def _hosts_and_settings() -> bool:
    for folder in (store.config_dir(), store.data_dir()):
        shutil.rmtree(folder, ignore_errors=True)
    return True


def cleanup(remove_data: bool = False) -> list[str]:
    """Each step on its own — one failing leaves the rest done. Returns what was taken away."""
    steps = [("start with the computer", _start_with_the_computer), ("Claude Desktop's connector", _claude_desktop),
             ("Claude Code's connector", _claude_code)]
    if remove_data:
        steps.append(("hosts, token secrets and settings", _hosts_and_settings))
    done = []
    for what, step in steps:
        try:
            if step():
                done.append(what)
        except Exception:  # an uninstaller goes on
            pass
    return done
