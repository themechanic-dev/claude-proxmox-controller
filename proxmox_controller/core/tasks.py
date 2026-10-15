"""Proxmox tasks in plain words, the way its web UI shows them: "VM 113 (TestVm) — Start", "Bulk start"."""

from __future__ import annotations

import time

WORDS = {
    "qmstart": "Start", "vzstart": "Start", "qmshutdown": "Shut down", "vzshutdown": "Shut down",
    "qmstop": "Stop", "vzstop": "Stop", "qmreboot": "Reboot", "vzreboot": "Reboot",
    "qmsuspend": "Suspend", "vzsuspend": "Suspend", "qmresume": "Resume", "vzresume": "Resume",
    "qmcreate": "Create", "vzcreate": "Create", "qmclone": "Clone", "vzclone": "Clone",
    "qmrestore": "Restore", "vzrestore": "Restore", "qmdestroy": "Destroy", "vzdestroy": "Destroy",
    "qmsnapshot": "Take snapshot", "vzsnapshot": "Take snapshot", "qmrollback": "Roll back", "vzrollback": "Roll back",
    "qmdelsnapshot": "Delete snapshot", "vzdelsnapshot": "Delete snapshot", "qmconfig": "Change settings",
    "qmmove": "Move disk", "qmigrate": "Migrate", "vzmigrate": "Migrate", "resize": "Grow disk",
    "vzdump": "Backup", "vncproxy": "Console", "spiceproxy": "SPICE console", "vncshell": "Shell",
    "startall": "Bulk start", "stopall": "Bulk shut down", "suspendall": "Bulk suspend", "migrateall": "Bulk migrate",
    "download": "Download", "imgcopy": "Upload", "imgdel": "Delete file", "aptupdate": "Update package lists",
    "srvreload": "Reload service", "srvrestart": "Restart service",
}


def running(task: dict) -> bool:
    return not task.get("endtime") or str(task.get("status", "")).lower() == "running"


def ok(task: dict) -> bool:
    return str(task.get("status", "")) == "OK"


def describe(task: dict, guests: dict[int, dict]) -> str:
    """What a task did, and to which guest."""
    word = WORDS.get(task.get("type", ""), task.get("type", "Task"))
    tid = str(task.get("id") or "")
    if tid.isdigit() and int(tid) in guests:
        g = guests[int(tid)]
        kind = "Container" if g.get("type") == "lxc" else "VM"
        return f"{kind} {tid} ({g.get('name', '')}) — {word}"
    if tid.isdigit():  # a guest that is gone (or on a node not shown)
        kind = {"qm": "VM", "vz": "Container"}.get(str(task.get("type", ""))[:2], "Guest")
        return f"{'Guest' if task.get('type') == 'vzdump' else kind} {tid} — {word}"
    return word


def outcome(task: dict) -> str:
    if running(task):
        return "Running"
    return str(task.get("status") or "unknown")


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def started(task: dict, now: float | None = None) -> str:
    """'14:05:31' today, 'Oct 12 03:00' before. Month names spelled here: Qt sets the system's locale for C, and
    strftime's %b would then write them in the computer's language inside an English app."""
    t = int(task.get("starttime") or 0)
    if not t:
        return "—"
    now = time.time() if now is None else now
    lt = time.localtime(t)
    if lt[:3] == time.localtime(now)[:3]:
        return time.strftime("%H:%M:%S", lt)
    return f"{MONTHS[lt.tm_mon - 1]} {lt.tm_mday} {lt.tm_hour:02d}:{lt.tm_min:02d}"


def took(task: dict, now: float | None = None) -> str:
    """How long it ran (or has been running): '3 s', '6 min 20 s', '1 h 05 min'."""
    begin = int(task.get("starttime") or 0)
    if not begin:
        return "—"
    end = (time.time() if now is None else now) if running(task) else int(task.get("endtime") or begin)
    s = max(0, int(end - begin))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {s % 3600 // 60:02d} min"
