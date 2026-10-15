"""Scheduled backups — Proxmox's backup jobs (Datacenter → Backup) — in plain words and back.

    schedule: "03:00"            every day at 03:00
              "mon..fri 21:30"   Monday to Friday
              "sat,sun 02:00"    weekends
              "sun 04:00"        one day a week
    prune-backups: "keep-last=3,keep-daily=7,keep-weekly=4,keep-monthly=6"   how many backups a job keeps
"""

from __future__ import annotations

import re

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DAY_NAMES = {"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday", "fri": "Friday",
             "sat": "Saturday", "sun": "Sunday"}
PRESETS = (("daily", "Every day"), ("weekdays", "Monday to Friday"), ("weekend", "Saturday and Sunday"),
           ("weekly", "Once a week"), ("custom", "Custom (Proxmox calendar event)"))
KEEP = (("keep-last", "Last"), ("keep-daily", "Daily"), ("keep-weekly", "Weekly"), ("keep-monthly", "Monthly"))
_TIME = r"(\d{1,2}):(\d{2})"


def schedule_value(preset: str, hour: int, minute: int, day: str = "sun", custom: str = "") -> str:
    at = f"{hour:02d}:{minute:02d}"
    return {"daily": at, "weekdays": f"mon..fri {at}", "weekend": f"sat,sun {at}",
            "weekly": f"{day} {at}"}.get(preset, custom.strip())


def parse_schedule(text: str) -> dict:
    """A schedule → {preset, hour, minute, day, custom}: the plain choice when it is one, else 'custom'."""
    s = " ".join(str(text or "").lower().split())
    out = {"preset": "custom", "hour": 3, "minute": 0, "day": "sun", "custom": str(text or "")}
    m = re.fullmatch(rf"(?:(\S+) )?{_TIME}", s)
    if not m:
        return out
    days, hour, minute = m.group(1), int(m.group(2)), int(m.group(3))
    if hour > 23 or minute > 59:
        return out
    out.update(hour=hour, minute=minute)
    if days is None:
        out["preset"] = "daily"
    elif days in ("mon..fri", "mon-fri", "mon,tue,wed,thu,fri"):
        out["preset"] = "weekdays"
    elif days in ("sat,sun", "sat..sun", "sun,sat"):
        out["preset"] = "weekend"
    elif days in DAYS:
        out.update(preset="weekly", day=days)
    return out


def describe_schedule(text: str) -> str:
    p = parse_schedule(text)
    at = f"{p['hour']:02d}:{p['minute']:02d}"
    return {"daily": f"Every day at {at}", "weekdays": f"Monday to Friday at {at}",
            "weekend": f"Saturday and Sunday at {at}",
            "weekly": f"{DAY_NAMES.get(p['day'], p['day'])}s at {at}"}.get(p["preset"], str(text or "—"))


def parse_keep(value) -> dict:
    """prune-backups as Proxmox gives it (a string, or already a dict) → {'keep-daily': 7, …}."""
    if isinstance(value, dict):
        items = value.items()
    else:
        items = (part.split("=", 1) for part in str(value or "").split(",") if "=" in part)
    out = {}
    for k, v in items:
        k = str(k).strip()
        if k.startswith("keep-") and str(v).strip().isdigit():
            out[k] = int(v)
    return out


def keep_value(keep: dict) -> str:
    return ",".join(f"{k}={keep[k]}" for k, _ in KEEP if keep.get(k))


def describe_keep(value) -> str:
    keep = parse_keep(value)
    if keep.get("keep-all"):
        return "all"
    parts = [f"{keep[k]} {name.lower()}" for k, name in KEEP if keep.get(k)]
    return ", ".join(parts) if parts else "storage's rule"


def job_vmids(job: dict) -> list[int]:
    return [int(v) for v in str(job.get("vmid") or "").replace(" ", "").split(",") if v.isdigit()]


def covers(job: dict, vmid: int) -> bool:
    """Whether a job backs up the guest: listed, or 'all' without being excluded."""
    if str(job.get("all", "0")) in ("1", "true", "True"):
        excluded = [int(v) for v in str(job.get("exclude") or "").replace(" ", "").split(",") if v.isdigit()]
        return int(vmid) not in excluded
    return int(vmid) in job_vmids(job)


def describe_guests(job: dict, names: dict[int, str]) -> str:
    if str(job.get("all", "0")) in ("1", "true", "True"):
        ex = [int(v) for v in str(job.get("exclude") or "").replace(" ", "").split(",") if v.isdigit()]
        return "All" + (f" except {', '.join(names.get(v, str(v)) for v in ex)}" if ex else "")
    ids = job_vmids(job)
    shown = [names.get(v, str(v)) for v in ids[:3]]
    return ", ".join(shown) + (f" (+{len(ids) - 3})" if len(ids) > 3 else "") if ids else "—"
