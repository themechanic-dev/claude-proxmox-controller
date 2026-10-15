"""Every request that came through the connector, kept as one JSON line each: when, from which Claude, to which host,
what, why, what the switches or the user decided, and how it ended."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from . import store

KEEP_BYTES = 2 << 20  # past this the log starts again, keeping the previous one as .1
_lock = threading.Lock()


def path() -> Path:
    return store.data_dir() / "connector-log.jsonl"


def _short(value, limit: int = 300):
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    if isinstance(value, dict):
        return {k: _short(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_short(v, limit) for v in value[:50]]
    return value


def add(entry: dict) -> dict:
    entry = {"time": time.time(), **_short(entry)}
    p = path()
    with _lock:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and p.stat().st_size > KEEP_BYTES:
            os.replace(p, p.with_suffix(".jsonl.1"))
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def last(n: int = 200) -> list[dict]:
    try:
        lines = path().read_text(encoding="utf-8").splitlines()[-n:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
