"""The start/shutdown order of a guest — Proxmox's `startup` setting (Options → Start/Shutdown order):

    startup: order=2,up=30,down=120

order — lower numbers start first and shut down last; without one, a guest comes after those that have it.
up    — seconds Proxmox waits after starting this guest before it starts the next one.
down  — seconds Proxmox gives this guest to shut down by itself before it stops it (default 180).
"""

from __future__ import annotations

DEFAULT_DOWN_S = 180


def parse(text: str) -> dict:
    """'order=2,up=30' → {'order': 2, 'up': 30, 'down': None}. A first value without a name is the order."""
    out = {"order": None, "up": None, "down": None}
    for i, part in enumerate(p.strip() for p in str(text or "").split(",") if p.strip()):
        key, eq, value = part.partition("=")
        if not eq and i == 0:
            key, value = "order", key
        if key in out and value.strip().isdigit():
            out[key] = int(value)
    return out


def value(order: int | None, up: int | None, down: int | None) -> str:
    parts = [f"{k}={v}" for k, v in (("order", order), ("up", up), ("down", down)) if v]
    return ",".join(parts)


def change(cfg: dict, order: int | None, up: int | None, down: int | None) -> dict:
    """The config change that sets the order, or {} when it is already so. Nothing at all → the setting is removed."""
    new = value(order, up, down)
    old = parse(cfg.get("startup", ""))
    if new == value(old["order"], old["up"], old["down"]):
        return {}
    return {"startup": new} if new else ({"delete": "startup"} if cfg.get("startup") else {})


def describe(text: str) -> str:
    """For a tooltip: 'order 2, then waits 30 s'."""
    s = parse(text)
    bits = []
    if s["order"]:
        bits.append(f"order {s['order']}")
    if s["up"]:
        bits.append(f"then waits {s['up']} s")
    if s["down"]:
        bits.append(f"shutdown timeout {s['down']} s")
    return ", ".join(bits)
