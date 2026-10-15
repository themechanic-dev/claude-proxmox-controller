"""The host's package sources, in plain words: which of them refused the last check (Proxmox's enterprise
repository answers 401 without a subscription, and apt-get update then fails with exit code 100 though the other
sources were checked), and the switch to the free No-Subscription repositories — as the web UI's Updates →
Repositories does it, through the same API."""

from __future__ import annotations

import re
from urllib.parse import urlparse

ERR = re.compile(r"^Err:\d+\s+(\S+)")
ENTERPRISE = "enterprise.proxmox.com"


def refused(log_lines: list[str]) -> list[dict]:
    """The sources a check could not read, from its task log: [{"url", "host", "reason"}] — the reason is the line
    after "Err:…" ("401  Unauthorized [IP: …]" → "401 Unauthorized")."""
    out = []
    for i, line in enumerate(log_lines):
        m = ERR.match(line.strip())
        if not m:
            continue
        reason = log_lines[i + 1].strip() if i + 1 < len(log_lines) else ""
        reason = " ".join(reason.split("[IP:")[0].split())
        url = m.group(1)
        out.append({"url": url, "host": urlparse(url).hostname or url, "reason": reason})
    return out


def explain(failures: list[dict]) -> str:
    """What to tell the user about the sources that refused, one line a host."""
    by_host: dict[str, set] = {}
    for f in failures:
        by_host.setdefault(f["host"], set()).add(f["reason"] or "no answer")
    parts = []
    for host, reasons in sorted(by_host.items()):
        text = f"{host} ({', '.join(sorted(reasons))}"
        if host == ENTERPRISE and any(r.startswith("401") for r in reasons):
            text += " — it needs a Proxmox subscription"
        parts.append(text + ")")
    return "; ".join(parts)


def only_enterprise(failures: list[dict]) -> bool:
    return bool(failures) and all(f["host"] == ENTERPRISE for f in failures)


# -- the repositories ------------------------------------------------------------------------------

def _product(repo: dict) -> str:
    """'pve', 'ceph' or '' (Debian and the rest), from where a repository points (…/debian/pve, …/debian/ceph-squid)."""
    for uri in repo.get("URIs") or []:
        path = urlparse(uri).path
        if "/debian/ceph" in path:
            return "ceph"
        if "/debian/pve" in path:
            return "pve"
    return ""


def _is_enterprise(repo: dict) -> bool:
    return any(ENTERPRISE in uri for uri in repo.get("URIs") or [])


def entries(info: dict) -> list[dict]:
    """Every repository of the host: {"path", "index", "product", "enterprise", "enabled", "uris"}."""
    out = []
    for f in info.get("files") or []:
        for i, repo in enumerate(f.get("repositories") or []):
            out.append({"path": f.get("path", ""), "index": i, "product": _product(repo),
                        "enterprise": _is_enterprise(repo), "enabled": bool(repo.get("Enabled")),
                        "uris": list(repo.get("URIs") or [])})
    return out


def standard(info: dict) -> dict:
    """handle → True (on), False (there, off) or None (not set up): Proxmox's own list of its repositories."""
    return {r.get("handle", ""): (None if r.get("status") is None else bool(r.get("status")))
            for r in info.get("standard-repos") or []}


def _handle(std: dict, product: str, kind: str) -> str:
    """The handle of a standard repository: pve's are 'enterprise' / 'no-subscription', Ceph's carry its release
    ('ceph-squid-no-subscription')."""
    if product == "pve":
        return kind if kind in std else ""
    return next((h for h in std if h.startswith("ceph-") and h.endswith("-" + kind)), "")


def describe(info: dict) -> list[str]:
    """Lines for the window: Proxmox's (and Ceph's) repositories and whether they are on."""
    std, lines = standard(info), []
    for product, title in (("pve", "Proxmox"), ("ceph", "Ceph")):
        shown = []
        for kind, word in (("enterprise", "Enterprise"), ("no-subscription", "No-Subscription"), ("test", "Test")):
            status = std.get(_handle(std, product, kind))
            if status is not None:
                shown.append(f"{word} {'on' if status else 'off'}")
        if shown:
            lines.append(f"{title}: " + ", ".join(shown))
    return lines


def plan_no_subscription(info: dict) -> list[tuple]:
    """What makes the host take Proxmox's (and Ceph's) updates from the free No-Subscription repositories, as the
    web UI does by hand: [("add", handle) | ("enable", path, index) | ("disable", path, index)]. For each product
    whose enterprise repository is on: its No-Subscription one is added (or switched on) and the enterprise one off.
    Empty when nothing is to change."""
    std, all_repos, plan = standard(info), entries(info), []
    for product in ("pve", "ceph"):
        on = [e for e in all_repos if e["product"] == product and e["enterprise"] and e["enabled"]]
        if not on:
            continue
        free = _handle(std, product, "no-subscription")
        if not free:
            continue  # this Proxmox does not offer one for it: leave it as it is
        if std.get(free) is None:
            plan.append(("add", free))
        elif std.get(free) is False:
            off = next((e for e in all_repos if e["product"] == product and not e["enterprise"] and not e["enabled"]
                        and any("no-subscription" in u or "download.proxmox.com" in u for u in e["uris"])), None)
            plan.append(("enable", off["path"], off["index"]) if off else ("add", free))
        plan += [("disable", e["path"], e["index"]) for e in on]
    return plan


def switch_to_no_subscription(pve, node: str) -> list[str]:
    """Carries out plan_no_subscription on the host: the free repositories first (added, or switched on), then —
    read afresh, as an addition can move the others within their file — the enterprise ones off, only of the products
    that just got their free one (never a product left with no source). Returns what was done, in words."""
    info = pve.apt_repositories(node)
    by_place = {(e["path"], e["index"]): e for e in entries(info)}
    done, switched = [], set()
    for step in plan_no_subscription(info):
        if step[0] == "add":
            pve.add_repository(node, step[1])
            switched.add("ceph" if step[1].startswith("ceph-") else "pve")
            done.append(f"added {step[1]}")
        elif step[0] == "enable":
            pve.change_repository(node, step[1], step[2], True)
            switched.add(by_place[(step[1], step[2])]["product"])
            done.append(f"switched on {step[1]}")
    for e in entries(pve.apt_repositories(node)) if switched else []:
        if e["enterprise"] and e["enabled"] and e["product"] in switched:
            pve.change_repository(node, e["path"], e["index"], False)
            done.append(f"switched off the {'Proxmox' if e['product'] == 'pve' else 'Ceph'} enterprise repository")
    return done
