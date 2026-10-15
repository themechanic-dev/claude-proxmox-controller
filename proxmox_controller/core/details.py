"""What the guest list does not carry: each guest's notes, MAC and IPv4 addresses, and whether it starts at boot."""

from __future__ import annotations

from . import netinfo
from .pve import Pve, PveError, agent_enabled, guest_macs


def read_details(pve: Pve, guests: list[dict]) -> dict[int, dict]:
    """Notes, MAC addresses and IPv4 addresses of every guest. Runs off the window's thread.

    Containers report their addresses themselves; VMs through the QEMU guest agent. A running VM without a
    (working) agent is looked up by its MAC address in this computer's ARP table."""
    out: dict[int, dict] = {}
    for g in guests:
        try:
            cfg = pve.guest_config(g["node"], g["type"], g["vmid"])
        except PveError as e:
            if not e.status:  # the host itself stopped answering: the rest would only wait for timeouts
                break
            cfg = {}
        running = g.get("status") == "running"
        agent = g["type"] == "qemu" and agent_enabled(cfg)
        ips = pve.interfaces(g["node"], g["type"], g["vmid"]) if running and (g["type"] == "lxc" or agent) else []
        out[g["vmid"]] = {"notes": str(cfg.get("description") or "").strip(), "macs": guest_macs(cfg), "ips": ips,
                          "source": "guest" if ips else "", "agent": agent, "running": running,
                          "onboot": str(cfg.get("onboot", "0")) == "1", "startup": str(cfg.get("startup") or "")}
    missing = [d for d in out.values() if d["running"] and not d["ips"] and d["macs"]]
    if missing:
        lines = netinfo.neighbour_lines()  # read once for all of them
        for d in missing:
            ips = netinfo.ips_for_macs(d["macs"], lines)
            if ips:
                d.update(ips=ips, source="arp")
    return out
