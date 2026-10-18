"""This computer's ARP table: the MAC address behind an IP, and the other way round.

After any traffic to a machine (for example opening its web page), the operating system remembers the MAC
address that answered for its IP. That gives a host's MAC for Wake-on-LAN without logging in to it, and the
IP of a VM that has no QEMU guest agent to report it. Works on Linux (`ip neigh`, /proc/net/arp) and Windows
(`arp -a`).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys

from . import procs

_MAC = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.IGNORECASE)


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def mac_for(host: str) -> str | None:
    """The MAC address this computer last saw for `host` (IP or name), or None."""
    ip = resolve(host)
    if not ip:
        return None
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    for line in _neighbour_lines():
        fields = line.split()
        if ip in fields:
            m = _MAC.search(line)
            if m and m.group(0).lower() not in ("00:00:00:00:00:00", "00-00-00-00-00-00"):
                return m.group(0).replace("-", ":").lower()
    return None


def normalize_mac(text: str) -> str:
    return text.replace("-", ":").lower()


def ips_for_macs(macs: list[str], lines: list[str] | None = None) -> list[str]:
    """IPv4 addresses this computer has seen answering for any of `macs`, in the order of `macs`."""
    wanted = [normalize_mac(m) for m in macs if m]
    found: dict[str, list[str]] = {m: [] for m in wanted}
    for line in _neighbour_lines() if lines is None else lines:
        m = _MAC.search(line)
        if not m or normalize_mac(m.group(0)) not in found:
            continue
        for field in line.split():
            try:
                ip = str(ipaddress.IPv4Address(field))
            except ValueError:
                continue
            if ip not in found[normalize_mac(m.group(0))]:
                found[normalize_mac(m.group(0))].append(ip)
            break
    return [ip for mac in wanted for ip in found[mac]]


def neighbour_lines() -> list[str]:
    """The raw table, read once so several lookups can share it."""
    return _neighbour_lines()


def _neighbour_lines() -> list[str]:
    commands = [["arp", "-a"]] if sys.platform.startswith("win") else [["ip", "neigh"], ["arp", "-an"]]
    for cmd in commands:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5, **procs.hidden()).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if out.strip():
            return [ln.replace("(", " ").replace(")", " ") for ln in out.splitlines()]
    try:
        with open("/proc/net/arp", encoding="ascii") as fh:
            return fh.read().splitlines()[1:]
    except OSError:
        return []
