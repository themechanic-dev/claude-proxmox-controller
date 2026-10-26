"""Wake-on-LAN: the "magic packet" that wakes a computer whose network card listens while it is off.

The packet is 6 bytes of 0xFF followed by the target's MAC address 16 times, sent as a UDP broadcast.
It works on the local network only (routers do not forward broadcasts), and the computer must have
Wake-on-LAN turned on in its BIOS/UEFI and on its network card.
"""

from __future__ import annotations

import re
import socket

PORTS = (9, 7)  # the two customary ports; sending to both costs nothing
_MAC = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}$", re.IGNORECASE)


def normalize_mac(mac: str) -> str:
    """'A0-B1-C2-D3-E4-F5' / 'a0b1c2d3e4f5' / 'a0:b1:c2:d3:e4:f5' → 'a0:b1:c2:d3:e4:f5'. ValueError if not a MAC."""
    text = mac.strip()
    if not _MAC.match(text):
        raise ValueError(f"not a MAC address: {mac!r}")
    hexdigits = re.sub(r"[:-]", "", text).lower()
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2))


def magic_packet(mac: str) -> bytes:
    raw = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    return b"\xff" * 6 + raw * 16


def send(mac: str, broadcast: str = "255.255.255.255", ports: tuple[int, ...] = PORTS, repeat: int = 3) -> int:
    """Send the magic packet `repeat` times to each port. Returns the number of datagrams sent."""
    packet = magic_packet(mac)
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(repeat):
            for port in ports:
                sock.sendto(packet, (broadcast, port))
                sent += 1
    return sent
