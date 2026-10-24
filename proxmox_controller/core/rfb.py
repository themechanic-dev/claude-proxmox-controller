"""The VNC protocol (RFB 3.3–3.8), client side, enough for a Proxmox console: VNC authentication, a 32-bit true-colour
screen with Raw and CopyRect updates, resolution changes, keys and the mouse.

Keys travel as physical key codes (QEMU's extended key event) when the server offers it, so the layout chosen on
this computer (Greek, English…) does not matter — the guest applies its own. Containers (vncterm) get key symbols.
"""

from __future__ import annotations

import struct

from .des import vnc_response
from .websocket import WebSocket

ENC_RAW, ENC_COPYRECT, ENC_DESKTOP_SIZE, ENC_CURSOR, ENC_QEMU_EXT_KEY = 0, 1, -223, -239, -258

# Linux input codes (evdev) → QEMU key numbers (PC/XT scan codes; 0x80 marks the E0-prefixed keys).
# Codes 1–88 are the same in both; the rest are the extended keys.
_EVDEV_EXTENDED = {
    96: 0x9C, 97: 0x9D, 98: 0xB5, 99: 0xB7, 100: 0xB8, 102: 0xC7, 103: 0xC8, 104: 0xC9, 105: 0xCB,
    106: 0xCD, 107: 0xCF, 108: 0xD0, 109: 0xD1, 110: 0xD2, 111: 0xD3, 119: 0xC6, 125: 0xDB, 126: 0xDC, 127: 0xDD,
    113: 0xA0, 114: 0xAE, 115: 0xB0,  # mute, volume down, volume up
}


def qnum_from_evdev(code: int) -> int:
    if 1 <= code <= 88:
        return code
    return _EVDEV_EXTENDED.get(code, 0)


def qnum_from_windows(scancode: int) -> int:
    """Windows reports the scan code with 0x100 (or 0xE000) for the extended keys."""
    base = scancode & 0x7F
    return base | 0x80 if scancode & 0xFF00 else base


# The keys of Ctrl+Alt+Delete: (keysym, qnum)
CTRL_ALT_DEL = ((0xFFE3, 0x1D), (0xFFE9, 0x38), (0xFFFF, 0xD3))


def opaque(pixels: bytes) -> bytes:
    """32-bit pixels with their unused fourth byte set to 255. QEMU sends 0 there, and Qt reads that byte as alpha:
    the console turned see-through, which GNOME showed as a white window (measured, 13/10/2026)."""
    buf = bytearray(pixels)
    buf[3::4] = b"\xff" * (len(buf) // 4)
    return bytes(buf)


def cursor_argb(pixels: bytes, mask: bytes, w: int, h: int) -> bytes:
    """The pointer's pixels with alpha from its bitmask (one bit per pixel, a row is padded to whole bytes)."""
    out = bytearray(pixels)
    row = (w + 7) // 8
    for y in range(h):
        for x in range(w):
            on = mask[y * row + x // 8] & (0x80 >> (x % 8))
            out[(y * w + x) * 4 + 3] = 0xFF if on else 0
            if not on:  # premultiplied by a zero alpha: the colour must be zero too
                out[(y * w + x) * 4:(y * w + x) * 4 + 3] = b"\0\0\0"
    return bytes(out)


class RfbError(Exception):
    pass


class RfbClient:
    def __init__(self, ws: WebSocket, password: str = ""):
        self.ws = ws
        self.password = password
        self.buf = bytearray()
        self.width = self.height = 0
        self.name = ""
        self.ext_keys = False  # the server takes physical key codes

    # -- the stream on top of WebSocket messages ---------------------------------------------------

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            message = self.ws.recv()
            if message is None:
                raise ConnectionError("The console was closed.")
            self.buf += message
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def _send(self, data: bytes) -> None:
        self.ws.send(data)

    def _reason(self) -> str:
        n = int.from_bytes(self._read(4), "big")
        return self._read(n).decode("utf-8", "replace")

    # -- opening -----------------------------------------------------------------------------------

    def handshake(self) -> tuple[int, int, str]:
        version = self._read(12)
        if not version.startswith(b"RFB "):
            raise RfbError("This is not a VNC console.")
        major, minor = int(version[4:7]), int(version[8:11])
        minor = 8 if (major, minor) >= (3, 8) else 7 if (major, minor) >= (3, 7) else 3
        self._send(b"RFB 003.%03d\n" % minor)
        if minor >= 7:
            count = self._read(1)[0]
            if count == 0:
                raise RfbError(self._reason())
            offered = self._read(count)
            if 2 in offered and self.password:
                chosen = 2
            elif 1 in offered:
                chosen = 1
            else:
                raise RfbError(f"The console wants a sign-in this app does not know (types {list(offered)}).")
            self._send(bytes([chosen]))
        else:
            chosen = int.from_bytes(self._read(4), "big")
            if chosen == 0:
                raise RfbError(self._reason())
        if chosen == 2:
            self._send(vnc_response(self.password, self._read(16)))
        if chosen == 2 or minor >= 8:
            if int.from_bytes(self._read(4), "big") != 0:
                raise RfbError(self._reason() if minor >= 8 else "The console refused the password.")
        self._send(b"\x01")  # ClientInit: share the screen with other viewers
        self.width, self.height = struct.unpack(">HH", self._read(4))
        self._read(16)  # the server's pixel format: replaced below
        self.name = self._read(int.from_bytes(self._read(4), "big")).decode("utf-8", "replace")
        # 32-bit little-endian 0x00RRGGBB — the byte order of a QImage in Format_RGB32
        self._send(struct.pack(">B3xBBBBHHHBBB3x", 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
        encodings = (ENC_COPYRECT, ENC_RAW, ENC_DESKTOP_SIZE, ENC_CURSOR, ENC_QEMU_EXT_KEY)
        self._send(struct.pack(">BxH", 2, len(encodings)) + b"".join(struct.pack(">i", e) for e in encodings))
        self.request_update(incremental=False)
        return self.width, self.height, self.name

    # -- the screen --------------------------------------------------------------------------------

    def request_update(self, incremental: bool = True, height: int | None = None) -> None:
        """Asks for the screen — or only its top `height` rows (a part watched often, cheaply)."""
        rows = self.height if height is None else max(1, min(int(height), self.height))
        self._send(struct.pack(">BBHHHH", 3, 1 if incremental else 0, 0, 0, self.width, rows))

    def next_update(self) -> list[tuple]:
        """Waits for the next screen update and returns its pieces:
        ("raw", x, y, w, h, bytes) · ("copy", src_x, src_y, x, y, w, h) · ("size", w, h) · ("bell",) · ("cut", text)
        · ("cursor", hot_x, hot_y, w, h, argb) — the guest's mouse pointer as 32-bit pixels with real alpha
          (w = h = 0: the guest shows no pointer)"""
        while True:
            kind = self._read(1)[0]
            if kind == 0:
                self._read(1)
                ops = []
                for _ in range(int.from_bytes(self._read(2), "big")):
                    x, y, w, h, enc = struct.unpack(">HHHHi", self._read(12))
                    if enc == ENC_RAW:
                        ops.append(("raw", x, y, w, h, opaque(self._read(w * h * 4))))
                    elif enc == ENC_COPYRECT:
                        sx, sy = struct.unpack(">HH", self._read(4))
                        ops.append(("copy", sx, sy, x, y, w, h))
                    elif enc == ENC_DESKTOP_SIZE:
                        self.width, self.height = w, h
                        ops.append(("size", w, h))
                    elif enc == ENC_CURSOR:
                        pixels = self._read(w * h * 4)
                        mask = self._read((w + 7) // 8 * h)
                        ops.append(("cursor", x, y, w, h, cursor_argb(pixels, mask, w, h)))
                    elif enc == ENC_QEMU_EXT_KEY:
                        self.ext_keys = True
                    else:
                        raise RfbError(f"The console sent a picture format this app does not know ({enc}).")
                self.request_update(incremental=True)
                return ops
            if kind == 1:  # colour map entries: unused with true colour
                self._read(1)
                _first, count = struct.unpack(">HH", self._read(4))
                self._read(count * 6)
            elif kind == 2:
                return [("bell",)]
            elif kind == 3:
                self._read(3)
                return [("cut", self._read(int.from_bytes(self._read(4), "big")).decode("latin-1"))]
            else:
                raise RfbError(f"The console sent a message this app does not know ({kind}).")

    # -- keys and the mouse ------------------------------------------------------------------------

    def key(self, down: bool, keysym: int, qnum: int = 0) -> None:
        if self.ext_keys and qnum:
            self._send(struct.pack(">BBHII", 255, 0, 1 if down else 0, keysym & 0xFFFFFFFF, qnum))
        elif keysym:
            self._send(struct.pack(">BBxxI", 4, 1 if down else 0, keysym & 0xFFFFFFFF))

    def pointer(self, buttons: int, x: int, y: int) -> None:
        self._send(struct.pack(">BBHH", 5, buttons & 0xFF, max(0, x), max(0, y)))

    def ctrl_alt_del(self) -> None:
        for keysym, qnum in CTRL_ALT_DEL:
            self.key(True, keysym, qnum)
        for keysym, qnum in reversed(CTRL_ALT_DEL):
            self.key(False, keysym, qnum)
