"""A pretend console: the server side of VNC over WebSocket, for demo mode and the tests. It asks for the VNC password,
shows a dark screen with a cursor, and draws a small block for every key typed (a new line on Enter)."""

from __future__ import annotations

import os
import struct
import threading

from .des import vnc_response
from .websocket import WebSocket

BG, FG, CURSOR = (0x1E, 0x1E, 0x24), (0xC8, 0xC8, 0xD0), (0x3F, 0xB9, 0x50)
CELL_W, CELL_H, MARGIN = 9, 16, 12


def _pixels(w: int, h: int, rgb: tuple) -> bytes:
    r, g, b = rgb
    return bytes((b, g, r, 0)) * (w * h)


class FakeVncServer:
    def __init__(self, ws: WebSocket, password: str, width: int = 720, height: int = 400, name: str = "demo",
                 ext_keys: bool = True):
        self.ws, self.password, self.width, self.height, self.name = ws, password, width, height, name
        self.offer_ext_keys = ext_keys
        self.buf = bytearray()
        self.keys: list[tuple] = []       # ("sym", down, keysym) or ("qnum", down, keysym, qnum)
        self.pointer: list[tuple] = []    # (buttons, x, y)
        self.client_ext_keys = False
        self.client_cursor = False
        self.authenticated = threading.Event()
        self.col = self.row = 0
        self.dirty: list[tuple] = []      # rectangles to send: (x, y, w, h, rgb)
        self.wants_update = False
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def start(self) -> "FakeVncServer":
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    # -- stream --------------------------------------------------------------------------------------

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            message = self.ws.recv()
            if message is None:
                raise ConnectionError
            self.buf += message
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def _send(self, data: bytes) -> None:
        self.ws.send(data)

    # -- protocol ------------------------------------------------------------------------------------

    def serve(self) -> None:
        try:
            self._serve()
        except (ConnectionError, OSError, struct.error):
            pass
        finally:
            try:
                self.ws.close()
            except OSError:
                pass

    def _serve(self) -> None:
        self._send(b"RFB 003.008\n")
        self._read(12)
        self._send(bytes([1, 2]))  # one security type: VNC authentication
        if self._read(1)[0] != 2:
            return
        challenge = os.urandom(16)
        self._send(challenge)
        if self._read(16) != vnc_response(self.password, challenge):
            reason = b"Authentication failed"
            self._send(struct.pack(">I", 1) + struct.pack(">I", len(reason)) + reason)
            return
        self._send(struct.pack(">I", 0))
        self.authenticated.set()
        self._read(1)  # ClientInit
        name = self.name.encode()
        self._send(struct.pack(">HH", self.width, self.height) + bytes(16) + struct.pack(">I", len(name)) + name)
        first = True
        while True:
            kind = self._read(1)[0]
            if kind == 0:      # SetPixelFormat
                self._read(19)
            elif kind == 2:    # SetEncodings
                self._read(1)
                count = int.from_bytes(self._read(2), "big")
                encodings = struct.unpack(f">{count}i", self._read(4 * count))
                self.client_ext_keys = -258 in encodings
                self.client_cursor = -239 in encodings
            elif kind == 3:    # FramebufferUpdateRequest
                incremental = self._read(9)[0]
                if first or not incremental:
                    first = False
                    self._full_screen()
                else:
                    with self.lock:
                        self.wants_update = True
                    self._flush()
            elif kind == 4:    # KeyEvent
                down, keysym = struct.unpack(">B2xI", self._read(7))
                self.keys.append(("sym", bool(down), keysym))
                self._typed(bool(down), keysym)
            elif kind == 5:    # PointerEvent
                self.pointer.append(struct.unpack(">BHH", self._read(5)))
            elif kind == 6:    # ClientCutText
                self._read(3)
                self._read(int.from_bytes(self._read(4), "big"))
            elif kind == 255:  # QEMU: extended key event
                sub, down, keysym, qnum = struct.unpack(">BHII", self._read(11))
                self.keys.append(("qnum", bool(down), keysym, qnum))
                self._typed(bool(down), keysym)
            else:
                return

    def _full_screen(self) -> None:
        rects = [struct.pack(">HHHHi", 0, 0, self.width, self.height, 0) + _pixels(self.width, self.height, BG)]
        cx, cy = self._cursor_xy()
        rects.append(struct.pack(">HHHHi", cx, cy, CELL_W - 1, CELL_H - 2, 0) + _pixels(CELL_W - 1, CELL_H - 2, CURSOR))
        if self.offer_ext_keys and self.client_ext_keys:
            rects.append(struct.pack(">HHHHi", 0, 0, 0, 0, -258))
        if self.client_cursor:  # an 8 × 8 white triangle, hot spot at its tip, like a tiny arrow
            mask = bytes(0xFF << (8 - (y + 1)) & 0xFF for y in range(8))
            rects.append(struct.pack(">HHHHi", 0, 0, 8, 8, -239) + _pixels(8, 8, (255, 255, 255)) + mask)
        self._send(struct.pack(">BxH", 0, len(rects)) + b"".join(rects))

    def _cursor_xy(self) -> tuple[int, int]:
        return MARGIN + self.col * CELL_W, MARGIN + self.row * CELL_H

    def _typed(self, down: bool, keysym: int) -> None:
        if not down:
            return
        x, y = self._cursor_xy()
        with self.lock:
            if keysym in (0xFF0D, 0xFF8D):  # Enter
                self.dirty.append((x, y, CELL_W - 1, CELL_H - 2, BG))
                self.col, self.row = 0, self.row + 1
            elif 0x20 < keysym < 0xFF or keysym > 0x1000000:  # a printable character
                self.dirty.append((x, y, CELL_W - 1, CELL_H - 2, FG))
                self.col += 1
            else:
                return
            if MARGIN + (self.col + 1) * CELL_W > self.width:
                self.col, self.row = 0, self.row + 1
            if MARGIN + (self.row + 1) * CELL_H > self.height:
                self.row = 0
            nx, ny = self._cursor_xy()
            self.dirty.append((nx, ny, CELL_W - 1, CELL_H - 2, CURSOR))
        self._flush()

    def _flush(self) -> None:
        with self.lock:
            if not (self.wants_update and self.dirty):
                return
            rects, self.dirty, self.wants_update = self.dirty, [], False
        self._send(struct.pack(">BxH", 0, len(rects)) +
                   b"".join(struct.pack(">HHHHi", x, y, w, h, 0) + _pixels(w, h, rgb) for x, y, w, h, rgb in rects))
