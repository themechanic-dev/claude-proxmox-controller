"""A guest's screen for the connector: one picture of it (PNG), keys typed into it and clicks on it, through the same
VNC console the app shows. Plain Python: no window is involved."""

from __future__ import annotations

import math
import socket
import struct
import time
import zlib
from typing import Callable

from .rfb import RfbClient, RfbError

MAX_WIDTH = 1280  # wider screens are halved (or more): enough to read, and lighter for Claude to look at
KEY_GAP_S = 0.012  # between keys, so a busy guest misses none

KEYS = {"enter": 0xFF0D, "return": 0xFF0D, "tab": 0xFF09, "escape": 0xFF1B, "esc": 0xFF1B, "backspace": 0xFF08,
        "delete": 0xFFFF, "del": 0xFFFF, "insert": 0xFF63, "home": 0xFF50, "end": 0xFF57, "pageup": 0xFF55,
        "pagedown": 0xFF56, "up": 0xFF52, "down": 0xFF54, "left": 0xFF51, "right": 0xFF53, "space": 0x20,
        "ctrl": 0xFFE3, "control": 0xFFE3, "alt": 0xFFE9, "shift": 0xFFE1, "super": 0xFFEB, "win": 0xFFEB,
        "meta": 0xFFEB, **{f"f{i}": 0xFFBD + i for i in range(1, 13)}}
SHIFT = 0xFFE1
SHIFTED = set('~!@#$%^&*()_+{}|:"<>?ABCDEFGHIJKLMNOPQRSTUVWXYZ')  # on a US keyboard, as the guest's default map
BUTTONS = {"left": 1, "middle": 2, "right": 4}  # the VNC button mask
WHEEL_UP, WHEEL_DOWN = 8, 16
CLICK_GAP_S = 0.06  # between a press and its release, and between two clicks: a double click, not two


def _connect(open_console: Callable[[], tuple], timeout: float) -> tuple:
    ws, password = open_console()
    ws.sock.settimeout(timeout)  # a guest that never answers must not hold the request
    client = RfbClient(ws, password)
    w, h, _ = client.handshake()
    return ws, client, w, h


def capture(open_console: Callable[[], tuple], timeout: float = 10.0) -> tuple[int, int, bytes]:
    """(width, height, pixels): 4 bytes a pixel, blue-green-red-alpha, as the console sends them."""
    ws, client, w, h = None, None, 0, 0
    try:
        ws, client, w, h = _connect(open_console, timeout)
        fb = bytearray(w * h * 4)
        end = time.monotonic() + timeout
        while True:  # the answer to the handshake's full-screen request; again after a change of resolution
            if time.monotonic() > end:
                raise TimeoutError("The guest's screen did not arrive.")
            drawn = False
            for op in client.next_update():
                if op[0] == "size":
                    w, h = op[1], op[2]
                    fb = bytearray(w * h * 4)
                    client.request_update(incremental=False)
                    drawn = False
                    break
                if op[0] == "raw":
                    _, x, y, rw, rh, data = op
                    for row in range(rh):
                        start = ((y + row) * w + x) * 4
                        fb[start:start + rw * 4] = data[row * rw * 4:(row + 1) * rw * 4]
                    drawn = True
                elif op[0] == "copy":
                    _, sx, sy, x, y, rw, rh = op
                    rows = [bytes(fb[((sy + r) * w + sx) * 4:((sy + r) * w + sx + rw) * 4]) for r in range(rh)]
                    for r, data in enumerate(rows):
                        start = ((y + r) * w + x) * 4
                        fb[start:start + rw * 4] = data
                    drawn = True
            if drawn:
                return w, h, bytes(fb)
    except socket.timeout as e:
        raise TimeoutError("The guest's screen did not arrive.") from e
    finally:
        if ws is not None:
            ws.close()


def scale_of(w: int, max_width: int = MAX_WIDTH) -> int:
    """The whole factor png() shrinks a screen this wide by (1: not at all)."""
    step = 1
    while w // step > max_width:
        step += 1
    return step


def png(w: int, h: int, bgra: bytes, max_width: int = MAX_WIDTH) -> tuple[bytes, int, int]:
    """The picture as PNG (no alpha), scaled down by a whole factor when wider than max_width: (png, width, height)."""
    step = scale_of(w, max_width)
    if step > 1:
        pixels = memoryview(bgra).cast("I")
        rows = [pixels[y * w:(y + 1) * w:step].tobytes() for y in range(0, h, step)]
        bgra, w, h = b"".join(rows), len(range(0, w, step)), len(rows)
    rgb = bytearray(w * h * 3)
    rgb[0::3], rgb[1::3], rgb[2::3] = bgra[2::4], bgra[1::4], bgra[0::4]
    stride = w * 3
    raw = b"".join(b"\x00" + bytes(rgb[y * stride:(y + 1) * stride]) for y in range(h))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    image = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
             chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))
    return image, w, h


def keysym_of(ch: str) -> int:
    if ch == "\n":
        return KEYS["enter"]
    if ch == "\t":
        return KEYS["tab"]
    code = ord(ch)
    return code if 0x20 <= code <= 0xFF else 0x01000000 + code  # beyond Latin-1: the Unicode key symbols


def parse_combo(combo: str) -> list[int]:
    """'ctrl+alt+delete' → its key symbols, modifiers first. ValueError for a key name not known."""
    syms = []
    for part in combo.lower().replace(" ", "").split("+"):
        if part in KEYS:
            syms.append(KEYS[part])
        elif len(part) == 1:
            syms.append(ord(part))
        else:
            raise ValueError(f"Unknown key '{part}'. Known: {', '.join(sorted(KEYS))}, or a single character.")
    return syms


def send(open_console: Callable[[], tuple], text: str = "", keys: list[str] | tuple = (),
         timeout: float = 10.0) -> int:
    """Types the text, then presses each combination ('enter', 'ctrl+alt+delete', 'f2'). Returns the keys pressed."""
    combos = [parse_combo(k) for k in keys]  # every name checked before anything is typed
    ws = None
    try:
        ws, client, _, _ = _connect(open_console, timeout)
        client.next_update()  # the first screen: read, so the console is not left waiting to send it
        pressed = 0
        for ch in text:
            sym = keysym_of(ch)
            shift = ch in SHIFTED
            if shift:
                client.key(True, SHIFT)
            client.key(True, sym)
            client.key(False, sym)
            if shift:
                client.key(False, SHIFT)
            pressed += 1
            time.sleep(KEY_GAP_S)
        for syms in combos:
            for sym in syms:
                client.key(True, sym)
            for sym in reversed(syms):
                client.key(False, sym)
            pressed += 1
            time.sleep(KEY_GAP_S)
        time.sleep(0.2)  # let the last keys leave before the console closes
        return pressed
    except socket.timeout as e:
        raise TimeoutError("The guest's console did not answer.") from e
    finally:
        if ws is not None:
            ws.close()


def answer_prompt(open_console: Callable[[], tuple], is_prompt: Callable[[int, int, bytes], bool],
                  keys: list[str] | tuple = ("enter",), timeout: float = 240.0, quiet: float = 15.0) -> bool:
    """Watches a guest's screen through one console connection and presses `keys` while `is_prompt(width, height,
    pixels)` finds the question on it — for a question that waits only seconds and comes after an unknown time
    (Windows' "Press any key to boot from CD or DVD": ~10 s after a restart, ~55 s after a cold start on the user's
    host). Keys pressed blind before it are thrown away by the guest, and after it they could reach the installer.
    True once answered (the question left the screen after the keys); False if it never came within `timeout`. A
    screen that stays still for `quiet` seconds, or a console that drops (the guest restarting), is opened again."""
    combos = [parse_combo(k) for k in keys]
    end = time.monotonic() + timeout
    answered = False
    while time.monotonic() < end:
        ws = None
        try:
            ws, client, w, h = _connect(open_console, quiet)
            fb = bytearray(w * h * 4)
            while time.monotonic() < end:
                for op in client.next_update():
                    if op[0] == "size":
                        w, h = op[1], op[2]
                        fb = bytearray(w * h * 4)
                        client.request_update(incremental=False)
                    elif op[0] == "raw":
                        _, x, y, rw, rh, data = op
                        for row in range(rh):
                            start = ((y + row) * w + x) * 4
                            fb[start:start + rw * 4] = data[row * rw * 4:(row + 1) * rw * 4]
                    elif op[0] == "copy":
                        _, sx, sy, x, y, rw, rh = op
                        rows = [bytes(fb[((sy + r) * w + sx) * 4:((sy + r) * w + sx + rw) * 4]) for r in range(rh)]
                        for r, data in enumerate(rows):
                            start = ((y + r) * w + x) * 4
                            fb[start:start + rw * 4] = data
                if is_prompt(w, h, bytes(fb)):
                    for syms in combos:
                        for sym in syms:
                            client.key(True, sym)
                        for sym in reversed(syms):
                            client.key(False, sym)
                        time.sleep(KEY_GAP_S)
                    answered = True
                elif answered:
                    return True
        except (socket.timeout, OSError, ConnectionError, RfbError):
            time.sleep(1.0)  # (and opened again)
        finally:
            if ws is not None:
                ws.close()
    return answered


def mark(w: int, h: int, bgra: bytes, x: int, y: int) -> bytes:
    """The screen with a red ring and cross at (x, y), in its own pixels: where a click will land, for the user to see
    before allowing it. Thick enough to stay visible in a picture shrunk to half."""
    buf = bytearray(bgra)
    red = b"\x00\x00\xff\xff"  # blue-green-red-alpha

    def dot(px: int, py: int) -> None:
        if 0 <= px < w and 0 <= py < h:
            i = (py * w + px) * 4
            buf[i:i + 4] = red

    for r in range(16, 21):
        for step in range(0, 360, 2):
            a = math.radians(step)
            dot(round(x + r * math.cos(a)), round(y + r * math.sin(a)))
    for t in range(-12, 13):
        if abs(t) < 4:  # the very point stays clear, to show what is under it
            continue
        for d in range(-2, 3):
            dot(x + t, y + d)
            dot(x + d, y + t)
    return bytes(buf)


def click(open_console: Callable[[], tuple], x: int, y: int, button: str = "left", double: bool = False,
          scroll: int = 0, timeout: float = 10.0) -> tuple[int, int]:
    """Clicks (or turns the wheel: scroll > 0 up, < 0 down) at (x, y) of the picture capture()+png() gave — scaled back
    to the screen's own pixels. The pointer goes there first, then presses. Returns the point on the screen.
    ValueError for a point outside the screen or a button not known."""
    if button not in BUTTONS:
        raise ValueError(f"Unknown button '{button}'. Known: {', '.join(BUTTONS)}.")
    ws = None
    try:
        ws, client, w, h = _connect(open_console, timeout)
        for op in client.next_update():  # the first screen: read, and a change of resolution noted
            if op[0] == "size":
                w, h = op[1], op[2]
        step = scale_of(w)
        sx, sy = x * step, y * step
        if not (0 <= sx < w and 0 <= sy < h):
            raise ValueError(f"({x}, {y}) is outside the screen: the picture of it is "
                             f"{math.ceil(w / step)}×{math.ceil(h / step)}.")
        client.pointer(0, sx, sy)  # there first: some guests take a press only where the pointer already is
        time.sleep(CLICK_GAP_S)
        if scroll:
            wheel = WHEEL_UP if scroll > 0 else WHEEL_DOWN
            for _ in range(min(abs(scroll), 50)):
                client.pointer(wheel, sx, sy)
                client.pointer(0, sx, sy)
                time.sleep(CLICK_GAP_S)
        else:
            for _ in range(2 if double else 1):
                client.pointer(BUTTONS[button], sx, sy)
                time.sleep(CLICK_GAP_S)
                client.pointer(0, sx, sy)
                time.sleep(CLICK_GAP_S)
        time.sleep(0.2)  # let the last events leave before the console closes
        return sx, sy
    except socket.timeout as e:
        raise TimeoutError("The guest's console did not answer.") from e
    finally:
        if ws is not None:
            ws.close()
