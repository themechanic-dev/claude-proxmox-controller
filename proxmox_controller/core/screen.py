"""A guest's screen for the connector: one picture of it (PNG), keys typed into it and clicks on it, through the same
VNC console the app shows. Plain Python: no window is involved."""

from __future__ import annotations

import math
import socket
import struct
import threading
import time
import zlib
from typing import Callable

from .rfb import RfbClient, RfbError, qnum_from_evdev

MAX_WIDTH = 1280  # wider screens are halved (or more): enough to read, and lighter for Claude to look at
KEY_GAP_S = 0.012  # between keys, so a busy guest misses none
KEY_HOLD_S = 0.08  # a key held as a hand holds it: answer_prompt's keys (Windows' boot question took no shorter one)
# Linux input codes of the keys answer_prompt may press, for their keyboard scan codes (QEMU's extended key event):
# sent as the built-in console sends a key typed by the user — which Windows' boot question took, when a key sent by
# its keysym alone, with no hold, was ignored there (the sixth live test, 24/10)
EVDEV = {"enter": 28, "return": 28, "escape": 1, "esc": 1, "tab": 15, "space": 57, "backspace": 14,
         "up": 103, "down": 108, "left": 105, "right": 106,
         # the letters too (Ubuntu's installer is answered "yes"), in the keyboard's rows as Linux numbers them
         **{c: 16 + i for i, c in enumerate("qwertyuiop")}, **{c: 30 + i for i, c in enumerate("asdfghjkl")},
         **{c: 44 + i for i, c in enumerate("zxcvbnm")}}

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


def typable(text: str) -> tuple[str, list[str]]:
    """The text as the console types it — each line end one Enter — and the characters it cannot type, sorted: what
    a US keyboard has not (Greek, accents, emoji…), since the guest maps keys as a US keyboard by default."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text, sorted({c for c in text if c not in "\n\t" and not 0x20 <= ord(c) < 0x7F})


def type_keys(key: Callable[[bool, int], None], text: str, stop: threading.Event | None = None,
              count: Callable[[int], None] | None = None) -> int:
    """Types `text` with key(down, keysym) — Shift held where a US keyboard needs it — a key every KEY_GAP_S;
    stops before the next key once `stop` is set; `count(n)` hears how many were typed. Returns that number."""
    typed = 0
    for ch in text:
        if stop is not None and stop.is_set():
            break
        sym = keysym_of(ch)
        shift = ch in SHIFTED
        if shift:
            key(True, SHIFT)
        key(True, sym)
        key(False, sym)
        if shift:
            key(False, SHIFT)
        typed += 1
        if count is not None:
            count(typed)
        time.sleep(KEY_GAP_S)
    return typed


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
        pressed = type_keys(client.key, text)
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
                  keys: list[str] | tuple | Callable[[int, int, bytes], tuple] = ("enter",), timeout: float = 240.0,
                  quiet: float = 15.0,
                  refresh: float = 0.5, top: float | None = None,
                  missed: Callable[[int, int, bytes], bool] | None = None, recovery: tuple = (),
                  settle: float = 12.0, first_after: float = 0.8, again_after: float = 0.6,
                  log: Callable[[str], None] | None = None) -> bool:
    """Watches a guest's screen through one console connection and presses `keys` while `is_prompt(width, height,
    pixels)` finds the question on it — for a question that waits only seconds and comes after an unknown time
    (Windows' "Press any key to boot from CD or DVD": ~5 s long, ~10 s after a restart, ~55 s after a cold start on the
    user's host). Keys pressed blind before it are thrown away by the guest.

    The screen is asked for every `refresh` seconds — only its top `top` share when given (the question's part: small
    enough to ask for often) — because QEMU did not send the changes by itself (the live tests of 24/10: connected all
    along, the question came and went unseen; then seen only at its end, with a picture every 2 s).

    `missed(width, height, pixels)` recognises the screen that says the question went unanswered; then `recovery` is
    played — steps of (key, seconds to wait before it) — at most 3 times, and the question is watched for again.

    `keys` may also be chosen by the picture: keys(width, height, pixels) → the names to press now.

    The keys go `first_after` seconds after the question shows, then every `again_after` seconds while it stays:
    Windows writes the question first and throws away the keys already pressed just after (the fifth live test,
    24/10: two Enters at once, both lost) — and it may ask twice in a row, so one answer is not the end.

    True once answered: after keys (or a recovery), neither the question nor the `missed` screen for `settle` seconds.
    False if it never came within `timeout`. A console that drops (the guest restarting) or stays silent for `quiet`
    seconds is opened again. `log(line)` hears what was seen, for the app's log file."""
    def scancoded(name: str) -> list[tuple[int, int]]:
        syms = parse_combo(name)
        if len(syms) == 1 and name.lower() in EVDEV:
            return [(syms[0], qnum_from_evdev(EVDEV[name.lower()]))]
        return [(sym, 0) for sym in syms]

    combos = None if callable(keys) else [scancoded(k) for k in keys]
    steps = [(scancoded(k), wait) for k, wait in recovery]  # (every name checked before anything is pressed)
    end = time.monotonic() + timeout
    answered, recoveries, recovered_at = False, 0, 0.0
    shown_at = pressed_at = quiet_since = 0.0  # when the question showed, the keys went, the screen went quiet
    say = log or (lambda line: None)
    last_said = 0.0

    def press(client, chosen):
        for keys_ in chosen:
            for sym, qnum in keys_:
                client.key(True, sym, qnum)
            time.sleep(KEY_HOLD_S)
            for sym, qnum in reversed(keys_):
                client.key(False, sym, qnum)
            time.sleep(KEY_GAP_S)

    while time.monotonic() < end:
        ws, done = None, threading.Event()
        try:
            ws, client, w, h = _connect(open_console, quiet)
            say(f"connected: {w}×{h}")
            fb = bytearray(w * h * 4)

            def ask_again(client=client):
                while not done.wait(refresh):
                    try:
                        client.request_update(False, None if top is None else client.height * top + 1)
                    except OSError:
                        return
            threading.Thread(target=ask_again, daemon=True, name="prompt-refresh").start()
            while time.monotonic() < end:
                ops = client.next_update()
                for op in ops:
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
                now = time.monotonic()
                picture = bytes(fb)
                seen = is_prompt(w, h, picture)
                # (a recovery's own first moments may still show the screen it answers: not missed again yet)
                lost = (not seen and missed is not None and now - recovered_at > 6.0 and missed(w, h, picture))
                if seen or lost or now - last_said >= 2.0:
                    last_said = now
                    say(f"update: {w}×{h}, {len(ops)} piece(s) ({','.join(sorted({op[0] for op in ops}))}) — "
                        f"question {'SEEN' if seen else 'MISSED' if lost else 'not seen'}")
                if seen:
                    shown_at = shown_at or now
                    quiet_since = 0.0
                    if now - shown_at >= first_after and now - pressed_at >= again_after:
                        names = tuple(keys(w, h, picture)) if callable(keys) else tuple(keys)
                        press(client, combos if combos is not None else [scancoded(k) for k in names])
                        answered, pressed_at = True, now
                        say("pressed: " + ", ".join(names))
                elif lost:
                    shown_at = 0.0
                    if recoveries >= 3 or not recovery:
                        say("the question was missed, and no more tries are left")
                        return False
                    recoveries += 1
                    say(f"try {recoveries + 1}: " + ", ".join(f"{k} after {d:g} s" for k, d in recovery))
                    for syms, wait in steps:
                        time.sleep(wait)
                        press(client, [syms])
                    answered, recovered_at, quiet_since = True, time.monotonic(), time.monotonic()
                else:
                    shown_at = 0.0
                    if answered:
                        quiet_since = quiet_since or now
                        if now - quiet_since >= settle:
                            say(f"answered: no question for {settle:g} s after the keys")
                            return True
        except (socket.timeout, OSError, ConnectionError, RfbError) as e:
            say(f"console dropped ({type(e).__name__}: {e}) — opening it again")
            time.sleep(1.0)
        finally:
            done.set()
            if ws is not None:
                ws.close()
    say(f"time is up: {'answered' if answered else 'the question was never answered'}")
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
