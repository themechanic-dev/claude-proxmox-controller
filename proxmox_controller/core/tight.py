"""Tight, the VNC picture encoding QEMU offers next to Raw: solid fills, small palettes and zlib for the parts of a
screen with few colours, and JPEG for the rest. A full 1920×1080 screen in Raw is 8 MB; in Tight it is a small part
of that — what lets a console be recorded as a video.

Pixels come as TPIXELs (red, green, blue: three bytes) because the client asks for 32-bit, depth-24 true colour, and
leave here as the client's own 32-bit pixels: blue, green, red, 255 (QImage's Format_RGB32 byte order)."""

from __future__ import annotations

import zlib
from typing import Callable

ENC_TIGHT = 7
JPEG_QUALITY_0 = -32       # pseudo-encodings -32…-23: JPEG quality 0…9
COMPRESS_LEVEL_0 = -256    # pseudo-encodings -256…-247: zlib level 0…9

FILL, JPEG, PNG = 0x08, 0x09, 0x0A
COPY, PALETTE, GRADIENT = 0, 1, 2
MIN_TO_COMPRESS = 12       # smaller data comes as it is, without zlib

_BITS = [bytes((v >> (7 - i)) & 1 for i in range(8)) for v in range(256)]  # a byte of a 2-colour row → 8 indices


class TightError(Exception):
    pass


def bgrx_from_rgb(rgb: bytes | bytearray) -> bytes:
    """TPIXELs (r, g, b) → 32-bit pixels (b, g, r, 255)."""
    n = len(rgb) // 3
    out = bytearray(b"\xff" * (n * 4))
    out[0::4] = rgb[2::3]
    out[1::4] = rgb[1::3]
    out[2::4] = rgb[0::3]
    return bytes(out)


def bgrx_from_indices(indices: bytes, palette: bytes) -> bytes:
    """One byte a pixel, each an index into the palette (TPIXELs) → 32-bit pixels."""
    tables = []
    for channel in (2, 1, 0):  # blue, green, red
        values = bytes(palette[i * 3 + channel] for i in range(len(palette) // 3))
        tables.append(values + bytes(256 - len(values)))
    n = len(indices)
    out = bytearray(b"\xff" * (n * 4))
    for k, table in enumerate(tables):
        out[k::4] = indices.translate(table)
    return bytes(out)


def _gradient(data: bytes, w: int, h: int) -> bytes:
    """The gradient filter: each component is sent as its difference from left + above − above-left."""
    out = bytearray(len(data))
    row = w * 3
    for y in range(h):
        for x in range(w):
            for c in range(3):
                i = y * row + x * 3 + c
                left = out[i - 3] if x else 0
                up = out[i - row] if y else 0
                up_left = out[i - row - 3] if x and y else 0
                pred = min(255, max(0, left + up - up_left))
                out[i] = (pred + data[i]) & 0xFF
    return bytes(out)


class TightDecoder:
    """Keeps the four zlib streams a Tight connection shares across its updates."""

    def __init__(self, decode_jpeg: Callable[[bytes, int, int], bytes]):
        self.streams = [zlib.decompressobj() for _ in range(4)]
        self.decode_jpeg = decode_jpeg  # (jpeg, w, h) → 32-bit pixels b, g, r, 255
        self.counts: dict[str, int] = {}  # rectangles of each kind so far (what the server chose to send)

    def _count(self, kind: str) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + 1

    @staticmethod
    def _length(read: Callable[[int], bytes]) -> int:
        """Tight's compact length: one to three bytes, seven bits each, low bits first."""
        n = 0
        for shift in (0, 7, 14):
            b = read(1)[0]
            n |= (b & (0x7F if shift < 14 else 0xFF)) << shift
            if not b & 0x80 or shift == 14:
                break
        return n

    def _data(self, read: Callable[[int], bytes], size: int, stream: int) -> bytes:
        if size < MIN_TO_COMPRESS:
            return read(size)
        data = self.streams[stream].decompress(read(self._length(read)))
        if len(data) != size:
            raise TightError(f"A Tight rectangle came with {len(data)} bytes instead of {size}.")
        return data

    def rect(self, read: Callable[[int], bytes], w: int, h: int) -> bytes:
        """One rectangle's 32-bit pixels, reading what it needs from the stream."""
        control = read(1)[0]
        for i in range(4):
            if control & (1 << i):
                self.streams[i] = zlib.decompressobj()
        kind = control >> 4
        if kind == FILL:
            self._count("fill")
            r, g, b = read(3)
            return bytes((b, g, r, 255)) * (w * h)
        if kind == JPEG:
            self._count("jpeg")
            return self.decode_jpeg(read(self._length(read)), w, h)
        if kind > JPEG:
            raise TightError(f"Tight sent a compression this app did not ask for ({kind}).")
        stream = kind & 0x03
        filt = read(1)[0] if kind & 0x04 else COPY
        if filt == COPY:
            self._count("copy")
            return bgrx_from_rgb(self._data(read, w * h * 3, stream))
        if filt == GRADIENT:
            self._count("gradient")
            return bgrx_from_rgb(_gradient(self._data(read, w * h * 3, stream), w, h))
        if filt != PALETTE:
            raise TightError(f"Tight sent a filter this app does not know ({filt}).")
        colours = read(1)[0] + 1
        self._count("palette2" if colours == 2 else "palette")
        palette = read(colours * 3)
        if colours == 2:
            row = (w + 7) // 8
            packed = self._data(read, row * h, stream)
            indices = b"".join(b"".join(_BITS[v] for v in packed[y * row:(y + 1) * row])[:w] for y in range(h))
        else:
            indices = self._data(read, w * h, stream)
        return bgrx_from_indices(indices, palette)
