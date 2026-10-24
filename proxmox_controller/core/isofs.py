"""A small ISO 9660 image with a Joliet tree, made in memory: a handful of files in its root folder — the answer disc a
new VM's installer reads (Windows looks for autounattend.xml on every disc, cloud-init for a disc named "cidata").

ISO 9660 alone allows only short capital names (AUTOUNAT.XML); the Joliet tree beside it keeps the real ones
(autounattend.xml, user-data), and Windows and Linux both read that one. Standard library only, as the rest of the
app: no genisoimage needed on this computer or on the host."""

from __future__ import annotations

import re
import struct
import time

SECTOR = 2048
_FIRST_FREE = 23  # sectors 0–15 system area, 16 primary, 17 Joliet, 18 terminator, 19–22 the four path tables


def _both16(n: int) -> bytes:
    return struct.pack("<H", n) + struct.pack(">H", n)


def _both32(n: int) -> bytes:
    return struct.pack("<I", n) + struct.pack(">I", n)


def _pad(text: bytes, size: int, fill: bytes = b" ") -> bytes:
    if len(text) > size:
        raise ValueError(f"too long for {size} bytes: {text!r}")
    return text + (fill * size)[:size - len(text)]


def _ucs2(text: str) -> bytes:
    return text.encode("utf-16-be")


def _record_date(t: time.struct_time) -> bytes:
    return bytes((t.tm_year - 1900, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, 0))


def _volume_date(t: time.struct_time) -> bytes:
    return time.strftime("%Y%m%d%H%M%S", t).encode() + b"00\x00"


def _record(ident: bytes, extent: int, size: int, folder: bool, t: time.struct_time) -> bytes:
    length = 33 + len(ident) + (1 - len(ident) % 2)  # padded to an even length
    rec = (bytes((length, 0)) + _both32(extent) + _both32(size) + _record_date(t) + bytes((2 if folder else 0, 0, 0))
           + _both16(1) + bytes((len(ident),)) + ident)
    return rec + b"\x00" * (length - len(rec))


def short_names(names: list[str]) -> list[str]:
    """ISO 9660 level 1 names for the primary tree: 8.3, capitals, digits and '_' — each one different."""
    out: list[str] = []
    for name in names:
        stem, _, ext = name.rpartition(".") if "." in name else (name, "", "")
        clean = lambda s, n: re.sub(r"[^A-Z0-9_]", "_", s.upper())[:n]  # noqa: E731
        base, ext = clean(stem, 8) or "FILE", clean(ext, 3)
        candidate, n = f"{base}.{ext}", 1
        while candidate in out:
            n += 1
            candidate = f"{base[:8 - len(str(n)) - 1]}_{n}.{ext}"
        out.append(candidate)
    return out


def _folder(entries: list[tuple[bytes, int, int]], own: int, t: time.struct_time) -> bytes:
    """A folder's records ('.', '..', then each file), none crossing a sector's end. Its size is known once the
    records are laid out, and '.' and '..' must state it: laid out twice."""
    def lay(size: int) -> bytes:
        out = b""
        for ident, extent, length, is_dir in [(b"\x00", own, size, True), (b"\x01", own, size, True)] + \
                [(i, e, n, False) for i, e, n in entries]:
            rec = _record(ident, extent, length, is_dir, t)
            room = SECTOR - len(out) % SECTOR
            if len(rec) > room:
                out += b"\x00" * room
            out += rec
        return out + b"\x00" * (-len(out) % SECTOR)
    return lay(len(lay(SECTOR)))


def _path_table(root: int, big_endian: bool) -> bytes:
    pack = ">" if big_endian else "<"
    return bytes((1, 0)) + struct.pack(pack + "I", root) + struct.pack(pack + "H", 1) + b"\x00\x00"


def _descriptor(kind: int, label: bytes, sectors: int, table_size: int, tables: tuple[int, int], root_rec: bytes,
                joliet: bool, t: time.struct_time) -> bytes:
    fill = _ucs2(" ") if joliet else b" "
    d = (bytes((kind,)) + b"CD001\x01\x00" + _pad(b"", 32, fill) + _pad(label, 32, fill) + b"\x00" * 8 + _both32(sectors)
         + (_pad(b"%/E", 32, b"\x00") if joliet else b"\x00" * 32)  # Joliet: UCS-2 level 3
         + _both16(1) + _both16(1) + _both16(SECTOR) + _both32(table_size)
         + struct.pack("<I", tables[0]) + b"\x00" * 4 + struct.pack(">I", tables[1]) + b"\x00" * 4
         + root_rec + _pad(b"", 128 * 4, fill) + _pad(b"", 37 * 3, fill)
         + _volume_date(t) * 2 + b"0000000000000000\x00" + _volume_date(t) + b"\x01\x00")
    return d + b"\x00" * (SECTOR - len(d))


def make_iso(files: dict[str, bytes], label: str, when: float | None = None) -> bytes:
    """An ISO image holding `files` (name → contents) in its root folder; `label` is the volume's name (cloud-init
    finds its disc by it). Names: letters, digits, '.', '-', '_' (what Proxmox, Windows and Linux all take)."""
    names = list(files)
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
            raise ValueError(f"file name {name!r}")
    if not re.fullmatch(r"[A-Za-z0-9_]{1,16}", label):
        raise ValueError(f"volume label {label!r}")
    t = time.gmtime(when if when is not None else time.time())
    shorts = short_names(names)
    # where things go: the two root folders (their size depends only on the names), then the files' data
    primary_size = len(_folder([(f"{s};1".encode(), 0, 0) for s in shorts], 0, t))
    joliet_size = len(_folder([(_ucs2(n), 0, 0) for n in names], 0, t))
    primary_at = _FIRST_FREE
    joliet_at = primary_at + primary_size // SECTOR
    at = joliet_at + joliet_size // SECTOR
    extents = []
    for name in names:
        extents.append(at)
        at += max(1, -(-len(files[name]) // SECTOR))
    total = at
    primary = _folder([(f"{s};1".encode(), e, len(files[n])) for s, e, n in zip(shorts, extents, names)], primary_at, t)
    joliet = _folder([(_ucs2(n), e, len(files[n])) for e, n in zip(extents, names)], joliet_at, t)
    pvd = _descriptor(1, label.upper().encode("ascii"), total, 10, (19, 20),
                      _record(b"\x00", primary_at, len(primary), True, t), False, t)
    svd = _descriptor(2, _ucs2(label), total, 10, (21, 22), _record(b"\x00", joliet_at, len(joliet), True, t), True, t)
    terminator = b"\xffCD001\x01" + b"\x00" * (SECTOR - 7)
    tables = b"".join(_path_table(r, big) + b"\x00" * (SECTOR - 10)
                      for r, big in ((primary_at, False), (primary_at, True), (joliet_at, False), (joliet_at, True)))
    image = b"\x00" * (16 * SECTOR) + pvd + svd + terminator + tables + primary + joliet
    for name in names:
        data = files[name]
        image += data + b"\x00" * (max(1, -(-len(data) // SECTOR)) * SECTOR - len(data))
    assert len(image) == total * SECTOR
    return image
