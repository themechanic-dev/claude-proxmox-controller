"""An Ubuntu Server that installs itself from its own ISO: the answers its installer (Subiquity) takes from a
"cidata" disc beside the ISO — autoinstall — and the one question it still asks.

Measured on the 26.04 live-server ISO (25/10, test VM 108): GRUB shows its one entry ~6 s after the start and boots it
after 30 s; the installer reads the disc by itself, then stops ~2½ minutes after the start at "Continue with
autoinstall? (yes|no)" — a confirmation it asks unless the word autoinstall is on the kernel's command line, which
only typing in GRUB's menu could put there. The question waits for good, so the app watches the console and types yes
itself (the user's choice, 25/10: no key in GRUB; like Windows' boot question, the app's own keys, without asking).
Then ~11 minutes: the disk, the system, the QEMU guest agent, OpenSSH, the security updates (the longest part), and a
restart into the installed system, without a "remove the installation medium" question. The installed system turns
cloud-init off after its first boot, so the disc is not read again; the app takes it away once the agent answers
(core/setupdisc.py)."""

from __future__ import annotations

import json
import re
import time

from . import cloudseed, screen, store
from .pve import Pve

# the live-server ISOs from 24.04 on (the release that asks the question; 26.04 measured, 24.04 not yet)
ISO = re.compile(r"ubuntu-(\d\d)\.\d\d(\.\d+)?-live-server-amd64[^/]*\.iso$", re.IGNORECASE)
ANSWER = ("y", "e", "s", "enter")
QUESTION_WAIT_S = 900  # it came ~2½ minutes after the start on the user's host
# Ubuntu's own LVM layout leaves about half the disk outside the system (measured: 10 of 18 GB): all of it, the user's
# choice (25/10)
STORAGE = {"layout": {"name": "lvm", "sizing-policy": "all"}}


def is_server_iso(volid: str) -> bool:
    m = ISO.search(volid or "")
    return bool(m) and int(m.group(1)) >= 24


def user_data(*, vm_name: str, user: str, password: str, ssh_keys: list[str], time_zone: str = "",
              keyboard: str = "", static: dict | None = None) -> str:
    """The autoinstall: the user (the password as a SHA-512 hash; Subiquity needs one), OpenSSH with the keys given
    (password sign-in only without a key, as the installer itself does), the QEMU guest agent, the whole disk, the
    host's time zone and keyboard (after US English; the menus stay English), and the network as the ready-made
    Ubuntu has it (core/cloudseed.network_config). Written as JSON, which is YAML too."""
    if not password:
        raise ValueError("An Ubuntu that installs itself needs the user's password (sudo asks for it).")
    keys = [k.strip() for k in ssh_keys if k.strip()]
    cfg: dict = {"version": 1, "locale": "en_US.UTF-8",
                 # (one variant per layout, even empty: "us,gr" with no variants stopped the installer — "inconsistent
                 # multi-layout", the live test of 26/10)
                 "keyboard": ({"layout": f"us,{keyboard}", "variant": ",", "toggle": "alt_shift_toggle"}
                              if keyboard and keyboard != "us" else {"layout": "us", "variant": ""}),
                 "identity": {"hostname": cloudseed.hostname_of(vm_name), "realname": user, "username": user,
                              "password": cloudseed.sha512_crypt(password)},
                 "ssh": {"install-server": True, "authorized-keys": keys, "allow-pw": not keys},
                 "packages": ["qemu-guest-agent"], "storage": STORAGE,
                 "network": cloudseed.network_config(static),
                 # (merged into what the installed system's first boot runs: a clean text login there too)
                 "user-data": dict(cloudseed.QUIET_KEYS)}
    if time_zone:
        cfg["timezone"] = time_zone
    return "#cloud-config\n" + json.dumps({"autoinstall": cfg}, indent=2) + "\n"


def seed_files(*, vm_name: str, vmid: int, **settings) -> dict[str, bytes]:
    """The setup disc's files (see user_data for `settings`)."""
    return {"user-data": user_data(vm_name=vm_name, **settings).encode(),
            "meta-data": cloudseed.meta_data(vm_name, vmid).encode()}


def _blocks(w: int, h: int, bgra: bytes, wanted: int = 4) -> list[tuple[int, int]]:
    """The screen's runs of lit lines (text rows), from the bottom up: (top, bottom) — every second pixel looked at."""
    stride, out, y = w * 4, [], h - 1

    def lit(y: int) -> bool:
        return max(bgra[y * stride + 1:(y + 1) * stride:8]) > 0x60  # (green: the console's text is grey)
    while y >= 0 and len(out) < wanted:
        if lit(y):
            bottom = y
            while y >= 0 and lit(y):
                y -= 1
            out.append((y + 1, bottom))
        else:
            y -= 1
    return out


def _extent(w: int, bgra: bytes, top: int, bottom: int) -> tuple[int, int]:
    """Where a run of lines has text: its leftmost and rightmost lit pixel (every second one)."""
    stride, left, right = w * 4, w, -1
    for y in range(top, bottom + 1):
        row = bgra[y * stride + 1:(y + 1) * stride:8]
        xs = [i * 2 for i, v in enumerate(row) if v > 0x60]
        if xs:
            left, right = min(left, xs[0]), max(right, xs[-1])
    return left, right


def question_on(w: int, h: int, bgra: bytes) -> bool:
    """Whether the console shows the installer's question — known by the shape of its three lines on the text console
    (measured 25/10, 1024×768, an 8-point font): "Confirmation is required to continue." and "Add 'autoinstall' to
    your kernel command line to avoid this" one under the other, an empty gap of about three lines, then "Continue
    with autoinstall? (yes|no)" from the left edge — anywhere on the screen: the installer's network log may go on
    under it and push it up while it waits (the live test of 26/10: the last line for three seconds only, then
    missed). Not the shape of GRUB's menu (720×400 text mode, long lines in from the edge), the log as it scrolls (no
    gap), the installer starting (nothing above), its error (no gap), nor the installed system's login."""
    if w < 640 or h < 480 or len(bgra) < w * h * 4:
        return False
    rows = list(reversed(_blocks(w, h, bgra, wanted=h)))  # every line of text, top down
    for i in range(2, len(rows)):
        (top, bottom), (above_top, above), (first_top, first) = rows[i], rows[i - 1], rows[i - 2]
        if top - above - 1 < 28 or not 8 <= bottom - top + 1 <= 20 or above_top - first - 1 > 8:
            continue  # (cheap first: the gap, the line's height, the two lines above one under the other)
        left, right = _extent(w, bgra, top, bottom)
        if left > 16 or not 210 <= right <= 350:  # "Continue with autoinstall? (yes|no)": 35 characters
            continue
        if 350 <= _extent(w, bgra, above_top, above)[1] <= 590 and 220 <= _extent(w, bgra, first_top, first)[1] <= 370:
            return True  # (59 and 37 characters)
    return False


def answer_question(pve: Pve, node: str, vmid: int, timeout: float | None = None) -> bool:
    """Types yes at the installer's question of a VM just started from an Ubuntu Server ISO with its autoinstall disc
    (screen.answer_prompt). The whole screen is asked for every second: where the question shows depends on how much
    log came before, and more may come after it. True when it was answered; what was seen goes to
    boot-prompt.log in the app's data folder (the last watch only)."""
    path = store.data_dir() / "boot-prompt.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        out = open(path, "w", encoding="utf-8")
    except OSError:
        out = None

    def log(line: str) -> None:
        if out is not None:
            out.write(f"{time.strftime('%H:%M:%S')} VM {vmid}: {line}\n")
            out.flush()

    try:
        # yes half a second after the question shows (its input() reads the keyboard from the moment it is
        # printed), again only if it still stands two minutes on; the screen asked for every second
        return screen.answer_prompt(lambda: pve.open_vnc(node, "qemu", vmid), question_on, ANSWER,
                                    QUESTION_WAIT_S if timeout is None else timeout, quiet=20.0, refresh=1.0,
                                    first_after=0.5, again_after=120.0, settle=10.0, log=log)
    finally:
        if out is not None:
            out.close()
