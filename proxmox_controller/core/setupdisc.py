"""The setup disc of a new VM — Windows' answer file (core/winsetup.py) or an Ubuntu desktop's cloud-init
(core/cloudseed.py) — from the moment it is uploaded until it is taken away again.

It holds the user's password (Windows: in its "hidden" form; Ubuntu: as a hash), so it stays on the host only while
the VM needs it: the app remembers it (settings "setup_discs") and, each time it reads the host, takes away the discs
whose VM is set up — its QEMU guest agent answers (both setups install the agent last) — or that waited long enough
(a VM without the agent: it has run READY_UPTIME_S; with it: AGENT_GIVE_UP_S), or whose VM is gone. Taking it away:
the CD drive is emptied and the file deleted, with the user's token (Claude's has no Datastore.Allocate)."""

from __future__ import annotations

import re
import secrets
import time

from . import screen, store
from .isofs import make_iso
from .pve import Pve, PveError

PREFIX = "pvc-setup-"
SLOTS = ("ide3", "ide1", "ide0", "sata5", "sata4", "sata3")  # CD drives a new VM may take: the first one free
READY_UPTIME_S = 30 * 60      # no agent will tell: by then the installer has long read the disc
AGENT_GIVE_UP_S = 3 * 3600    # the agent never answered (its install failed): the disc has done its part anyway
BOOT_PROMPT_WAIT_S = 300  # Windows' "Press any key to boot from CD or DVD…" stays ~5 s: ~55 s after a cold start on
                          # the user's host (24/10), ~10 s after a restart — watched for, not guessed


def disc_name(vmid: int) -> str:
    """A new name each time: Proxmox refuses to replace a file, and an old VM's disc may still be there."""
    return f"{PREFIX}{int(vmid)}-{secrets.token_hex(3)}.iso"


def free_slot(params: dict) -> str:
    for slot in SLOTS:
        if slot not in params:
            return slot
    raise ValueError("no free CD drive for the setup disc")


def storage_of(volid: str) -> str:
    return volid.split(":", 1)[0]


def upload(pve: Pve, node: str, storage: str, vmid: int, files: dict[str, bytes], label: str) -> str:
    """Makes the disc, puts it on `storage` (one that takes ISO images) and returns its volid."""
    name = disc_name(vmid)
    upid = pve.upload_data(node, storage, name, make_iso(files, label))
    if isinstance(upid, str) and upid.startswith("UPID:"):
        pve.wait_task(node, upid, timeout=300, poll=0.5)  # (a small file: done at once)
    return f"{storage}:iso/{name}"


def delete(pve: Pve, node: str, volid: str) -> None:
    """Deletes the disc's file; already gone is as good."""
    try:
        upid = pve.delete_volume(node, storage_of(volid), volid)
    except PveError as e:
        if "does not exist" in str(e) or e.status == 404:
            return
        raise
    if isinstance(upid, str) and upid.startswith("UPID:"):
        pve.wait_task(node, upid, timeout=120)


def entry(host_id: str, node: str, vmid: int, volid: str, drive: str, agent: bool) -> dict:
    """What the app remembers of a disc, to take it away later (agent: the setup installs the guest agent)."""
    return {"host": host_id, "node": node, "vmid": int(vmid), "volid": volid, "drive": drive, "agent": bool(agent),
            "made": int(time.time())}


QUESTION_BAND = 0.09   # Windows writes its question in the top 9% of the screen …
BELOW_BAND = 0.16      # … and the firmware its "No bootable option" lines right under it: the part watched
# Windows' question missed: the firmware's Boot Manager, then the DVD — second in its list, as the app's VMs boot their
# disk first (order=scsi0;ide2) — and Enter at once and again for a few seconds, as the user found works (24/10: the
# question comes ~2 s after the DVD is chosen and waits ~5 s)
BOOT_MANAGER_STEPS = (("enter", 0.0), ("down", 2.5), ("enter", 0.8)) + (("enter", 0.5),) * 7
KEY_PAGE_WAIT_S = 480  # Setup's product key page came ~1 min after the boot question was answered (24/10)


def prompt_measure(w: int, h: int, bgra: bytes) -> dict:
    """What the screen's top shows, every 4th pixel each way: white samples in the question's band (words) and how far
    left they start; samples under it that are not black (below), and of those the grey ones and how far left they
    start (the firmware's own messages)."""
    out = {"words": 0, "left": w, "below": 0, "grey": 0, "grey_left": w}
    if not w or not h or len(bgra) < w * h * 4:
        return out
    band, under, step = int(h * QUESTION_BAND), int(h * BELOW_BAND), 4
    for y in range(0, under, step):
        row = y * w * 4
        for x in range(0, w, step):
            i = row + x * 4
            b, g, r = bgra[i], bgra[i + 1], bgra[i + 2]
            hi, lo = max(r, g, b), min(r, g, b)
            if y < band:
                if lo >= 0xC8:
                    out["words"] += 1
                    out["left"] = min(out["left"], x)
            elif hi > 0x30:
                out["below"] += 1
                if 0x60 <= hi < 0xC8 and hi - lo < 0x20:
                    out["grey"] += 1
                    out["grey_left"] = min(out["grey_left"], x)
    return out


def boot_prompt_on(w: int, h: int, bgra: bytes) -> bool:
    """Whether the screen shows Windows' "Press any key to boot from CD or DVD": white words at the top, set in from
    the left edge (Windows indents its question), with nothing under them. Only the top of the screen counts — the
    part asked for often (the rest may be old). The firmware's logo and boot menu leave the top empty; its grey "No
    bootable option…" lines come under the question once it is gone; QEMU's "Guest has not initialized the display
    (yet)." (white, at the top, before the firmware starts — taken for the question in the first live test) begins at
    the edge."""
    m = prompt_measure(w, h, bgra)
    return m["words"] >= 20 and m["below"] <= 3 and m["left"] >= w * 0.06


def boot_prompt_missed(w: int, h: int, bgra: bytes) -> bool:
    """Whether the firmware says the question went unanswered: grey lines from the left edge under the question
    ("BdsDxe: No bootable option or device was found." / "Press any key to enter the Boot Manager Menu.")."""
    m = prompt_measure(w, h, bgra)
    return m["grey"] >= 15 and m["grey_left"] <= w * 0.02


def answer_boot_prompt(pve: Pve, node: str, vmid: int, timeout: float | None = None) -> bool:
    """Presses Enter at Windows' boot question of a VM that has just been started from its installer disc, the
    moment it shows; if it was missed, through the firmware's Boot Manager (screen.answer_prompt). Then answers
    Setup's product key page, which an answer file without a key does not skip. True when the boot question was
    answered. What it saw goes to boot-prompt.log in the app's data folder (the last watch only)."""
    path = store.data_dir() / "boot-prompt.log"
    measured: list[dict] = [{}]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        out = open(path, "w", encoding="utf-8")
    except OSError:
        out = None

    def judge(w: int, h: int, bgra: bytes) -> bool:
        measured[0] = prompt_measure(w, h, bgra)
        return boot_prompt_on(w, h, bgra)

    def log(line: str) -> None:
        if out is not None:
            out.write(f"{time.strftime('%H:%M:%S')} VM {vmid}: {line}"
                      + (f"  {measured[0]}" if line.startswith("update") else "") + "\n")
            out.flush()

    def open_console():
        return pve.open_vnc(node, "qemu", vmid)

    try:
        answered = screen.answer_prompt(open_console, judge, ("enter",),
                                        BOOT_PROMPT_WAIT_S if timeout is None else timeout, top=BELOW_BAND,
                                        missed=boot_prompt_missed, recovery=BOOT_MANAGER_STEPS, log=log)
        if answered:  # then Setup's product key page, answered as the user would: "I don't have a product key"
            log("watching for Setup's product key page")
            screen.answer_prompt(open_console, product_key_page, product_key_keys, KEY_PAGE_WAIT_S, refresh=1.0,
                                 top=KEY_PAGE_ROWS, first_after=1.5, again_after=1.0, settle=8.0, log=log)
        return answered
    finally:
        if out is not None:
            out.close()


def ready(e: dict, g: dict | None, agent_answers) -> bool:
    """Whether the disc can go: its VM is gone, or set up (the agent answers), or waited long enough."""
    if g is None:
        return True
    if g.get("status") != "running":
        return False
    uptime = int(g.get("uptime") or 0)
    if not e.get("agent"):
        return uptime >= READY_UPTIME_S
    return uptime >= AGENT_GIVE_UP_S or agent_answers()


def take_away(pve: Pve, e: dict, exists: bool) -> None:
    """Empties the VM's CD drive (if it still holds the disc) and deletes the file. Proxmox puts a drive it is given
    into the boot order (the first live test: order=scsi0;ide2;net0;ide3, waiting for the next start): taken out
    again, as it was."""
    node, vmid, volid, drive = e["node"], int(e["vmid"]), e["volid"], e["drive"]
    if exists:
        cfg = pve.guest_config(node, "qemu", vmid)
        if str(cfg.get(drive, "")).split(",")[0] == volid:
            pve.update_config(node, "qemu", vmid, {drive: "none,media=cdrom"})
            boot = str(pve.guest_config(node, "qemu", vmid).get("boot", ""))
            if boot.startswith("order="):
                order = [d for d in boot[len("order="):].split(";") if d]
                if drive in order:
                    pve.update_config(node, "qemu", vmid,
                                      {"boot": "order=" + ";".join(d for d in order if d != drive)})
    delete(pve, node, volid)


def tidy(pve: Pve, entries: list[dict], guests: list[dict]) -> tuple[set[str], list[str]]:
    """Takes away the discs that may go (see ready). Returns their volids and what was done, in words; a disc that
    could not be taken away now is tried again the next time."""
    by_id = {int(g["vmid"]): g for g in guests if g.get("type") == "qemu"}
    gone, said = set(), []
    for e in entries:
        g = by_id.get(int(e["vmid"]))
        try:
            if not ready(e, g, lambda: pve.agent_ping(e["node"], int(e["vmid"]))):
                continue
            take_away(pve, e, g is not None)
        except PveError:
            continue
        gone.add(e["volid"])
        name = f"VM {e['vmid']}" + (f" ({g.get('name', '')})" if g else "")
        said.append(f"{name}: setup finished — its setup disc was taken away" if g else
                    f"{name} is gone: its setup disc was deleted too")
    return gone, said


def is_setup_disc(volid: str) -> bool:
    return bool(re.search(rf"[:/]{PREFIX}\d+-[0-9a-f]+\.iso$", volid))


KEY_PAGE_ROWS = 0.45  # the part of the screen watched for Setup's product key page (its dialog's top and the field)


def product_key_page(w: int, h: int, bgra: bytes) -> bool:
    """Whether the screen shows Windows Setup's "Product key" page, which Setup shows even with an answer file when it
    names no key (measured on Windows 11 25H2, 24/10; the user wants no key in it, not even Microsoft's generic one).
    Known by its place, not its words (they follow the ISO's language): the white dialog on Setup's purple and, in
    it, the one-line field the key goes in — its top and bottom border, two rows across the field's width about 20
    rows apart. Only the top KEY_PAGE_ROWS of the screen are looked at."""
    if w < 800 or h < 600 or len(bgra) < w * h * 4:
        return False

    def at(x: int, y: int) -> tuple[int, int, int]:
        i = (y * w + x) * 4
        return bgra[i + 2], bgra[i + 1], bgra[i]

    r, g, b = at(8, int(h * 0.3))  # beside the dialog: Setup's purple
    if not (r < 60 and g < 30 and 60 <= b <= 120):
        return False
    limit = int(h * KEY_PAGE_ROWS)
    # the dialog's body: white for rows on end (its frame has a white edge of one row above the title bar)
    top = next((y for y in range(int(h * 0.05), limit) if all(min(at(w // 2, y + k)) >= 0xF0 for k in range(6))),
               None)
    if top is None:
        return False
    left = next((x for x in range(0, w // 2) if min(at(x, top + 60)) >= 0xF0), None)
    if left is None:
        return False
    x0, x1 = left + 42, left + 392
    if x1 >= w:
        return False
    span = len(range(x0, x1, 2))
    borders = [y for y in range(top + 140, min(top + 185, limit))
               if sum(1 for x in range(x0, x1, 2) if min(at(x, y)) < 0xF0) >= 0.95 * span]
    return len(borders) >= 2 and 15 <= borders[-1] - borders[0] <= 25


def product_key_keys(w: int, h: int, bgra: bytes) -> tuple:
    """On the product key page: Tab while the key field has the focus (its bottom border blue), then Enter on what
    has it next — "I don't have a product key" (the border grey). Looking first, each time: a Tab pressed again blind
    would move on to "Privacy statement"."""
    limit = int(h * KEY_PAGE_ROWS)

    def at(x: int, y: int) -> tuple[int, int, int]:
        i = (y * w + x) * 4
        return bgra[i + 2], bgra[i + 1], bgra[i]

    top = next((y for y in range(int(h * 0.05), limit) if all(min(at(w // 2, y + k)) >= 0xF0 for k in range(6))), 0)
    left = next((x for x in range(0, w // 2) if min(at(x, top + 60)) >= 0xF0), 0)
    x = left + 210
    bottom = [at(x, y) for y in range(top + 160, min(top + 185, limit)) if min(at(x, y)) < 0xF0]
    focused = any(b > 150 and r < 60 for r, g, b in bottom)
    return ("tab",) if focused else ("enter",)
