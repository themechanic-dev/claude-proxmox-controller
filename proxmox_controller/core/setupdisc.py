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
        pve.wait_task(node, upid, timeout=300)
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


def boot_prompt_on(w: int, h: int, bgra: bytes) -> bool:
    """Whether the screen shows Windows' "Press any key to boot from CD or DVD": white words near the top of an
    otherwise black screen, set in from the left edge (Windows indents its question). The firmware's logo, its boot
    menu, its grey messages ("BdsDxe: No bootable option…", which come once the question is gone) and Windows' own
    screens look otherwise — and QEMU's "Guest has not initialized the display (yet)." (white, at the top of a black
    screen, before the firmware starts: the first live test took it for the question) begins at the edge. Every 4th
    pixel each way."""
    m = prompt_measure(w, h, bgra)
    return m["words"] >= 20 and m["elsewhere"] <= m["samples"] * 0.0005 and m["left"] >= w * 0.06


def prompt_measure(w: int, h: int, bgra: bytes) -> dict:
    """What boot_prompt_on decides by: white samples near the top (words) and how far left they start, and samples
    that are not black below them (elsewhere)."""
    if not w or not h or len(bgra) < w * h * 4:
        return {"words": 0, "elsewhere": 0, "samples": 1, "left": 0}
    top, step = int(h * 0.09), 4
    words = elsewhere = samples = 0
    left = w
    for y in range(0, h, step):
        row = y * w * 4
        for x in range(0, w, step):
            i = row + x * 4
            b, g, r = bgra[i], bgra[i + 1], bgra[i + 2]
            samples += 1
            if y < top:
                if min(r, g, b) >= 0xC8:
                    words += 1
                    left = min(left, x)
            elif max(r, g, b) > 0x30:
                elsewhere += 1
    return {"words": words, "elsewhere": elsewhere, "samples": samples, "left": left}


def answer_boot_prompt(pve: Pve, node: str, vmid: int, timeout: float | None = None) -> bool:
    """Presses Enter at Windows' boot question of a VM that has just been started from its installer disc, the
    moment it shows (screen.answer_prompt). True when answered. What it saw goes to boot-prompt.log in the app's
    data folder (the last watch only)."""
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

    try:
        return screen.answer_prompt(lambda: pve.open_vnc(node, "qemu", vmid), judge, ("enter",),
                                    BOOT_PROMPT_WAIT_S if timeout is None else timeout, log=log)
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
    """Empties the VM's CD drive (if it still holds the disc) and deletes the file."""
    node, vmid, volid, drive = e["node"], int(e["vmid"]), e["volid"], e["drive"]
    if exists:
        cfg = pve.guest_config(node, "qemu", vmid)
        if str(cfg.get(drive, "")).split(",")[0] == volid:
            pve.update_config(node, "qemu", vmid, {drive: "none,media=cdrom"})
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
