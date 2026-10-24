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

from .isofs import make_iso
from .pve import Pve, PveError

PREFIX = "pvc-setup-"
SLOTS = ("ide3", "ide1", "ide0", "sata5", "sata4", "sata3")  # CD drives a new VM may take: the first one free
READY_UPTIME_S = 30 * 60      # no agent will tell: by then the installer has long read the disc
AGENT_GIVE_UP_S = 3 * 3600    # the agent never answered (its install failed): the disc has done its part anyway
BOOT_KEY_S = 40               # Windows' "Press any key to boot from CD or DVD…" comes ~10 s after the start, for ~5 s
BOOT_KEY_EVERY_S = 1.0


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


def press_boot_key(pve: Pve, node: str, vmid: int, seconds: float | None = None, every: float | None = None,
                   sleep=time.sleep) -> int:
    """Presses Enter in a VM that has just started, every `every` seconds for `seconds` (BOOT_KEY_EVERY_S,
    BOOT_KEY_S): Windows' installer disc asks for a key before it boots, and without one the VM goes on to the network
    boot. Enter before or after that question does nothing (the firmware's logo, the installer loading). Returns how
    many went through."""
    seconds = BOOT_KEY_S if seconds is None else seconds
    every = BOOT_KEY_EVERY_S if every is None else every
    done, end = 0, time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            pve.send_key(node, vmid, "ret")
            done += 1
        except PveError:
            pass  # not running yet, or no longer: the next one may go through
        sleep(every)
    return done


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
