"""A VM's display, sound card and USB devices in Proxmox's own config format, read and written in one place.

    vga: qxl                                   the display (qxl = SPICE)
    tablet: 1                                  the USB tablet: an absolute pointer (clicks land where they are sent)
    audio0: device=ich9-intel-hda,driver=spice  the sound card and where its sound goes
    usb0: host=0781:5581,usb3=1                 a USB device of the host, by vendor:product (any port)
    usb1: spice                                 a slot for a USB device of the viewing computer, through SPICE
"""

from __future__ import annotations

import re

DISPLAYS = (("std", "Default"), ("qxl", "SPICE"), ("virtio", "VirtIO-GPU"))
SOUND_CARDS = (("ich9-intel-hda", "Intel HD Audio (ich9)"), ("intel-hda", "Intel HD Audio"),
               ("AC97", "AC97 (old systems)"))
SOUND_OUTPUTS = (("spice", "SPICE"), ("none", "None (silent)"))
SPICE_USB_PORTS = 2      # devices of this computer that can be handed to the VM at the same time
USB_SLOTS_OLD, USB_SLOTS = 5, 14  # Proxmox 7 allows usb0–usb4; 8 and newer usb0–usb13
# Proxmox leaves the USB tablet out with these displays unless the VM sets it (QemuServer.pm: "disable for spice because
# it is not needed" — it is, for a VNC console: without it the guest has only a relative mouse, and a click sent to a
# point lands wherever the pointer already is; Windows has no other absolute mouse, Linux has QEMU's vmmouse)
TABLET_OFF_WITH = re.compile(r"qxl[234]?|serial\d+")
_USB_KEY = re.compile(r"usb(\d+)$")


def options(text: str) -> dict:
    """'device=ich9-intel-hda,driver=spice' → {'device': …, 'driver': …}; a first value without a name is 'type'."""
    out = {}
    for i, part in enumerate(p for p in (text or "").split(",") if p):
        key, eq, value = part.partition("=")
        if eq:
            out[key.strip()] = value.strip()
        elif i == 0:
            out["type"] = key.strip()
    return out


def display_of(cfg: dict) -> str:
    vga = options(str(cfg.get("vga", "")))
    return vga.get("type", "std") or "std"


def tablet_of(cfg: dict, display: str | None = None) -> bool:
    """Whether the VM gets the USB tablet: its own setting, or else Proxmox's default for the display (`display`: the
    one it will have, if that is changing)."""
    if "tablet" in cfg:
        return str(cfg["tablet"]).strip().lower() not in ("0", "", "false", "no", "off")
    return not TABLET_OFF_WITH.fullmatch(display if display is not None else display_of(cfg))


def pointer_state(text: str) -> tuple[str, str]:
    """From QEMU's 'info mice': ('absolute' | 'relative' | 'unknown', the mouse in use — the line marked '*')."""
    for line in (text or "").splitlines():
        if line.lstrip().startswith("*"):
            return ("absolute" if "(absolute)" in line else "relative"), line.split(":", 1)[-1].strip()
    return "unknown", ""


def sound_of(cfg: dict) -> tuple[str, str] | None:
    """(card, output) or None."""
    a = options(str(cfg.get("audio0", "")))
    if not a.get("device"):
        return None
    return a["device"], a.get("driver", "spice")


def sound_value(card: str, output: str) -> str:
    return f"device={card},driver={output}"


def usb_slots(cfg: dict) -> dict[int, str]:
    """{slot number: value} of the USB entries in a VM's config."""
    return {int(m.group(1)): str(v) for k, v in cfg.items() if (m := _USB_KEY.match(k))}


def usb_host(value: str) -> str:
    """'host=0781:5581,usb3=1' → '0781:5581';  'spice' → 'spice';  'host=1-2' → '1-2'."""
    o = options(value)
    return (o.get("host") or o.get("type") or "").lower()


def is_hub(dev: dict) -> bool:
    return str(dev.get("class", "")) == "9" or str(dev.get("vendid", "")).lower() == "1d6b"  # hubs, root hubs


def usb_id(dev: dict) -> str:
    return f"{str(dev.get('vendid', '')).lower()}:{str(dev.get('prodid', '')).lower()}"


def usb_label(dev: dict) -> str:
    name = " ".join(x for x in (str(dev.get("manufacturer") or "").strip(), str(dev.get("product") or "").strip()) if x)
    return f"{name or 'USB device'}  ({usb_id(dev)})"


def usb_value(dev_id: str, fast: bool = False) -> str:
    return f"host={dev_id}" + (",usb3=1" if fast else "")


def is_fast(dev: dict) -> bool:
    try:
        return float(dev.get("speed") or 0) >= 5000  # USB 3: 5000 Mbit/s and up
    except ValueError:
        return False


def wanted_usb(host_ids: list[str], spice_ports: int, fast_ids: set[str]) -> list[str]:
    """The usbN values for the chosen host devices and SPICE ports."""
    return [usb_value(i, i in fast_ids) for i in host_ids] + ["spice"] * spice_ports


def usb_changes(cfg: dict, wanted: list[str], limit: int = USB_SLOTS) -> dict:
    """The config changes that turn the VM's USB entries into `wanted`: entries that stay keep their slot, removed
    ones are deleted, new ones take the lowest free slots."""
    current = usb_slots(cfg)
    left = list(wanted)
    keep: dict[int, str] = {}
    for slot, value in sorted(current.items()):
        match = next((w for w in left if usb_host(w) == usb_host(value)), None)
        if match is not None:
            left.remove(match)
            keep[slot] = value if match == value else match
    if len(keep) + len(left) > limit:
        raise ValueError(f"A VM can have at most {limit} USB devices on this Proxmox.")
    out: dict = {f"usb{s}": v for s, v in keep.items() if current.get(s) != v}
    free = (s for s in range(limit) if s not in keep)
    for value in left:
        out[f"usb{next(free)}"] = value
    gone = [f"usb{s}" for s in sorted(current) if s not in keep and f"usb{s}" not in out]
    if gone:
        out["delete"] = ",".join(gone)
    return out


def merge(*changes: dict) -> dict:
    """Several config changes in one request: their 'delete' lists are joined."""
    out: dict = {}
    deletes: list[str] = []
    for c in changes:
        for k, v in c.items():
            if k == "delete":
                deletes += [d for d in str(v).split(",") if d]
            else:
                out[k] = v
    if deletes:
        out["delete"] = ",".join(dict.fromkeys(deletes))
    return out
