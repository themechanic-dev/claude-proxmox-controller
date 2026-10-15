"""What a new VM is made of: the operating-system profiles and the Proxmox API parameters for one that boots an ISO
image. Shared by the New VM window and the connector."""

from __future__ import annotations

import os
import re
from urllib.parse import unquote, urlsplit

VMNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$")

# operating-system profiles: Proxmox's OS type and sensible starting sizes
PROFILES = {
    "linux": {"label": "Linux", "ostype": "l26", "cores": 2, "memory": 2048, "disk": 32},
    "win11": {"label": "Windows 11 / Server 2022 or newer", "ostype": "win11", "cores": 4, "memory": 8192, "disk": 64},
    "win10": {"label": "Windows 10 / older Windows", "ostype": "win10", "cores": 2, "memory": 4096, "disk": 64},
    "other": {"label": "Other", "ostype": "other", "cores": 1, "memory": 1024, "disk": 16},
}
WINDOWS = ("win11", "win10")


def vm_params(*, vmid: int, name: str, profile: str, iso: str, virtio_iso: str, cores: int, host_cpu: bool,
              memory: int, disk_gb: int, storage: str, bridge: str, agent: bool, onboot: bool, start: bool) -> dict:
    """The Proxmox API parameters for a new VM that boots an ISO image.

    Windows only has drivers for the fast VirtIO disk and network on the separate VirtIO disc. Without that disc
    the VM gets a SATA disk and an Intel e1000e card, which Windows knows by itself, so the installer finds both."""
    windows = profile in WINDOWS
    fast = not windows or bool(virtio_iso)
    disk = "scsi0" if fast else "sata0"
    p = {"vmid": vmid, "name": name, "ostype": PROFILES[profile]["ostype"], "cores": cores, "memory": memory,
         "scsihw": "virtio-scsi-single",
         disk: f"{storage}:{disk_gb}," + ("iothread=1,discard=on" if fast else "discard=on"),
         "ide2": f"{iso},media=cdrom",
         "net0": f"{'virtio' if fast else 'e1000e'},bridge={bridge},firewall=1",
         "boot": f"order={disk};ide2;net0", "onboot": onboot, "start": start}
    if host_cpu:
        p["cpu"] = "host"
    if agent:
        p["agent"] = "1"
    if profile == "win11":  # Windows 11 insists on UEFI with Secure Boot and a TPM 2.0
        p.update(bios="ovmf", machine="q35", efidisk0=f"{storage}:1,efitype=4m,pre-enrolled-keys=1",
                 tpmstate0=f"{storage}:1,version=v2.0")
    if windows and virtio_iso:
        p["ide0"] = f"{virtio_iso},media=cdrom"
    return p


def iso_name_from_url(url: str) -> str:
    name = os.path.basename(unquote(urlsplit(url.strip()).path))
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)
