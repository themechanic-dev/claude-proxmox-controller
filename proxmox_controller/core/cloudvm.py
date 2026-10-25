"""A VM from Ubuntu's official cloud image — no installer. Shared by the New VM window and the connector
(get_cloud_image, create_cloud_vm).

The app's setup disc (core/cloudseed.py) sets the user, its password, SSH keys and the network, and installs the
updates and the QEMU guest agent on the first start — for the desktop also the desktop itself and, if asked, Remote
Desktop. (vm_params can still give a VM Proxmox's own cloud-init drive instead, without a seed.)"""

from __future__ import annotations

import re
from urllib.parse import quote

from .vmspec import DEFAULT_CPU

CLOUD_IMAGES = {"24.04": 626, "26.04": 865}  # release → the image's size in MB
CLOUD_URL = "https://cloud-images.ubuntu.com/releases/{v}/release/ubuntu-{v}-server-cloudimg-amd64.img"
USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
# The desktop as the Windows VMs (the user's choice, 24/10): 2 cores and 4 GB without the host's CPU type ran at
# 100 % with stuttering sound over Remote Desktop, and Firefox left 0.7 GB free
SIZES = {"server": {"cores": 2, "memory": 2048, "disk": 20, "host_cpu": False},
         "desktop": {"cores": 4, "memory": 8192, "disk": 32, "host_cpu": True}}


def image_name(release: str) -> str:
    return f"ubuntu-{release}-server-cloudimg-amd64.qcow2"  # (the image is qcow2; Proxmox goes by the extension)


def find_image(images: list[dict], release: str) -> str:
    """The volid of that release's image among the host's disk images, or ""."""
    return next((i["volid"] for i in images if i["volid"].endswith("/" + image_name(release))), "")


def release_of(volid: str) -> str:
    m = re.search(r"ubuntu-(\d\d\.\d\d)-server-cloudimg", volid)
    return m.group(1) if m else ""


def vm_params(*, vmid: int, name: str, image: str, storage: str, bridge: str, cores: int, memory: int, user: str,
              ssh_key: str = "", desktop: bool = False, onboot: bool = False, seed: str = "",
              host_cpu: bool = False) -> dict:
    """The Proxmox API parameters. `seed`: the volid of the app's own cloud-init disc (the desktop), in place of
    Proxmox's cloud-init drive. The disk is the image's own size (~3.5 GB) until it is grown after the copy."""
    p = {"vmid": vmid, "name": name, "ostype": "l26", "cores": cores, "cpu": "host" if host_cpu else DEFAULT_CPU,
         "memory": memory,
         "scsihw": "virtio-scsi-single", "scsi0": f"{storage}:0,import-from={image},discard=on,iothread=1",
         "boot": "order=scsi0", "net0": f"virtio,bridge={bridge},firewall=1", "agent": "1",
         "vga": "qxl" if desktop else "std", "onboot": bool(onboot)}
    if seed:
        p["ide2"] = f"{seed},media=cdrom"
    else:
        p.update({"ide2": f"{storage}:cloudinit", "ciuser": user, "ipconfig0": "ip=dhcp"})
        if ssh_key:
            p["sshkeys"] = quote(ssh_key.strip(), safe="")  # Proxmox wants the keys URL-encoded
    if desktop:
        p.update(audio0="device=ich9-intel-hda,driver=spice", tablet=1)  # (Proxmox leaves the tablet out with SPICE)
    return p
