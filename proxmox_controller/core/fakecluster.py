"""A pretend Proxmox VE cluster that answers API calls like the real one, in memory.

Used by demo mode (no network at all) and by the tests (behind a local HTTPS server). Only the
endpoints the app uses are implemented; answers follow the shapes of Proxmox VE 8/9.
"""

from __future__ import annotations

import random
import re
import time
from copy import deepcopy

from . import vmhw

NODE = "pve"


PRIVS = {  # Proxmox VE 9's privileges (pveum documentation); Sys.AccessNetwork only in newer releases
    "Group.Allocate", "Mapping.Audit", "Mapping.Modify", "Mapping.Use", "Permissions.Modify", "Pool.Allocate",
    "Pool.Audit", "Realm.AllocateUser", "Realm.Allocate", "SDN.Allocate", "SDN.Audit", "Sys.Audit", "Sys.Console",
    "Sys.Incoming", "Sys.Modify", "Sys.PowerMgmt", "Sys.Syslog", "User.Modify", "SDN.Use", "VM.Allocate", "VM.Audit",
    "VM.Backup", "VM.Clone", "VM.Config.CDROM", "VM.Config.CPU", "VM.Config.Cloudinit", "VM.Config.Disk",
    "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options", "VM.Console",
    "VM.GuestAgent.Audit", "VM.GuestAgent.FileRead", "VM.GuestAgent.FileSystemMgmt", "VM.GuestAgent.FileWrite",
    "VM.GuestAgent.Unrestricted", "VM.Migrate", "VM.PowerMgmt", "VM.Replicate", "VM.Snapshot.Rollback", "VM.Snapshot",
    "Datastore.Allocate", "Datastore.AllocateSpace", "Datastore.AllocateTemplate", "Datastore.Audit",
    "Sys.AccessNetwork",
}
VM_CONFIG = ("VM.Config.Disk", "VM.Config.CDROM", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Network",
             "VM.Config.HWType", "VM.Config.Options", "VM.Config.Cloudinit")


def _upid(kind: str, vmid) -> str:
    return f"UPID:{NODE}:{random.randint(0x1000, 0xFFFF):08X}:{int(time.time()):08X}:{kind}:{vmid}:root@pam!controller:"


class FakeCluster:
    def __init__(self, token: str = "root@pam!controller=secret", profile: str = "server"):
        self.token = token  # root's token: everything is allowed
        self.has_access_network = True  # False: a Proxmox release without Sys.AccessNetwork
        self.network_share = False  # True: a NAS share with every content, listed first (as the user's 'nas', 15/10)
        self.users: dict[str, dict] = {"root@pam": {"userid": "root@pam", "comment": ""}}
        self.api_tokens: dict[str, dict] = {}  # "user@realm!name" → {"secret", "privsep", "comment"}
        self.roles: dict[str, list[str]] = {}
        self.acl: list[dict] = []  # {"path", "roleid", "ugid", "type": "user" | "token", "propagate"}
        self.principal = "root@pam!controller"  # who is asking, while a request is handled
        self.exec_runs: dict[int, dict] = {}  # guest-agent programs: pid → their answer
        self.forbidden: set[str] = set()  # "METHOD path" patterns that answer 403, for tests
        self.warn_next: list[str] = []  # the next task ends "WARNINGS: <n>" with these, for tests
        self.cpu_model, self.cpus, self.mem_total = "Intel(R) Xeon(R) CPU D-1528 @ 1.90GHz", 12, 48 << 30
        self.guests = {
            100: {"vmid": 100, "type": "lxc", "name": "pihole", "status": "running", "cores": 1, "memory": 512,
                  "swap": 512, "disk_gb": 4, "onboot": 1, "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "ip": "192.0.2.10",
                  "description": "DNS for the house"},
            101: {"vmid": 101, "type": "lxc", "name": "nextcloud", "status": "running", "cores": 2, "memory": 2048,
                  "swap": 512, "disk_gb": 32, "onboot": 1, "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "ip": "192.0.2.11",
                  "description": "", "tags": "cloud;prod"},
            102: {"vmid": 102, "type": "lxc", "name": "test-box", "status": "stopped", "cores": 1, "memory": 1024,
                  "swap": 0, "disk_gb": 8, "onboot": 0, "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "ip": "",
                  "description": ""},
            200: {"vmid": 200, "type": "qemu", "name": "windows-11", "status": "stopped", "cores": 4, "memory": 8192,
                  "disk_gb": 64, "onboot": 0, "ip": "", "description": "", "agent": 1, "spice": 1},
            201: {"vmid": 201, "type": "qemu", "name": "ubuntu-desktop", "status": "running", "cores": 4, "memory": 16384,
                  "disk_gb": 40, "onboot": 0, "ip": "192.0.2.21", "description": "build machine", "agent": 1,
                  "tags": "dev", "spice": 1},
        }
        self.snaps: dict[int, list[dict]] = {101: [{"name": "before-upgrade", "description": "Nextcloud 29",
                                                    "snaptime": int(time.time()) - 86400 * 3}]}
        if profile == "desktop":  # an old home PC turned into a Proxmox host
            self.cpu_model, self.cpus, self.mem_total = "AMD Ryzen 7 2700X Eight-Core Processor", 16, 32 << 30
            self.guests = {
                100: {"vmid": 100, "type": "lxc", "name": "home-assistant", "status": "running", "cores": 2,
                      "memory": 2048, "swap": 512, "disk_gb": 16, "onboot": 1, "description": "",
                      "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "ip": "192.0.2.30"},
                101: {"vmid": 101, "type": "lxc", "name": "jellyfin", "status": "running", "cores": 4,
                      "memory": 4096, "swap": 512, "disk_gb": 24, "onboot": 1, "description": "media",
                      "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "ip": "192.0.2.31"},
                102: {"vmid": 102, "type": "lxc", "name": "docker-lab", "status": "stopped", "cores": 2,
                      "memory": 2048, "swap": 512, "disk_gb": 32, "onboot": 0, "description": "",
                      "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "ip": ""},
            }
            self.snaps = {}
        self.isos = ["local:iso/ubuntu-24.04.1-live-server-amd64.iso"]
        self.images: list[str] = []  # disk images to import (content "import"): cloud images
        self.secrets: dict[int, str] = {}  # a new guest's password as Proxmox received it, for the tests
        self.uploaded: dict[str, int] = {}  # file name → bytes received, for the tests
        self.files: dict[str, bytes] = {}  # a small uploaded file's contents (an answer disc), for the tests
        self.keys: list[tuple[int, str]] = []  # (vmid, key) pressed with sendkey, for the tests
        self.templates = ["local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
                          "local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst"]
        self.appliances = [
            {"type": "lxc", "template": "alpine-3.20-default_20240908_amd64.tar.xz", "os": "alpine", "version": "3.20",
             "headline": "Alpine Linux 3.20", "section": "system"},
            {"type": "lxc", "template": "debian-12-standard_12.7-1_amd64.tar.zst", "os": "debian-12", "version": "12.7-1",
             "headline": "Debian 12 Bookworm", "section": "system"},
            {"type": "lxc", "template": "ubuntu-24.04-standard_24.04-2_amd64.tar.zst", "os": "ubuntu-24.04",
             "version": "24.04-2", "headline": "Ubuntu 24.04 Noble", "section": "system"},
        ]
        self.tasks: dict[str, str] = {}
        self.repo_files = [  # a fresh Proxmox 9 without a subscription: Debian, and the two enterprise repositories
            {"path": "/etc/apt/sources.list.d/debian.sources", "file-type": "sources", "repositories": [
                {"Types": ["deb"], "URIs": ["http://deb.debian.org/debian"], "Suites": ["trixie", "trixie-updates"],
                 "Components": ["main", "contrib"], "Enabled": 1},
                {"Types": ["deb"], "URIs": ["http://security.debian.org/debian-security"],
                 "Suites": ["trixie-security"], "Components": ["main", "contrib"], "Enabled": 1}]},
            {"path": "/etc/apt/sources.list.d/pve-enterprise.sources", "file-type": "sources", "repositories": [
                {"Types": ["deb"], "URIs": ["https://enterprise.proxmox.com/debian/pve"], "Suites": ["trixie"],
                 "Components": ["pve-enterprise"], "Enabled": 1}]},
            {"path": "/etc/apt/sources.list.d/ceph.sources", "file-type": "sources", "repositories": [
                {"Types": ["deb"], "URIs": ["https://enterprise.proxmox.com/debian/ceph-squid"], "Suites": ["trixie"],
                 "Components": ["enterprise"], "Enabled": 1}]}]
        self.updates = [  # waiting package updates, as a host a few weeks after its install has them
            {"Package": "pve-manager", "OldVersion": "9.1.1", "Version": "9.1.2", "Title": "Proxmox Virtual Environment "
             "Management Tools", "Priority": "important", "Section": "admin", "Arch": "amd64"},
            {"Package": "proxmox-kernel-6.17", "OldVersion": "6.17.2-1", "Version": "6.17.4-1", "Title": "Latest "
             "Proxmox Kernel Image", "Priority": "optional", "Section": "admin", "Arch": "all"},
            {"Package": "openssl", "OldVersion": "3.5.1-1", "Version": "3.5.1-1+deb13u1", "Title": "Secure Sockets "
             "Layer toolkit - cryptographic utility", "Priority": "optional", "Section": "utils", "Arch": "amd64"}]
        self.pending_keys: dict[int, set] = {}  # vmid → settings waiting for the VM's next start
        self.task_logs: dict[str, list[str]] = {}  # upid → its log lines
        self.task_list: list[dict] = []  # every task, for the Tasks panel
        self.jobs: dict[str, dict] = {"backup-nightly": {  # one scheduled backup, as a home server would have
            "id": "backup-nightly", "type": "vzdump", "enabled": 1, "schedule": "03:00", "storage": "local",
            "vmid": "100,101", "mode": "snapshot", "compress": "zstd", "notes-template": "{{guestname}}",
            "prune-backups": "keep-daily=7,keep-weekly=4", "comment": "the services"}}
        self.backups: list[dict] = []  # on "local"; each keeps a copy of the guest it was taken from
        for vmid, days, protected, notes in ((101, 3, True, "before the Nextcloud 29 upgrade"), (101, 1, False, "")):
            if vmid in self.guests:
                self.backups.append(self._backup_entry(self.guests[vmid], "local", time.time() - days * 86400,
                                                       notes or self.guests[vmid]["name"], protected))
        self.usb = [  # what is plugged into the pretend host
            {"busnum": 1, "devnum": 1, "port": 0, "level": 0, "class": 9, "vendid": "1d6b", "prodid": "0002",
             "manufacturer": "Linux Foundation", "product": "2.0 root hub", "speed": "480"},
            {"busnum": 1, "devnum": 3, "port": 2, "level": 1, "class": 0, "vendid": "0781", "prodid": "5581",
             "manufacturer": "SanDisk", "product": "Ultra", "speed": "5000", "usbpath": "1-2"},
            {"busnum": 1, "devnum": 4, "port": 4, "level": 1, "class": 0, "vendid": "046d", "prodid": "c52b",
             "manufacturer": "Logitech", "product": "USB Receiver", "speed": "12", "usbpath": "1-4"},
        ]
        now = int(time.time())
        for ago, kind, vmid, took in ((26 * 3600, "startall", "", 40), (9 * 3600, "vzdump", "", 380),
                                      (2 * 3600, "qmstart", 201, 3)):  # the boot, last night's backup, a start
            if vmid == "" or vmid in self.guests:
                self._task(kind, vmid, start=now - ago, took=took)
        self.vnc: dict[int, dict] = {}  # port → {"ticket", "password", "vmid"} of an opened console
        self.consoles: list = []  # demo mode's pretend screens (FakeVncServer), for the tests

    # -- dispatch --------------------------------------------------------------------------------

    def handle(self, method: str, path: str, params: dict, auth: str) -> tuple[int, str, dict]:
        """(status, reason, payload) for one API call. `path` is after /api2/json."""
        who = auth.removeprefix("PVEAPIToken=")
        tokenid, _, secret = who.partition("=")
        if who == self.token:
            self.principal = tokenid
        elif tokenid in self.api_tokens and self.api_tokens[tokenid]["secret"] == secret:
            self.principal = tokenid
        else:
            return 401, "authentication failure", {"data": None}
        if not self.is_root():
            for (m, rx), need in REQUIRES:
                if m == method and re.fullmatch(rx, path) and not self.allowed(need):
                    return 403, "Permission check failed", {"data": None}
            # as Proxmox: a guest made (or restored) with start=1 is also a power request on it
            if (method == "POST" and re.fullmatch(r"/nodes/[^/]+/(?:lxc|qemu)", path) and params.get("start") == "1"
                    and not self.allowed([("VM.PowerMgmt",)])):
                return 403, f"Permission check failed (/vms/{params.get('vmid')}, VM.PowerMgmt)", {"data": None}
        for pattern in self.forbidden:
            if re.fullmatch(pattern, f"{method} {path}"):
                return 403, "Permission check failed (/vms, VM.PowerMgmt)", {"data": None}
        for (m, rx), fn in ROUTES:
            if m == method:
                match = re.fullmatch(rx, path)
                if match:
                    try:
                        return 200, "OK", {"data": fn(self, params, *match.groups())}
                    except KeyError as e:
                        return 500, f"Configuration file 'nodes/{NODE}/lxc/{e}.conf' does not exist", {"data": None}
                    except ValueError as e:
                        return 400, "Parameter verification failed.", {"data": None, "errors": {"param": str(e)}}
                    except RuntimeError as e:
                        return 500, str(e), {"data": None}
                    except PermissionError as e:
                        return 403, str(e), {"data": None}
        return 501, f"Method '{method} {path}' not implemented", {"data": None}

    # -- answers ---------------------------------------------------------------------------------

    def version(self, p):
        return {"version": "8.4.1", "release": "8.4", "repoid": "fake"}

    def nodes(self, p):
        return [{"node": NODE, "status": "online", "cpu": 0.07, "maxcpu": self.cpus, "mem": 9 << 30,
                 "maxmem": self.mem_total, "uptime": 4 * 3600}]

    def node_status(self, p, node):
        running = [g for g in self.guests.values() if g["status"] == "running"]
        return {"cpu": 0.04 + 0.03 * len(running) + random.uniform(0, 0.03), "cpuinfo": {"cpus": self.cpus,
                "model": self.cpu_model, "sockets": 1},
                "memory": {"used": sum(g["memory"] for g in running) * (1 << 20) + (2 << 30), "total": self.mem_total},
                "rootfs": {"used": 21 << 30, "total": 94 << 30}, "uptime": 4 * 3600 + int(time.time()) % 3600,
                "loadavg": ["0.31", "0.42", "0.40"], "pveversion": "pve-manager/8.4.1/fake", "kversion": "Linux 6.8.12-9-pve"}

    def node_command(self, p, node):
        if p.get("command") not in ("shutdown", "reboot"):
            raise ValueError("command must be shutdown or reboot")
        return None

    def storages(self, p, node):
        out = [{"storage": "local", "type": "dir", "content": "iso,vztmpl,backup,import", "used": 21 << 30,
                "total": 94 << 30, "active": 1, "enabled": 1, "shared": 0},
               {"storage": "local-lvm", "type": "lvmthin", "content": "rootdir,images", "used": 180 << 30,
                "total": 800 << 30, "active": 1, "enabled": 1, "shared": 0}]
        if self.network_share:  # Proxmox lists storages in no set order: on the user's host the NAS came first
            out.insert(0, {"storage": "nas", "type": "cifs", "content": "iso,images,vztmpl,import,backup,snippets,rootdir",
                           "used": 415 << 30, "total": 7233 << 30, "active": 1, "enabled": 1, "shared": 1})
        content = p.get("content")
        return [s for s in out if not content or content in s["content"].split(",")]

    def storage_content(self, p, node, storage):
        if storage == "local" and p.get("content") == "vztmpl":
            return [{"volid": t, "size": 130 << 20, "content": "vztmpl"} for t in self.templates]
        if p.get("content") == "iso":
            return [{"volid": v, "size": 2 << 30, "content": "iso"} for v in self.isos if v.startswith(storage + ":")]
        if p.get("content") == "backup":  # Proxmox leaves out, without a word, the backups one may not make
            return self.backup_list(storage, p.get("vmid")) if self.allowed(  # (check_volume_access)
                [("Datastore.Allocate",), ("Datastore.AllocateSpace", "VM.Backup")]) else []
        if p.get("content") == "import":
            return [{"volid": v, "size": 600 << 20, "content": "import", "format": "qcow2"} for v in self.images
                    if v.startswith(storage + ":")]
        return []

    def _repos_on(self, part: str) -> bool:
        return any(r["Enabled"] and any(part in u for u in r["URIs"]) for f in self.repo_files for r in f["repositories"])

    def apt_updates(self, p, node):
        """Proxmox's own packages come only through a Proxmox repository the host can read: the enterprise one
        refuses a host without a subscription — then only Debian's updates show, as on the user's host (14/10)."""
        pve_readable = self._repos_on("download.proxmox.com/debian/pve")
        return [dict(u) for u in self.updates if pve_readable or not u["Package"].startswith(("pve-", "proxmox-"))]

    def apt_refresh(self, p, node):
        upid = self._task("aptupdate", "")
        lines = ["starting apt-get update", "Hit:1 http://deb.debian.org/debian trixie InRelease"]
        failed = []
        for f in self.repo_files:
            for r in f["repositories"]:
                if r["Enabled"] and "enterprise.proxmox.com" in r["URIs"][0]:
                    n = len(lines)
                    lines += [f"Err:{n} {r['URIs'][0]} trixie InRelease", "  401  Unauthorized [IP: 45.144.208.36 443]"]
                    failed.append(r["URIs"][0])
        lines += ["Reading package lists..."] + [f"E: Failed to fetch {u}/dists/trixie/InRelease  401  Unauthorized"
                                                 for u in failed]
        self.task_logs[upid] = lines + (["TASK ERROR: command 'apt-get update' failed: exit code 100"] if failed
                                        else ["TASK OK"])
        if failed:
            self.tasks[upid] = "command 'apt-get update' failed: exit code 100"
            self.task_list[-1]["status"] = self.tasks[upid]
        return upid

    STANDARD = (("enterprise", "Enterprise", "enterprise.proxmox.com/debian/pve", "pve-enterprise"),
                ("no-subscription", "No-Subscription", "download.proxmox.com/debian/pve", "pve-no-subscription"),
                ("test", "Test", "download.proxmox.com/debian/pve", "pve-test"),
                ("ceph-squid-enterprise", "Ceph Squid Enterprise", "enterprise.proxmox.com/debian/ceph-squid",
                 "enterprise"),
                ("ceph-squid-no-subscription", "Ceph Squid No-Subscription", "download.proxmox.com/debian/ceph-squid",
                 "no-subscription"),
                ("ceph-squid-test", "Ceph Squid Test", "download.proxmox.com/debian/ceph-squid", "test"))

    def _standard_entry(self, handle):
        for h, _name, where, component in self.STANDARD:
            if h == handle:
                for f in self.repo_files:
                    for i, r in enumerate(f["repositories"]):
                        if any(where in u for u in r["URIs"]) and component in r["Components"]:
                            return f, i, r
                return None
        raise ValueError(f"unknown repository handle '{handle}'")

    def apt_repositories(self, p, node):
        std = []
        for h, name, _where, _component in self.STANDARD:
            found = self._standard_entry(h)
            std.append({"handle": h, "name": name, **({"status": found[2]["Enabled"]} if found else {})})
        return {"files": deepcopy(self.repo_files), "errors": [], "infos": [], "digest": "x", "standard-repos": std}

    def add_repository(self, p, node):
        handle = p.get("handle", "")
        found = self._standard_entry(handle)
        if found:  # as Proxmox: one already there is switched on
            found[2]["Enabled"] = 1
            return None
        _h, _name, where, component = next(s for s in self.STANDARD if s[0] == handle)
        repo = {"Types": ["deb"], "URIs": ["http://" + where], "Suites": ["trixie"], "Components": [component],
                "Enabled": 1}
        if "ceph" in where:  # put first in Ceph's file: the others move — a change must read them afresh
            next(f for f in self.repo_files if f["path"].endswith("ceph.sources"))["repositories"].insert(0, repo)
        else:
            self.repo_files.append({"path": "/etc/apt/sources.list.d/proxmox.sources", "file-type": "sources",
                                    "repositories": [repo]})
        return None

    def change_repository(self, p, node):
        f = next((f for f in self.repo_files if f["path"] == p.get("path")), None)
        index = int(p.get("index", -1))
        if f is None or not 0 <= index < len(f["repositories"]):
            raise ValueError("repository not found")
        if "enabled" in p:
            f["repositories"][index]["Enabled"] = 1 if p["enabled"] == "1" else 0
        return None

    def network(self, p, node):
        nets = [{"iface": "vmbr0", "type": "bridge", "active": 1}, {"iface": "eno1", "type": "eth", "active": 1}]
        if not self.allowed([("SDN.Audit",), ("SDN.Use",)]):  # as Proxmox: bridges left out without a word
            nets = [n for n in nets if n["type"] != "bridge"]
        return nets

    def next_id(self, p):
        n = 100
        while n in self.guests:
            n += 1
        return str(n)

    def resources(self, p):
        out = []
        for g in self.guests.values() if self.allowed([("VM.Audit",)]) else []:
            on = g["status"] == "running"
            out.append({"id": f"{g['type']}/{g['vmid']}", "vmid": g["vmid"], "name": g["name"], "node": NODE,
                        "type": g["type"], "status": g["status"], "template": int(g.get("template", 0)),
                        "cpu": random.uniform(0.005, 0.08) if on else 0, "maxcpu": g["cores"],
                        "mem": int(g["memory"] * (1 << 20) * random.uniform(0.2, 0.6)) if on else 0,
                        "maxmem": g["memory"] << 20, "disk": int(g["disk_gb"] * (1 << 30) * 0.35),
                        "maxdisk": g["disk_gb"] << 30, "uptime": g.get("uptime", 7200) if on else 0,
                        **({"tags": g["tags"]} if g.get("tags") else {})})
        return out

    def guest_status(self, p, node, kind, vmid, action):
        g = self._guest(kind, vmid)
        g["status"] = "running" if action in ("start", "reboot") else "stopped"
        self.pending_keys.pop(int(vmid), None)  # a stop or a restart applies what was waiting
        if "agent_next" in g:
            g["agent"] = g.pop("agent_next")
        return self._task(f"vz{action}" if kind == "lxc" else f"qm{action}", vmid)

    def guest_config(self, p, node, kind, vmid):
        g = self._guest(kind, vmid)
        if "cfg" in g:  # made through the API: everything it was given, with later edits on top
            cfg = dict(g["cfg"])
            cfg.update(name=g["name"], cores=g["cores"], memory=g["memory"], onboot=g["onboot"])
            if g["description"]:
                cfg["description"] = g["description"]
            if g.get("tags"):
                cfg["tags"] = g["tags"]
            return cfg
        cfg = {"cores": g["cores"], "memory": g["memory"], "onboot": g["onboot"], "description": g["description"]}
        if g.get("tags"):
            cfg["tags"] = g["tags"]
        if kind == "lxc":
            cfg.update(hostname=g["name"], swap=g["swap"], net0=g["net0"], ostype="debian",
                       rootfs=f"local-lvm:vm-{g['vmid']}-disk-0,size={g['disk_gb']}G")
            cfg.update(g.get("extra", {}))
        else:
            cfg.update(name=g["name"], scsi0=f"local-lvm:vm-{g['vmid']}-disk-0,size={g['disk_gb']}G",
                       net0=f"virtio={self.mac(g['vmid'])},bridge=vmbr0,firewall=1", ostype="l26")
            if g.get("agent"):
                cfg["agent"] = "1"
            if g.get("spice"):
                cfg.setdefault("vga", "qxl")
            cfg.update(g.get("extra", {}))
        return cfg

    def update_config(self, p, node, kind, vmid):
        g = self._guest(kind, vmid)
        for key in filter(None, p.get("delete", "").split(",")):  # Proxmox removes settings with delete=a,b
            if key == "description":
                g["description"] = ""
            g.get("cfg", {}).pop(key, None)
            g.get("extra", {}).pop(key, None)
        for key, value in p.items():
            if re.fullmatch(r"vga|audio\d|usb\d+|startup|tablet|hotplug|boot|ide\d|sata\d+|scsi\d+", key):
                before = self.guest_config({}, node, kind, vmid)
                was = vmhw.tablet_of(before) if key == "tablet" else None
                if re.fullmatch(r"ide\d|sata\d+|scsi\d+", key) and key not in before and g["status"] == "running":
                    self.pending_keys.setdefault(int(vmid), set()).add(key)  # a new drive: at the next start
                (g["cfg"] if "cfg" in g else g.setdefault("extra", {}))[key] = value
                cfg_now = g.get("cfg", g.get("extra", {}))
                boot = str(cfg_now.get("boot", ""))
                order = boot.split("=", 1)[1].split(";") if boot.startswith("order=") else None
                if "media=cdrom" in str(value) and order is not None and key not in order:
                    cfg_now["boot"] = f"{boot};{key}"  # (measured 24/10: Proxmox appends the drive given)
                if g["status"] == "running" and re.fullmatch(r"vga|audio\d", key):
                    self.pending_keys.setdefault(int(vmid), set()).add(key)  # display and sound wait for a restart
                hotplug = str(self.guest_config({}, node, kind, vmid).get("hotplug", "network,disk,usb"))
                if (key == "tablet" and g["status"] == "running" and "usb" not in hotplug.split(",")
                        and was != vmhw.tablet_of(self.guest_config({}, node, kind, vmid))):
                    self.pending_keys.setdefault(int(vmid), set()).add(key)  # as Proxmox: plugged in only with USB hotplug
        for key in ("cores", "memory", "swap", "onboot"):
            if key in p:
                g[key] = int(p[key])
        if "agent" in p:
            on = 1 if str(p["agent"]).split(",")[0] in ("1", "enabled=1") else 0
            if g["status"] == "running" and on != int(g.get("agent") or 0):
                g["agent_next"] = on
                self.pending_keys.setdefault(int(vmid), set()).add("agent")
            else:
                g["agent"] = on
        for key in ("description", "net0", "tags"):
            if key in p:
                g[key] = p[key]
        if "hostname" in p:
            g["name"] = p["hostname"]
        if "name" in p and kind == "qemu":
            g["name"] = p["name"]
        return None

    def resize(self, p, node, kind, vmid):
        g = self._guest(kind, vmid)
        m = re.fullmatch(r"(\+?)(\d+)G", p.get("size", ""))
        if not m:
            raise ValueError("size must be <n>G or +<n>G")
        new = g["disk_gb"] + int(m.group(2)) if m.group(1) else int(m.group(2))
        if new < g["disk_gb"]:
            raise ValueError("shrinking disks is not supported")
        g["disk_gb"] = new
        return None

    def delete_guest(self, p, node, kind, vmid):
        g = self._guest(kind, vmid)
        if g["status"] == "running":
            raise ValueError("guest is running - stop it first")
        del self.guests[g["vmid"]]
        return self._task("vzdestroy", vmid)

    def interfaces(self, p, node, vmid):
        g = self._guest("lxc", vmid)
        if g["status"] != "running":
            raise KeyError(vmid)
        return [{"name": "lo", "inet": "127.0.0.1/8"}, {"name": "eth0", "inet": f"{g['ip']}/24"}]

    def agent_interfaces(self, p, node, vmid):
        g = self._guest("qemu", vmid)
        if g["status"] != "running":
            raise KeyError(vmid)
        if not g.get("agent"):
            raise RuntimeError("No QEMU guest agent configured")
        if g.get("agent_down"):
            raise RuntimeError("QEMU guest agent is not running")
        return {"result": [{"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
                           {"name": "ens18", "ip-addresses": [{"ip-address": g["ip"], "ip-address-type": "ipv4"}]},
                           {"name": "docker0", "ip-addresses": [{"ip-address": "172.17.0.1",
                                                                 "ip-address-type": "ipv4"}]}]}

    def agent_exec(self, p, node, vmid):
        g = self._guest("qemu", vmid)
        if g["status"] != "running":
            raise RuntimeError(f"VM {vmid} not running")
        if not g.get("agent"):
            raise RuntimeError("No QEMU guest agent configured")
        if g.get("agent_down"):
            raise RuntimeError("QEMU guest agent is not running")
        command = p.get("command") or []
        command = [command] if isinstance(command, str) else [str(c) for c in command]
        if not command:
            raise ValueError("command: missing")
        prog, args = command[0].rsplit("/", 1)[-1], command[1:]
        out, err, code = "", "", 0
        if prog == "uname":
            out = f"Linux {g['name']} 6.8.0-45-generic x86_64 GNU/Linux\n"
        elif prog == "hostname":
            out = g["name"] + "\n"
        elif prog == "echo":
            out = " ".join(args) + "\n"
        elif prog == "cat" and p.get("input-data"):
            out = p["input-data"]
        elif prog == "false":
            code = 1
        else:
            err, code = f"{prog}: command not found\n", 127
        pid = random.randint(1000, 99999)
        self.exec_runs[pid] = {"exited": 1, "exitcode": code, **({"out-data": out} if out else {}),
                               **({"err-data": err} if err else {})}
        return {"pid": pid}

    def agent_ping(self, p, node, vmid):
        """Answers when the agent is turned on, plugged in (the VM started with it) and running inside
        (g["agent_down"]: installed or not, it does not answer)."""
        g = self._guest("qemu", vmid)
        if g["status"] != "running" or not g.get("agent") or g.get("agent_down"):
            raise RuntimeError("QEMU guest agent is not running")
        return {}

    def agent_exec_status(self, p, node, vmid):
        run = self.exec_runs.get(int(p.get("pid", 0)))
        if run is None:
            raise ValueError("pid: no such process")
        return run

    def rrd(self, p, node, kind, vmid):
        g = self._guest(kind, vmid)
        step = {"hour": 60, "day": 1800, "week": 10800, "month": 43200, "year": 604800}[p.get("timeframe", "hour")]
        now = int(time.time()) // step * step
        on = g["status"] == "running"
        return [{"time": now - i * step, "maxcpu": g["cores"], "maxmem": g["memory"] << 20,
                 "cpu": (0.02 + 0.03 * random.random()) if on else 0,
                 "mem": (g["memory"] << 20) * (0.3 + 0.1 * random.random()) if on else 0} for i in range(70, -1, -1)]

    def snapshots(self, p, node, kind, vmid):
        self._guest(kind, vmid)
        return deepcopy(self.snaps.get(int(vmid), [])) + [{"name": "current", "description": "You are here!"}]

    def create_snapshot(self, p, node, kind, vmid):
        self._guest(kind, vmid)
        name = p.get("snapname", "")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,39}", name):
            raise ValueError("invalid snapshot name")
        self.snaps.setdefault(int(vmid), []).append({"name": name, "description": p.get("description", ""),
                                                     "snaptime": int(time.time())})
        return self._task("vzsnapshot", vmid)

    def rollback(self, p, node, kind, vmid, name):
        self._snap(vmid, name)
        return self._task("vzrollback", vmid)

    def delete_snapshot(self, p, node, kind, vmid, name):
        snap = self._snap(vmid, name)
        self.snaps[int(vmid)].remove(snap)
        return self._task("vzdelsnapshot", vmid)

    def appliance_list(self, p, node):
        return deepcopy(self.appliances)

    def download(self, p, node):
        template = p.get("template", "")
        if template not in [a["template"] for a in self.appliances]:
            raise ValueError("no such template")
        volid = f"{p.get('storage', 'local')}:vztmpl/{template}"
        if volid not in self.templates:
            self.templates.append(volid)
        return self._task("download", "")

    def create_container(self, p, node):
        if p.get("restore") == "1":
            return self.restore_guest(p, node, "lxc")
        vmid = int(p.get("vmid", 0))
        if vmid in self.guests or vmid < 100:
            raise ValueError(f"CT {vmid} already exists or is invalid")
        if p.get("ostemplate") not in self.templates:
            raise ValueError("template not found")
        if p.get("password"):
            if len(p["password"]) < 5:  # as Proxmox: a container's root password has at least 5 characters
                raise ValueError("password: value must be at least 5 characters long")
            self.secrets[vmid] = p["password"]
        size = int(re.search(r":(\d+)$", p.get("rootfs", "local-lvm:8")).group(1))
        self.guests[vmid] = {"vmid": vmid, "type": "lxc", "name": p.get("hostname", f"ct{vmid}"),
                             "status": "running" if p.get("start") == "1" else "stopped",
                             "cores": int(p.get("cores", 1)), "memory": int(p.get("memory", 512)),
                             "swap": int(p.get("swap", 512)), "disk_gb": size, "onboot": int(p.get("onboot", 0)),
                             "net0": p.get("net0", ""), "ip": "192.0.2.%d" % (vmid % 200), "description": "",
                             **({"extra": {"startup": p["startup"]}} if p.get("startup") else {})}
        return self._task("vzcreate", vmid)

    def download_url(self, p, node, storage):
        content = p.get("content")
        if content not in ("iso", "import"):
            raise ValueError("content: value 'iso', 'vztmpl' or 'import' expected")
        if not re.fullmatch(r"https?://\S+", p.get("url", "")):
            raise ValueError("url: invalid format")
        name = p.get("filename", "")
        pattern = r"[A-Za-z0-9._-]+\.iso" if content == "iso" else r"[A-Za-z0-9._-]+\.(qcow2|raw|vmdk|img)"
        if not re.fullmatch(pattern, name):
            raise ValueError("filename: invalid format")
        volid = f"{storage}:{content}/{name}"
        target = self.isos if content == "iso" else self.images
        if volid in target:
            raise ValueError(f"refusing to override existing file '{name}'")
        target.append(volid)
        return self._task("download", "")

    def upload_file(self, p, node, storage):
        name = p.get("filename", "")
        if p.get("content") != "iso" or not re.fullmatch(r"[A-Za-z0-9._-]+\.iso", name):
            raise ValueError("filename: wrong file extension")
        volid = f"{storage}:iso/{name}"
        if volid not in self.isos:
            self.isos.append(volid)
        self.uploaded[name] = int(p.get("size", 0))
        if isinstance(p.get("data"), bytes):
            self.files[name] = p["data"]
        return self._task("imgcopy", "")

    def create_vm(self, p, node):
        if p.get("archive"):
            return self.restore_guest(p, node, "qemu")
        vmid = int(p.get("vmid", 0))
        if vmid in self.guests or vmid < 100:
            raise ValueError(f"VM {vmid} already exists or is invalid")
        name = p.get("name", "")
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", name):
            raise ValueError("name: invalid format - value does not look like a valid DNS name")
        for key in (k for k in p if re.fullmatch(r"ide\d|sata\d+", k) and "media=cdrom" in p[k] or k == "ide2"):
            value = p[key].split(",")[0]
            if value not in self.isos and value != "none" and not value.endswith(":cloudinit"):
                raise ValueError(f"{key}: volume '{value}' does not exist")
        disk = next((k for k in ("scsi0", "sata0", "virtio0") if k in p), None)
        m = re.match(r"([^:,]+):(\d+)", p.get(disk, "")) if disk else None
        if not m or m.group(1) not in ("local-lvm", "local"):
            raise ValueError("a disk on an existing storage is needed")
        size = int(m.group(2))
        source = re.search(r"import-from=([^,]+)", p.get(disk, ""))
        if source:  # a disk made from an image (a cloud image): its own size, 3.5 GiB for Ubuntu's
            if source.group(1) not in self.images:
                raise ValueError(f"import-from: volume '{source.group(1)}' does not exist")
            size = 3
        if p.get("cipassword"):
            self.secrets[vmid] = p["cipassword"]
        cfg = {k: ("**********" if k == "cipassword" else v) for k, v in p.items() if k not in ("vmid", "start")}
        cfg[disk] = p[disk].replace(f"{m.group(1)}:{size}", f"{m.group(1)}:vm-{vmid}-disk-0", 1) + f",size={size}G"
        for extra in ("efidisk0", "tpmstate0"):
            if extra in p:
                cfg[extra] = p[extra].replace(":1", f":vm-{vmid}-{extra[:-1]}", 1)
        self.guests[vmid] = {"vmid": vmid, "type": "qemu", "name": name,
                             "status": "running" if p.get("start") == "1" else "stopped",
                             "cores": int(p.get("cores", 1)), "memory": int(p.get("memory", 512)), "disk_gb": size,
                             "onboot": int(p.get("onboot", 0)), "ip": "", "description": "",
                             "agent": 1 if str(p.get("agent", "0")).startswith("1") else 0, "cfg": cfg}
        return self._task("qmcreate", vmid)

    def clone(self, p, node, vmid):
        src = self._guest("qemu", vmid)
        newid = int(p.get("newid", 0))
        if newid in self.guests or newid < 100:
            raise ValueError(f"VM {newid} already exists or is invalid")
        new = deepcopy(src)
        new.update(vmid=newid, name=p.get("name") or f"Copy-of-VM-{src['name']}", status="stopped", template=0)
        new.pop("tags", None)
        if "cfg" in new:
            new["cfg"]["name"] = new["name"]
        self.guests[newid] = new
        return self._task("qmclone", newid)

    def vncproxy(self, p, node, kind, vmid):
        g = self._guest(kind, vmid)
        if g["status"] != "running":
            raise ValueError("VM is not running")
        port = 5900 + len(self.vnc)
        ticket = f"PVEVNC:{random.randint(0, 1 << 32):08X}::fake"
        password = f"{random.randint(0, 99999999):08d}" if kind == "qemu" and p.get("generate-password") == "1" else ""
        self.vnc[port] = {"ticket": ticket, "password": password or ticket, "vmid": int(vmid), "kind": kind}
        out = {"port": str(port), "ticket": ticket, "upid": _upid("vncproxy", vmid), "user": "root@pam!controller",
               "cert": "-----BEGIN CERTIFICATE-----\n…"}
        if password:
            out["password"] = password
        return out

    def qemu_status(self, p, node, vmid):
        g = self._guest("qemu", vmid)
        on = g["status"] == "running"
        out = {"vmid": int(vmid), "status": g["status"], "name": g["name"], "qmpstatus": g["status"],
               "uptime": g.get("uptime", 7200) if on else 0}
        vga = str(g.get("cfg", g.get("extra", {})).get("vga", "")).split(",")[0]
        if on and (g.get("spice") or vga.startswith("qxl")):
            out["spice"] = 1
        return out

    def monitor(self, p, node, vmid):
        """QEMU's monitor, for 'info mice' only: the mouse a click from the console moves, as QEMU lists it (measured
        on the user's host, 23/10: Windows 11 with SPICE and no tablet — only the PS/2 mouse; Ubuntu — vmmouse, which
        the Linux kernel turns on, beside the tablet). A USB tablet when the VM has one (Proxmox leaves it out with
        the SPICE display unless it is set); else, in a Linux guest, vmmouse; else only the relative PS/2 mouse."""
        g = self._guest("qemu", vmid)
        if p.get("command", "").split() != ["info", "mice"]:
            raise PermissionError(f"the pretend monitor answers 'info mice' only, not '{p.get('command', '')}'")
        if g["status"] != "running":
            raise RuntimeError(f"VM {vmid} not running")
        cfg = self.guest_config({}, node, "qemu", vmid)
        tablet = vmhw.tablet_of(cfg)
        if "tablet" in self.pending_keys.get(int(vmid), set()):
            tablet = not tablet  # set, but not plugged in until the next start
        linux = str(cfg.get("ostype", "l26")).startswith("l")
        vmmouse = "  Mouse #5: vmmouse (absolute)\n" if linux else ""
        if tablet:
            return "  Mouse #2: QEMU PS/2 Mouse\n" + vmmouse + "* Mouse #3: QEMU HID Tablet (absolute)\n"
        if linux:
            return "  Mouse #2: QEMU PS/2 Mouse\n" + vmmouse.replace("  ", "* ", 1)
        return "* Mouse #2: QEMU PS/2 Mouse\n"

    def spiceproxy(self, p, node, vmid):
        g = self._guest("qemu", vmid)
        if g["status"] != "running" or not g.get("spice"):
            raise ValueError("VM is not running or has no SPICE display")
        return {"type": "spice", "proxy": f"http://{p.get('proxy', NODE)}:3128", "host": f"pvespiceproxy:fake:{vmid}:{NODE}::0",
                "tls-port": 61000, "password": "fake-spice-password", "ca": "-----BEGIN CERTIFICATE-----\\n…",
                "host-subject": "OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=pve.lan",
                "title": f"VM {vmid} - {g['name']}", "delete-this-file": 1, "toggle-fullscreen": "Shift+F11",
                "release-cursor": "Ctrl+Alt+R", "secure-attention": "Ctrl+Alt+Ins"}

    def hardware_usb(self, p, node):
        return deepcopy(self.usb)

    def qemu_pending(self, p, node, vmid):
        g = self._guest("qemu", vmid)
        cfg = self.guest_config({}, node, "qemu", vmid)
        waiting = self.pending_keys.get(int(vmid), set()) if g["status"] == "running" else set()
        out = [{"key": k, "value": v, **({"pending": v} if k in waiting else {})} for k, v in cfg.items()]
        return out + [{"key": k, "pending": str(g.get(f"{k}_next", 1))} for k in sorted(waiting) if k not in cfg]

    # -- backups ---------------------------------------------------------------------------------

    def _backup_entry(self, g: dict, storage: str, when: float, notes: str, protected: bool) -> dict:
        kind = "qemu" if g["type"] == "qemu" else "lxc"
        stamp = time.strftime("%Y_%m_%d-%H_%M_%S", time.localtime(when))
        fmt = "vma.zst" if kind == "qemu" else "tar.zst"
        return {"volid": f"{storage}:backup/vzdump-{kind}-{g['vmid']}-{stamp}.{fmt}", "storage": storage,
                "vmid": g["vmid"], "ctime": int(when), "size": int(g["disk_gb"] * (1 << 30) * 0.3), "format": fmt,
                "subtype": kind, "content": "backup", "notes": notes, "protected": 1 if protected else 0,
                "guest": deepcopy(g)}

    def backup_list(self, storage: str, vmid=None) -> list[dict]:
        return [{k: v for k, v in b.items() if k != "guest"} for b in self.backups
                if b["storage"] == storage and (vmid is None or b["vmid"] == int(vmid))]

    def vzdump(self, p, node):
        ids = [int(v) for v in p.get("vmid", "").split(",") if v.strip().isdigit()]
        if p.get("all") == "1":
            ex = {int(v) for v in p.get("exclude", "").split(",") if v.strip().isdigit()}
            ids = [v for v in self.guests if v not in ex and not self.guests[v].get("template")]
        if len(ids) > 1:  # one task for all of them, like Proxmox
            upids = [self.vzdump({**p, "vmid": str(v), "all": "0"}, node) for v in ids]
            upid = self._task("vzdump", "")
            self.task_logs[upid] = [line for u in upids for line in self.task_logs.get(u, [])]
            return upid
        g = self.guests.get(ids[0] if ids else 0)
        if g is None:
            raise ValueError("unable to find VM")
        if p.get("mode", "snapshot") not in ("snapshot", "suspend", "stop"):
            raise ValueError("mode: value not in enum")
        notes = p.get("notes-template", "").replace("{{guestname}}", g["name"]).replace("{{vmid}}", str(g["vmid"]))
        entry = self._backup_entry(g, p.get("storage", "local"), time.time(), notes, p.get("protected") == "1")
        while any(b["volid"] == entry["volid"] for b in self.backups):  # two in the same second
            entry["volid"] = entry["volid"].replace(".", "-1.", 1)
        self.backups.append(entry)
        upid = self._task("vzdump", g["vmid"])
        total = entry["size"] / (1 << 30)
        self.task_logs[upid] = [f"INFO: starting new backup job: vzdump {g['vmid']} --mode {p.get('mode', 'snapshot')}",
                                f"INFO: Starting Backup of VM {g['vmid']} ({g['type']})"] + \
            [f"INFO: {pct:3d}% ({total * pct / 100:.1f} GiB of {total:.1f} GiB) in {pct // 10}s" for pct in (25, 50, 75, 100)] + \
            [f"INFO: archive file size: {total:.2f}GB", "INFO: Finished Backup of VM", "INFO: Backup job finished successfully"]
        return upid

    def restore_guest(self, p, node, kind):
        archive = p.get("archive") or p.get("ostemplate", "")
        b = next((b for b in self.backups if b["volid"] == archive), None)
        if b is None:
            raise ValueError(f"volume '{archive}' does not exist")
        vmid = int(p.get("vmid", 0))
        old = self.guests.get(vmid)
        if old is not None:
            if p.get("force") != "1":
                raise ValueError(f"unable to restore VM {vmid} - VM {vmid} already exists")
            if old["status"] == "running":
                raise ValueError(f"unable to restore VM {vmid} - VM is running")
        self.restored_with = dict(p)  # what the request asked for, for the tests (unique: new MAC addresses)
        g = deepcopy(b["guest"])
        g.update(vmid=vmid, status="running" if p.get("start") == "1" else "stopped")
        if "cfg" in g:
            g["cfg"]["name"] = g["name"]
        self.guests[vmid] = g
        upid = self._task("qmrestore" if kind == "qemu" else "vzrestore", vmid)
        self.task_logs[upid] = [f"restore vma archive: {archive}", "progress 50% (read)", "progress 100% (read)",
                                "TASK OK"]
        return upid

    def backup_content(self, p, node, storage, volid):
        b = next((b for b in self.backups if b["volid"] == volid and b["storage"] == storage), None)
        if b is None:
            raise ValueError(f"volume '{volid}' does not exist")
        return b

    def delete_content(self, p, node, storage, volid):
        if volid.startswith(f"{storage}:iso/"):  # an ISO image (Datastore.Allocate, checked before)
            if volid not in self.isos:
                raise ValueError(f"volume '{volid}' does not exist")
            self.isos.remove(volid)
            self.files.pop(volid.split("/", 1)[1], None)
            return self._task("imgdel", "")
        return self.delete_backup(p, node, storage, volid)

    def send_key(self, p, node, vmid):
        g = self._guest("qemu", vmid)
        if g["status"] != "running":
            raise RuntimeError(f"VM {vmid} not running")
        self.keys.append((int(vmid), p.get("key", "")))
        return None

    def delete_backup(self, p, node, storage, volid):
        b = self.backup_content(p, node, storage, volid)
        if b["protected"]:
            raise ValueError("cannot delete protected backup")
        self.backups.remove(b)
        return self._task("imgdel", "")

    def update_backup(self, p, node, storage, volid):
        b = self.backup_content(p, node, storage, volid)
        if "protected" in p:
            b["protected"] = 1 if p["protected"] == "1" else 0
        if "notes" in p:
            b["notes"] = p["notes"]
        return None

    # -- scheduled backups ---------------------------------------------------------------------

    JOB_KEYS = ("enabled", "schedule", "storage", "vmid", "all", "exclude", "mode", "compress", "notes-template",
                "prune-backups", "comment")

    def _job_out(self, job: dict) -> dict:
        out = dict(job)
        out["next-run"] = int(time.time()) + 3600 if str(job.get("enabled", 1)) == "1" else None
        return {k: v for k, v in out.items() if v is not None}

    def list_jobs(self, p):
        return [self._job_out(j) for j in self.jobs.values()]

    def create_job(self, p):
        if not p.get("schedule"):
            raise ValueError("schedule: property is missing and it is not optional")
        if not p.get("vmid") and p.get("all") != "1":
            raise ValueError("vmid: either 'vmid' or 'all' is needed")
        if p.get("mode", "snapshot") not in ("snapshot", "suspend", "stop"):
            raise ValueError("mode: value not in enum")
        job_id = p.get("id") or f"backup-{random.randint(0x10000000, 0xFFFFFFFF):08x}"
        self.jobs[job_id] = {"id": job_id, "type": "vzdump", "enabled": int(p.get("enabled", "1")),
                             **{k: v for k, v in p.items() if k in self.JOB_KEYS and k != "enabled"}}
        return None

    def update_job(self, p, job_id):
        job = self.jobs.get(job_id)
        if job is None:
            raise ValueError(f"job '{job_id}' does not exist")
        for key in filter(None, p.get("delete", "").split(",")):
            job.pop(key, None)
        for k, v in p.items():
            if k in self.JOB_KEYS:
                job[k] = int(v) if k == "enabled" else v
        return None

    def delete_job(self, p, job_id):
        if self.jobs.pop(job_id, None) is None:
            raise ValueError(f"job '{job_id}' does not exist")
        return None

    def not_backed_up(self, p):
        from .jobs import covers
        on = [j for j in self.jobs.values()]
        return [{"vmid": g["vmid"], "name": g["name"], "type": g["type"]} for g in self.guests.values()
                if not g.get("template") and not any(covers(j, g["vmid"]) for j in on)]

    def list_tasks(self, p, node):
        limit = int(p.get("limit", 50))
        source = p.get("source", "archive")  # as Proxmox: running tasks only when asked for (active or all)
        everyone = self.allowed([("Sys.Audit",)])  # else only the asker's own tasks
        rows = [(t["starttime"], i, t) for i, t in enumerate(self.task_list)
                if (source == "all" or ("endtime" in t) == (source == "archive"))
                and (everyone or t["user"] == self.principal)]
        return [t for *_, t in sorted(rows, key=lambda r: r[:2], reverse=True)][:limit]  # same second: later first

    def stop_task(self, p, node, upid):
        t = next((t for t in self.task_list if t["upid"] == upid), None)
        if t is None:
            raise ValueError("no such task")
        if t["user"] != self.principal and not self.allowed([("Sys.Modify",)]):
            raise PermissionError("Permission check failed (/nodes/pve, Sys.Modify)")
        if "endtime" not in t:  # running: it ends now, stopped by the user
            self.finish_task(upid, "interrupted by signal")
        return None

    def _bulk(self, p, start: bool) -> str:
        self.last_bulk = dict(p)  # what was asked, for the tests
        ids = [int(v) for v in p.get("vms", "").split(",") if v.strip().isdigit()] or \
              [v for v, g in self.guests.items() if not start or g.get("onboot")]
        from .startup import parse
        def place(v):
            g = self.guests.get(v, {})
            return parse((g.get("cfg") or g.get("extra") or {}).get("startup", ""))["order"] or 1 << 30

        order = sorted(ids, key=lambda v: (place(v), v), reverse=not start)  # shut down in reverse order
        upid = self._task("startall" if start else "stopall", "")
        lines = []
        for v in order:
            g = self.guests.get(v)
            if g is None or g.get("template"):
                continue
            want = "running" if start else "stopped"
            if g["status"] != want:
                g["status"] = want
                lines.append(f"{'Starting' if start else 'Stopping'} {'VM' if g['type'] == 'qemu' else 'CT'} {v}")
        self.task_logs[upid] = lines + ["TASK OK"]
        return upid

    def start_all(self, p, node):
        return self._bulk(p, True)

    def stop_all(self, p, node):
        return self._bulk(p, False)

    def task_log(self, p, node, upid):
        lines = self.task_logs.get(upid, ["TASK OK"])
        start, limit = int(p.get("start", 0)), int(p.get("limit", 50))  # Proxmox's default limit is 50
        return [{"n": i + 1, "t": t} for i, t in enumerate(lines) if i >= start][:limit]

    def task_status(self, p, node, upid):
        if upid not in self.tasks:
            raise ValueError("no such task")
        if self.tasks[upid] is None:
            return {"status": "running", "upid": upid}
        return {"status": "stopped", "exitstatus": self.tasks[upid], "upid": upid}

    # -- users, tokens, roles, permissions --------------------------------------------------------

    def is_root(self) -> bool:
        return self.principal.split("!")[0] == "root@pam"

    def privileges(self) -> set[str]:
        if self.is_root():
            return set(PRIVS)
        user = self.principal.split("!")[0]
        info = self.api_tokens.get(self.principal, {})
        out = set()
        for e in self.acl:
            if e["path"] == "/" and (e["ugid"] == self.principal or (e["ugid"] == user and not info.get("privsep"))):
                out |= set(self.roles.get(e["roleid"], []))
        return out

    def allowed(self, need) -> bool:
        """need: alternatives, each a tuple of privileges all required ("root" for access management)."""
        if need == "root":
            return self.is_root()
        have = self.privileges()
        return any(all(x in have for x in alt) for alt in need)

    def _known(self, privs) -> list[str]:
        items = [x for x in (privs.split(",") if isinstance(privs, str) else privs) if x]
        for x in items:
            if x not in PRIVS or (x == "Sys.AccessNetwork" and not self.has_access_network):
                raise ValueError(f"invalid privilege '{x}'")
        return items

    def create_user(self, p):
        uid = p.get("userid", "")
        if "@" not in uid:
            raise ValueError("userid: invalid format")
        if uid in self.users:
            raise ValueError(f"user '{uid}' already exists")
        self.users[uid] = {"userid": uid, "comment": p.get("comment", "")}

    def list_users(self, p):
        return list(self.users.values())

    def delete_user(self, p, uid):
        if uid not in self.users:
            raise ValueError(f"no such user ('{uid}')")
        del self.users[uid]
        self.api_tokens = {k: v for k, v in self.api_tokens.items() if not k.startswith(uid + "!")}
        self.acl = [e for e in self.acl if e["ugid"].split("!")[0] != uid]

    def create_token(self, p, uid, name):
        if uid not in self.users:
            raise ValueError(f"no such user ('{uid}')")
        full = f"{uid}!{name}"
        if full in self.api_tokens:
            raise ValueError(f"Token already exists.")
        secret = f"{random.getrandbits(128):032x}"
        self.api_tokens[full] = {"secret": secret, "privsep": str(p.get("privsep", "1")) in ("1", "true"),
                                 "comment": p.get("comment", "")}
        return {"full-tokenid": full, "info": {"privsep": int(self.api_tokens[full]["privsep"])}, "value": secret}

    def delete_token(self, p, uid, name):
        if self.api_tokens.pop(f"{uid}!{name}", None) is None:
            raise ValueError("no such token")
        self.acl = [e for e in self.acl if e["ugid"] != f"{uid}!{name}"]

    def list_roles(self, p):
        return [{"roleid": r, "privs": ",".join(v)} for r, v in self.roles.items()]

    def create_role(self, p):
        rid = p.get("roleid", "")
        if rid in self.roles:
            raise ValueError(f"role '{rid}' already exists")
        self.roles[rid] = self._known(p.get("privs", ""))

    def update_role(self, p, rid):
        if rid not in self.roles:
            raise ValueError(f"role '{rid}' does not exist")
        privs = self._known(p.get("privs", ""))
        self.roles[rid] = sorted(set(self.roles[rid]) | set(privs)) if str(p.get("append", "0")) == "1" else privs

    def delete_role(self, p, rid):
        if self.roles.pop(rid, None) is None:
            raise ValueError(f"role '{rid}' does not exist")
        self.acl = [e for e in self.acl if e["roleid"] != rid]

    def list_acl(self, p):
        return [{"path": e["path"], "roleid": e["roleid"], "ugid": e["ugid"], "type": e["type"],
                 "propagate": e["propagate"]} for e in self.acl]

    def update_acl(self, p):
        path, delete = p.get("path", ""), str(p.get("delete", "0")) == "1"
        for role in [r for r in str(p.get("roles", "")).split(",") if r]:
            if role not in self.roles:
                raise ValueError(f"role '{role}' does not exist")
            for kind, key in (("user", "users"), ("token", "tokens")):
                for ugid in [u for u in str(p.get(key, "")).split(",") if u]:
                    self.acl = [e for e in self.acl if not (e["path"] == path and e["roleid"] == role and
                                                            e["ugid"] == ugid)]
                    if not delete:
                        self.acl.append({"path": path, "roleid": role, "ugid": ugid, "type": kind,
                                         "propagate": int(str(p.get("propagate", "1")) == "1")})

    # -- helpers ---------------------------------------------------------------------------------

    @staticmethod
    def mac(vmid) -> str:
        """The (pretend) MAC address of a VM's first network card."""
        return f"BC:24:11:00:{int(vmid) // 100:02X}:{int(vmid) % 100:02X}"

    def _guest(self, kind: str, vmid) -> dict:
        g = self.guests[int(vmid)]
        if g["type"] != kind:
            raise KeyError(vmid)
        return g

    def _snap(self, vmid, name) -> dict:
        for s in self.snaps.get(int(vmid), []):
            if s["name"] == name:
                return s
        raise ValueError(f"snapshot '{name}' does not exist")

    def _task(self, kind: str, vmid, start: int | None = None, took: int = 1) -> str:
        upid = _upid(kind, vmid)
        status = "OK"
        if self.warn_next:  # done, with warnings — as a Windows VM's start says a word about its firmware
            status = f"WARNINGS: {len(self.warn_next)}"
            self.task_logs[upid] = [f"WARN: {w}" for w in self.warn_next] + [f"TASK {status}"]
            self.warn_next = []
        self.tasks[upid] = status
        start = int(time.time()) if start is None else start
        self.task_list.append({"upid": upid, "node": NODE, "type": kind, "id": str(vmid), "user": self.principal,
                               "starttime": start, "endtime": start + took, "status": status,
                               "pid": random.randint(1000, 99999)})
        return upid

    def long_task(self, kind: str, vmid, lines: list[str]) -> str:
        """A task that keeps running until finish_task() or a Stop, for the tests."""
        upid = self._task(kind, vmid)
        self.tasks[upid] = None
        t = self.task_list[-1]
        del t["endtime"]
        t["status"] = "RUNNING"  # as Proxmox lists a task that has not ended
        self.task_logs[upid] = list(lines)
        return upid

    def finish_task(self, upid: str, status: str = "OK") -> None:
        t = next(t for t in self.task_list if t["upid"] == upid)
        t.update(endtime=int(time.time()), status=status)
        self.tasks[upid] = status
        self.task_logs.setdefault(upid, []).append("TASK OK" if status == "OK" else f"TASK {status}"
                                                   if status.startswith("WARNINGS: ") else f"TASK ERROR: {status}")


_N = r"([^/]+)"
ROUTES = [
    (("GET", r"/version"), FakeCluster.version),
    (("GET", r"/nodes"), FakeCluster.nodes),
    (("GET", rf"/nodes/{_N}/status"), FakeCluster.node_status),
    (("POST", rf"/nodes/{_N}/status"), FakeCluster.node_command),
    (("GET", rf"/nodes/{_N}/storage"), FakeCluster.storages),
    (("GET", rf"/nodes/{_N}/storage/{_N}/content"), FakeCluster.storage_content),
    (("GET", rf"/nodes/{_N}/network"), FakeCluster.network),
    (("GET", rf"/nodes/{_N}/apt/update"), FakeCluster.apt_updates),
    (("POST", rf"/nodes/{_N}/apt/update"), FakeCluster.apt_refresh),
    (("GET", rf"/nodes/{_N}/apt/repositories"), FakeCluster.apt_repositories),
    (("PUT", rf"/nodes/{_N}/apt/repositories"), FakeCluster.add_repository),
    (("POST", rf"/nodes/{_N}/apt/repositories"), FakeCluster.change_repository),
    (("GET", r"/cluster/nextid"), FakeCluster.next_id),
    (("GET", r"/cluster/resources"), FakeCluster.resources),
    (("POST", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/status/(start|shutdown|stop|reboot)"), FakeCluster.guest_status),
    (("GET", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/config"), FakeCluster.guest_config),
    (("PUT", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/config"), FakeCluster.update_config),
    (("PUT", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/resize"), FakeCluster.resize),
    (("DELETE", rf"/nodes/{_N}/(lxc|qemu)/(\d+)"), FakeCluster.delete_guest),
    (("GET", rf"/nodes/{_N}/lxc/(\d+)/interfaces"), FakeCluster.interfaces),
    (("GET", rf"/nodes/{_N}/qemu/(\d+)/agent/network-get-interfaces"), FakeCluster.agent_interfaces),
    (("GET", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/rrddata"), FakeCluster.rrd),
    (("GET", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/snapshot"), FakeCluster.snapshots),
    (("POST", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/snapshot"), FakeCluster.create_snapshot),
    (("POST", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/snapshot/{_N}/rollback"), FakeCluster.rollback),
    (("DELETE", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/snapshot/{_N}"), FakeCluster.delete_snapshot),
    (("GET", rf"/nodes/{_N}/aplinfo"), FakeCluster.appliance_list),
    (("POST", rf"/nodes/{_N}/aplinfo"), FakeCluster.download),
    (("POST", rf"/nodes/{_N}/lxc"), FakeCluster.create_container),
    (("POST", rf"/nodes/{_N}/storage/{_N}/download-url"), FakeCluster.download_url),
    (("POST", rf"/nodes/{_N}/storage/{_N}/upload"), FakeCluster.upload_file),
    (("POST", rf"/nodes/{_N}/qemu"), FakeCluster.create_vm),
    (("POST", rf"/nodes/{_N}/(lxc|qemu)/(\d+)/vncproxy"), FakeCluster.vncproxy),
    (("GET", rf"/nodes/{_N}/hardware/usb"), FakeCluster.hardware_usb),
    (("POST", rf"/nodes/{_N}/vzdump"), FakeCluster.vzdump),
    (("DELETE", rf"/nodes/{_N}/storage/{_N}/content/(.+)"), FakeCluster.delete_content),
    (("PUT", rf"/nodes/{_N}/storage/{_N}/content/(.+)"), FakeCluster.update_backup),
    (("GET", rf"/nodes/{_N}/tasks/{_N}/log"), FakeCluster.task_log),
    (("GET", rf"/nodes/{_N}/tasks"), FakeCluster.list_tasks),
    (("DELETE", rf"/nodes/{_N}/tasks/{_N}"), FakeCluster.stop_task),
    (("POST", rf"/nodes/{_N}/startall"), FakeCluster.start_all),
    (("POST", rf"/nodes/{_N}/stopall"), FakeCluster.stop_all),
    (("GET", r"/cluster/backup"), FakeCluster.list_jobs),
    (("POST", r"/cluster/backup"), FakeCluster.create_job),
    (("PUT", rf"/cluster/backup/{_N}"), FakeCluster.update_job),
    (("DELETE", rf"/cluster/backup/{_N}"), FakeCluster.delete_job),
    (("GET", r"/cluster/backup-info/not-backed-up"), FakeCluster.not_backed_up),
    (("GET", rf"/nodes/{_N}/qemu/(\d+)/pending"), FakeCluster.qemu_pending),
    (("GET", rf"/nodes/{_N}/qemu/(\d+)/status/current"), FakeCluster.qemu_status),
    (("POST", rf"/nodes/{_N}/qemu/(\d+)/spiceproxy"), FakeCluster.spiceproxy),
    (("POST", rf"/nodes/{_N}/qemu/(\d+)/monitor"), FakeCluster.monitor),
    (("PUT", rf"/nodes/{_N}/qemu/(\d+)/sendkey"), FakeCluster.send_key),
    (("POST", rf"/nodes/{_N}/qemu/(\d+)/clone"), FakeCluster.clone),
    (("GET", rf"/nodes/{_N}/tasks/{_N}/status"), FakeCluster.task_status),
    (("POST", rf"/nodes/{_N}/qemu/(\d+)/agent/exec"), FakeCluster.agent_exec),
    (("POST", rf"/nodes/{_N}/qemu/(\d+)/agent/ping"), FakeCluster.agent_ping),
    (("GET", rf"/nodes/{_N}/qemu/(\d+)/agent/exec-status"), FakeCluster.agent_exec_status),
    (("POST", r"/access/users"), FakeCluster.create_user),
    (("GET", r"/access/users"), FakeCluster.list_users),
    (("DELETE", rf"/access/users/([^/!]+)"), FakeCluster.delete_user),
    (("POST", rf"/access/users/([^/!]+)/token/{_N}"), FakeCluster.create_token),
    (("DELETE", rf"/access/users/([^/!]+)/token/{_N}"), FakeCluster.delete_token),
    (("GET", r"/access/roles"), FakeCluster.list_roles),
    (("POST", r"/access/roles"), FakeCluster.create_role),
    (("PUT", rf"/access/roles/{_N}"), FakeCluster.update_role),
    (("DELETE", rf"/access/roles/{_N}"), FakeCluster.delete_role),
    (("GET", r"/access/acl"), FakeCluster.list_acl),
    (("PUT", r"/access/acl"), FakeCluster.update_acl),
]

_G = r"/nodes/[^/]+/(?:lxc|qemu)/\d+"
# What each call checks, as Proxmox's API schema says (alternatives of privileges all required); calls not listed
# are open to every user (the version, the node list, the guest list filtered by VM.Audit, own tasks)
REQUIRES = [
    (("GET", r"/nodes/[^/]+/status"), [("Sys.Audit",)]),
    (("POST", r"/nodes/[^/]+/status"), [("Sys.PowerMgmt",)]),
    (("GET", r"/nodes/[^/]+/apt/update"), [("Sys.Modify",)]),
    (("POST", r"/nodes/[^/]+/apt/update"), [("Sys.Modify",)]),
    (("GET", r"/nodes/[^/]+/apt/repositories"), [("Sys.Audit",)]),
    (("PUT", r"/nodes/[^/]+/apt/repositories"), [("Sys.Modify",)]),
    (("POST", r"/nodes/[^/]+/apt/repositories"), [("Sys.Modify",)]),
    (("GET", r"/nodes/[^/]+/storage/[^/]+/content"), [("Datastore.Audit",), ("Datastore.AllocateSpace",)]),
    (("POST", _G + r"/status/(?:start|shutdown|stop|reboot)"), [("VM.PowerMgmt",)]),
    (("GET", _G + r"/(?:config|rrddata|snapshot|pending|status/current)"), [("VM.Audit",)]),
    (("GET", r"/nodes/[^/]+/lxc/\d+/interfaces"), [("VM.Audit",)]),
    (("PUT", _G + r"/config"), [(x,) for x in VM_CONFIG]),
    (("PUT", _G + r"/resize"), [("VM.Config.Disk",)]),
    (("DELETE", _G), [("VM.Allocate",)]),
    (("GET", r"/nodes/[^/]+/qemu/\d+/agent/network-get-interfaces"), [("VM.GuestAgent.Audit",),
                                                                      ("VM.GuestAgent.Unrestricted",)]),
    (("POST", r"/nodes/[^/]+/qemu/\d+/agent/exec"), [("VM.GuestAgent.Unrestricted",)]),
    (("POST", r"/nodes/[^/]+/qemu/\d+/agent/ping"), [("VM.GuestAgent.Audit",), ("VM.GuestAgent.Unrestricted",)]),
    (("GET", r"/nodes/[^/]+/qemu/\d+/agent/exec-status"), [("VM.GuestAgent.Unrestricted",)]),
    (("POST", _G + r"/snapshot"), [("VM.Snapshot",)]),
    (("POST", _G + r"/snapshot/[^/]+/rollback"), [("VM.Snapshot",), ("VM.Snapshot.Rollback",)]),
    (("DELETE", _G + r"/snapshot/[^/]+"), [("VM.Snapshot",)]),
    (("POST", r"/nodes/[^/]+/(?:lxc|qemu)"), [("VM.Allocate", "Datastore.AllocateSpace")]),
    (("POST", r"/nodes/[^/]+/qemu/\d+/clone"), [("VM.Clone", "VM.Allocate")]),
    (("POST", r"/nodes/[^/]+/aplinfo"), [("Datastore.AllocateTemplate",)]),
    (("POST", r"/nodes/[^/]+/storage/[^/]+/download-url"), [("Datastore.AllocateTemplate", "Sys.Modify"),
                                                            ("Datastore.AllocateTemplate", "Sys.AccessNetwork")]),
    (("POST", r"/nodes/[^/]+/storage/[^/]+/upload"), [("Datastore.AllocateTemplate",)]),
    (("POST", _G + r"/vncproxy"), [("VM.Console",)]),
    (("POST", r"/nodes/[^/]+/qemu/\d+/spiceproxy"), [("VM.Console",)]),
    (("PUT", r"/nodes/[^/]+/qemu/\d+/sendkey"), [("VM.Console",)]),
    (("POST", r"/nodes/[^/]+/qemu/\d+/monitor"), [("Sys.Audit",), ("Sys.Modify",)]),  # (Proxmox 9: 'info' needs no more)
    (("GET", r"/nodes/[^/]+/hardware/usb"), [("Sys.Modify",)]),
    (("POST", r"/nodes/[^/]+/vzdump"), [("VM.Backup", "Datastore.AllocateSpace")]),
    (("DELETE", r"/nodes/[^/]+/storage/[^/]+/content/.+"), [("Datastore.Allocate",),
                                                            ("Datastore.AllocateSpace", "VM.Backup")]),
    (("PUT", r"/nodes/[^/]+/storage/[^/]+/content/.+"), [("Datastore.Audit",), ("Datastore.AllocateSpace",)]),
    (("POST", r"/nodes/[^/]+/(?:startall|stopall)"), [("VM.PowerMgmt",)]),
    (("GET", r"/cluster/backup(?:-info/not-backed-up)?"), [("Sys.Audit",)]),
    (("POST", r"/cluster/backup"), [("Sys.Modify",)]),
    (("PUT", r"/cluster/backup/[^/]+"), [("Sys.Modify",)]),
    (("DELETE", r"/cluster/backup/[^/]+"), [("Sys.Modify",)]),
    (("GET", r"/access/(?:users|roles|acl)"), "root"),
    (("POST", r"/access/.*"), "root"),
    (("PUT", r"/access/.*"), "root"),
    (("DELETE", r"/access/.*"), "root"),
]
