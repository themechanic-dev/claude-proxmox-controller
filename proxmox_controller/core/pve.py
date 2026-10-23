"""A small client for the Proxmox VE REST API (https://<host>:8006/api2/json), standard library only.

Authentication is an API token (Datacenter → Permissions → API Tokens). Proxmox ships a self-signed
certificate, so instead of trusting a certificate authority the client *pins* the certificate: the
SHA-256 fingerprint is confirmed by the user once (it is shown in the Proxmox web UI under
node → System → Certificates) and every later connection must present the same one, before the token
is sent.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

from . import tasks

DEFAULT_PORT = 8006
KINDS = ("lxc", "qemu")  # containers, virtual machines
GUEST_ACTIONS = ("start", "shutdown", "stop", "reboot")
DISK_CONTENT = ("images", "rootdir")  # VM disks, container disks
NETWORK_STORAGE = ("cifs", "nfs", "cephfs", "rbd", "iscsi", "iscsidirect", "glusterfs", "pbs", "esxi")


def storage_order(storage: dict, content: str | None = None) -> tuple:
    """Proxmox lists a node's storages in no set order (the user's New VM offered local-lvm, and the next time the
    NAS, 15/10): by name — and for disks the host's own storages first, a network share after, so a new guest's
    disk lands on the host unless the user picks the share."""
    remote = bool(storage.get("shared")) or storage.get("type") in NETWORK_STORAGE
    return (remote if content in DISK_CONTENT else False, storage.get("storage", ""))


class PveError(Exception):
    """A request the Proxmox API refused or could not answer, worded for the user."""

    def __init__(self, message: str, status: int = 0, reason: str = ""):
        super().__init__(message)
        self.status = status
        self.reason = reason  # Proxmox's own words, e.g. "Permission check failed (/vms/102, VM.Allocate)"


class CertificateMismatch(PveError):
    """The host presented a different certificate than the one that was confirmed."""


@dataclass
class Host:
    id: str
    name: str
    address: str  # "192.168.1.80" or "pve.lan:8006"
    token_id: str = ""  # "root@pam!controller"
    token_secret: str = ""
    fingerprint: str = ""  # "AB:CD:…" SHA-256 of the certificate, as Proxmox shows it
    mac: str = ""  # for Wake-on-LAN
    broadcast: str = "255.255.255.255"
    extra: dict = field(default_factory=dict)

    @property
    def hostname(self) -> str:
        return split_address(self.address)[0]

    @property
    def port(self) -> int:
        return split_address(self.address)[1]


def split_address(address: str) -> tuple[str, int]:
    text = address.strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
    text = text.split("/", 1)[0]
    if text.startswith("["):  # [IPv6]:port
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
    elif text.count(":") == 1:
        host, port = text.split(":")
    else:
        host, port = text, ""
    return host, int(port) if port.isdigit() else DEFAULT_PORT


def format_fingerprint(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def normalize_fingerprint(text: str) -> str:
    hexdigits = "".join(ch for ch in text.upper() if ch in "0123456789ABCDEF")
    return ":".join(hexdigits[i:i + 2] for i in range(0, len(hexdigits), 2))


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the certificate is checked by its pinned fingerprint instead
    return ctx


def fetch_fingerprint(address: str, timeout: float = 8.0) -> str:
    """The SHA-256 fingerprint of the certificate the host presents — for the user to confirm."""
    host, port = split_address(address)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with _tls_context().wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        raise PveError(f"Could not reach {host}:{port} — {e}") from e
    return format_fingerprint(der)



def backup_kind(b: dict) -> str:
    """qemu or lxc. Proxmox says it (subtype); the file name does too: vzdump-qemu-114-2026_10_14-11_20_01.vma.zst."""
    if b.get("subtype") in ("qemu", "lxc"):
        return b["subtype"]
    return "lxc" if "/vzdump-lxc-" in b.get("volid", "") or ":vzdump-lxc-" in b.get("volid", "") else "qemu"


def backup_name(b: dict) -> str:
    """The guest's name as the backup remembers it: the first line of its note ({{guestname}} by default)."""
    lines = (b.get("notes") or "").strip().splitlines()
    return lines[0].strip()[:40] if lines else ""

class Pve:
    def __init__(self, host: Host, timeout: float = 20.0):
        self.host = host
        self.timeout = timeout

    # -- transport ---------------------------------------------------------------------------------

    def _connect(self, timeout: float | None = None) -> http.client.HTTPSConnection:
        """A connection to the host whose certificate matches the confirmed fingerprint. Nothing, not even the
        token, is sent before that check."""
        h = self.host
        if not h.fingerprint:
            raise PveError("The certificate of this host has not been confirmed yet.")
        conn = http.client.HTTPSConnection(h.hostname, h.port, timeout=timeout or self.timeout, context=_tls_context())
        try:
            conn.connect()
        except (OSError, ssl.SSLError) as e:
            conn.close()
            raise PveError(f"Could not reach {h.hostname}:{h.port} — {e}") from e
        presented = format_fingerprint(conn.sock.getpeercert(binary_form=True))
        if presented != normalize_fingerprint(h.fingerprint):
            conn.close()
            raise CertificateMismatch(
                f"{h.name} presented a different certificate than the one you confirmed. Nothing was sent. "
                f"If you renewed the certificate, confirm the new one in the host's settings.")
        return conn

    def _headers(self) -> dict:
        h = self.host
        return {"Authorization": f"PVEAPIToken={h.token_id}={h.token_secret}", "Accept": "application/json"}

    @staticmethod
    def _answer(status: int, reason: str, raw: bytes):
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {}
        if status >= 400:
            raise PveError(_error_text(status, reason, payload), status=status, reason=reason)
        return payload.get("data") if isinstance(payload, dict) else None

    def request(self, method: str, path: str, params: dict | None = None, as_json: bool = False):
        """Call the API; returns the "data" member of the answer. as_json: the body as JSON (for list values such as
        a guest-agent command; Proxmox takes both)."""
        url = "/api2/json" + path
        body = None
        headers = self._headers()
        if as_json:
            body = json.dumps({k: v for k, v in (params or {}).items() if v is not None})
            headers["Content-Type"] = "application/json"
            params = {}
        else:
            params = {k: _form_value(v) for k, v in (params or {}).items() if v is not None}
        if method in ("POST", "PUT") and not as_json:
            body = urlencode(params)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif params:
            url += "?" + urlencode(params)
        conn = self._connect()
        try:
            conn.request(method, url, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, http.client.HTTPException) as e:
            raise PveError(f"The connection to {self.host.name} failed — {e}") from e
        finally:
            conn.close()
        return self._answer(resp.status, resp.reason, raw)

    def upload(self, node: str, storage: str, path: str, content: str = "iso",
               progress=None, cancelled=None, chunk: int = 1 << 20) -> str:
        """Send a file from this computer to one of the host's storages (an ISO image). The file is streamed, so
        a 6 GB image needs no memory; `progress(sent, total)` is called as it goes and `cancelled()` can stop it.
        Returns the task that moves the file into place."""
        name = upload_name(path)
        size = os.path.getsize(path)
        boundary = "pvc" + uuid.uuid4().hex
        head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"content\"\r\n\r\n{content}\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"filename\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        conn = self._connect(timeout=max(self.timeout, 120.0))
        try:
            conn.putrequest("POST", f"/api2/json/nodes/{q(node)}/storage/{q(storage)}/upload")
            for k, v in self._headers().items():
                conn.putheader(k, v)
            conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
            conn.putheader("Content-Length", str(len(head) + size + len(tail)))
            conn.endheaders()
            conn.send(head)
            sent = 0
            with open(path, "rb") as fh:
                while True:
                    if cancelled is not None and cancelled():
                        raise PveError("The upload was cancelled.")
                    block = fh.read(chunk)
                    if not block:
                        break
                    conn.send(block)
                    sent += len(block)
                    if progress is not None:
                        progress(sent, size)
            conn.send(tail)
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, http.client.HTTPException) as e:
            raise PveError(f"The upload to {self.host.name} failed — {e}") from e
        finally:
            conn.close()
        return self._answer(resp.status, resp.reason, raw)

    def get(self, path: str, **params):
        return self.request("GET", path, params)

    def post(self, path: str, **params):
        return self.request("POST", path, params)

    def put(self, path: str, **params):
        return self.request("PUT", path, params)

    def delete(self, path: str, **params):
        return self.request("DELETE", path, params)

    # -- cluster and nodes -------------------------------------------------------------------------

    def version(self) -> dict:
        return self.get("/version") or {}

    def nodes(self) -> list[dict]:
        return self.get("/nodes") or []

    def node_status(self, node: str) -> dict:
        return self.get(f"/nodes/{q(node)}/status") or {}

    def apt_updates(self, node: str) -> list[dict]:
        """The package updates waiting on a node (Package, OldVersion, Version, Title…), as Proxmox found them at its
        last check (the daily "Update package database" task, or apt_refresh). Sorted by name."""
        return sorted(self.get(f"/nodes/{q(node)}/apt/update") or [], key=lambda u: str(u.get("Package", "")))

    def apt_refresh(self, node: str) -> str:
        """Checks for updates now (apt update) — a task."""
        return self.post(f"/nodes/{q(node)}/apt/update")

    def apt_repositories(self, node: str) -> dict:
        """The host's package sources as Proxmox parses them: files (path, repositories…), standard-repos (handle,
        name, status), infos, digest."""
        return self.get(f"/nodes/{q(node)}/apt/repositories") or {}

    def add_repository(self, node: str, handle: str) -> None:
        """One of Proxmox's standard repositories ('no-subscription', 'ceph-squid-no-subscription'…)."""
        self.put(f"/nodes/{q(node)}/apt/repositories", handle=handle)

    def change_repository(self, node: str, path: str, index: int, enabled: bool) -> None:
        # (the parameters as a dict: Proxmox's is called "path", like post()'s own first argument)
        self.request("POST", f"/nodes/{q(node)}/apt/repositories",
                     {"path": path, "index": int(index), "enabled": bool(enabled)})

    def storages(self, node: str, content: str | None = None) -> list[dict]:
        found = self.get(f"/nodes/{q(node)}/storage", content=content, enabled=1 if content else None) or []
        return sorted(found, key=lambda s: storage_order(s, content))

    def node_command(self, node: str, command: str) -> None:
        """Shut down or reboot the host itself ("shutdown" | "reboot")."""
        if command not in ("shutdown", "reboot"):
            raise ValueError(command)
        self.post(f"/nodes/{q(node)}/status", command=command)

    def bridges(self, node: str) -> list[str]:
        nets = self.get(f"/nodes/{q(node)}/network", type="any_bridge") or []
        names = sorted(n["iface"] for n in nets if n.get("iface") and n.get("type") in ("bridge", "OVSBridge"))
        return sorted(names, key=lambda n: (n != "vmbr0", n))  # the usual default first

    def next_id(self) -> int:
        return int(self.get("/cluster/nextid"))

    # -- guests ------------------------------------------------------------------------------------

    def guests(self) -> list[dict]:
        """Every container and VM of the cluster: vmid, name, node, type, status, cpu, mem, disk, uptime…"""
        return [g for g in (self.get("/cluster/resources", type="vm") or []) if g.get("type") in KINDS]

    def guest_action(self, node: str, kind: str, vmid: int, action: str) -> str:
        _check_kind(kind)
        if action not in GUEST_ACTIONS:
            raise ValueError(action)
        return self.post(f"/nodes/{q(node)}/{kind}/{int(vmid)}/status/{action}")

    def guest_config(self, node: str, kind: str, vmid: int) -> dict:
        _check_kind(kind)
        return self.get(f"/nodes/{q(node)}/{kind}/{int(vmid)}/config") or {}

    def update_config(self, node: str, kind: str, vmid: int, changes: dict) -> None:
        _check_kind(kind)
        if changes:
            self.put(f"/nodes/{q(node)}/{kind}/{int(vmid)}/config", **changes)

    def resize_disk(self, node: str, kind: str, vmid: int, disk: str, grow_gb: int) -> None:
        """Grow a disk by `grow_gb` GiB (Proxmox cannot shrink)."""
        _check_kind(kind)
        if grow_gb <= 0:
            raise ValueError("a disk can only grow")
        self.put(f"/nodes/{q(node)}/{kind}/{int(vmid)}/resize", disk=disk, size=f"+{int(grow_gb)}G")

    def delete_guest(self, node: str, kind: str, vmid: int) -> str:
        _check_kind(kind)
        return self.delete(f"/nodes/{q(node)}/{kind}/{int(vmid)}", purge=1, **{"destroy-unreferenced-disks": 1})

    def interfaces(self, node: str, kind: str, vmid: int) -> list[str]:
        """IPv4 addresses of a running guest (containers directly, VMs through the QEMU guest agent)."""
        _check_kind(kind)
        try:
            if kind == "lxc":
                data = self.get(f"/nodes/{q(node)}/lxc/{int(vmid)}/interfaces") or []
                addrs = [a.split("/")[0] for i in data if i.get("name") != "lo"
                         for a in (i.get("inet"),) if a]
            else:
                data = (self.get(f"/nodes/{q(node)}/qemu/{int(vmid)}/agent/network-get-interfaces") or {})
                addrs = [a["ip-address"] for i in data.get("result", [])
                         if not str(i.get("name", "")).startswith(IGNORED_IFACES)  # Docker & co. inside the VM
                         for a in i.get("ip-addresses", []) if a.get("ip-address-type") == "ipv4"]
        except PveError:
            return []  # stopped, no guest agent, or no permission: simply unknown
        return [a for a in addrs if not a.startswith("127.")]

    def rrd(self, node: str, kind: str, vmid: int, timeframe: str = "hour") -> list[dict]:
        _check_kind(kind)
        if timeframe not in ("hour", "day", "week", "month", "year"):
            raise ValueError(timeframe)
        return self.get(f"/nodes/{q(node)}/{kind}/{int(vmid)}/rrddata", timeframe=timeframe, cf="AVERAGE") or []

    # -- snapshots ---------------------------------------------------------------------------------

    def snapshots(self, node: str, kind: str, vmid: int) -> list[dict]:
        _check_kind(kind)
        data = self.get(f"/nodes/{q(node)}/{kind}/{int(vmid)}/snapshot") or []
        return [s for s in data if s.get("name") != "current"]

    def create_snapshot(self, node: str, kind: str, vmid: int, name: str, description: str = "") -> str:
        _check_kind(kind)
        return self.post(f"/nodes/{q(node)}/{kind}/{int(vmid)}/snapshot", snapname=name,
                         description=description or None)

    def rollback_snapshot(self, node: str, kind: str, vmid: int, name: str) -> str:
        _check_kind(kind)
        return self.post(f"/nodes/{q(node)}/{kind}/{int(vmid)}/snapshot/{q(name)}/rollback")

    def delete_snapshot(self, node: str, kind: str, vmid: int, name: str) -> str:
        _check_kind(kind)
        return self.delete(f"/nodes/{q(node)}/{kind}/{int(vmid)}/snapshot/{q(name)}")

    # -- creating containers -----------------------------------------------------------------------

    def templates(self, node: str) -> list[dict]:
        """Container templates already on the host's storages: [{volid, size, storage}]."""
        out = []
        for st in self.storages(node, content="vztmpl"):
            name = st.get("storage")
            for item in self.get(f"/nodes/{q(node)}/storage/{q(name)}/content", content="vztmpl") or []:
                out.append({"volid": item.get("volid"), "size": item.get("size", 0), "storage": name})
        return sorted(out, key=lambda t: t["volid"] or "")

    def appliances(self, node: str) -> list[dict]:
        """Templates Proxmox can download: [{template, os, version, headline, …}]."""
        return [a for a in (self.get(f"/nodes/{q(node)}/aplinfo") or []) if a.get("type") == "lxc"]

    def download_template(self, node: str, storage: str, template: str) -> str:
        return self.post(f"/nodes/{q(node)}/aplinfo", storage=storage, template=template)

    def create_container(self, node: str, params: dict) -> str:
        return self.post(f"/nodes/{q(node)}/lxc", **params)

    # -- consoles ----------------------------------------------------------------------------------

    def open_vnc(self, node: str, kind: str, vmid: int):
        """A VNC console of a running guest through the API: (WebSocket, password). Proxmox accepts the API token
        here (measured on PVE 9.1), so no browser login is needed."""
        from . import websocket
        _check_kind(kind)
        params = {"websocket": 1}
        if kind == "qemu":
            params["generate-password"] = 1  # a random VNC password instead of the ticket's predictable start
        data = self.post(f"/nodes/{q(node)}/{kind}/{int(vmid)}/vncproxy", **params) or {}
        h = self.host
        conn = self._connect()
        sock, conn.sock = conn.sock, None  # the socket now belongs to the console
        path = (f"/api2/json/nodes/{q(node)}/{kind}/{int(vmid)}/vncwebsocket?port={int(data['port'])}"
                f"&vncticket={q(data['ticket'])}")
        host = f"[{h.hostname}]:{h.port}" if ":" in h.hostname else f"{h.hostname}:{h.port}"
        try:
            ws = websocket.client_handshake(sock, host, path, {"Authorization": self._headers()["Authorization"]})
        except (websocket.HandshakeError, OSError) as e:
            sock.close()
            raise PveError(f"The console did not open — {e}") from e
        sock.settimeout(None)  # a console waits for the screen to change for as long as it is open
        return ws, str(data.get("password") or data.get("ticket") or "")

    def has_spice(self, node: str, vmid: int) -> bool:
        """Whether a running VM offers SPICE (sound, clipboard, USB) — the same check the Proxmox web UI makes."""
        return bool((self.get(f"/nodes/{q(node)}/qemu/{int(vmid)}/status/current") or {}).get("spice"))

    def spice_config(self, node: str, vmid: int) -> dict:
        """The connection file for a SPICE viewer (remote-viewer). Its password works once and only briefly."""
        return self.post(f"/nodes/{q(node)}/qemu/{int(vmid)}/spiceproxy", proxy=self.host.hostname) or {}

    # -- VM hardware -------------------------------------------------------------------------------

    def usb_devices(self, node: str) -> list[dict]:
        """USB devices plugged into the host (hubs left out): vendid, prodid, manufacturer, product, speed, port…"""
        from .vmhw import is_hub
        return [d for d in (self.get(f"/nodes/{q(node)}/hardware/usb") or []) if not is_hub(d)]

    def monitor(self, node: str, vmid: int, command: str) -> str:
        """A QEMU monitor command's answer, for a reading such as 'info mice'. Proxmox 9 lets 'info' through with
        Sys.Audit; other commands need more."""
        return str(self.post(f"/nodes/{q(node)}/qemu/{int(vmid)}/monitor", command=command) or "")

    def pending(self, node: str, vmid: int) -> list[str]:
        """Settings of a running VM that change only at its next start."""
        items = self.get(f"/nodes/{q(node)}/qemu/{int(vmid)}/pending") or []
        return [i["key"] for i in items if "pending" in i or i.get("delete")]

    # -- creating VMs ------------------------------------------------------------------------------

    def isos(self, node: str) -> list[dict]:
        """ISO images on the host's storages: [{volid, size, storage}]."""
        out = []
        for st in self.storages(node, content="iso"):
            name = st.get("storage")
            for item in self.get(f"/nodes/{q(node)}/storage/{q(name)}/content", content="iso") or []:
                out.append({"volid": item.get("volid"), "size": item.get("size", 0), "storage": name})
        return sorted(out, key=lambda t: (t["volid"] or "").lower())

    def images(self, node: str) -> list[dict]:
        """Disk images to make VMs from (content "import": cloud images): [{volid, size, storage}]."""
        out = []
        for st in self.storages(node, content="import"):
            for item in self.get(f"/nodes/{q(node)}/storage/{q(st['storage'])}/content", content="import") or []:
                out.append({"volid": item["volid"], "size": item.get("size", 0), "storage": st["storage"]})
        return out

    def download_url(self, node: str, storage: str, url: str, filename: str, content: str = "iso",
                     checksum: str = "", algorithm: str = "sha256") -> str:
        """Have the host itself download a file (an ISO image) into one of its storages."""
        extra = {"checksum": checksum, "checksum-algorithm": algorithm} if checksum else {}
        return self.post(f"/nodes/{q(node)}/storage/{q(storage)}/download-url", url=url, filename=filename,
                         content=content, **{"verify-certificates": 1}, **extra)

    def create_vm(self, node: str, params: dict) -> str:
        return self.post(f"/nodes/{q(node)}/qemu", **params)

    def clone_vm(self, node: str, vmid: int, newid: int, name: str, full: bool = True, storage: str = "") -> str:
        """Copy a VM or template. A full copy stands on its own; a linked one shares the template's disk."""
        return self.post(f"/nodes/{q(node)}/qemu/{int(vmid)}/clone", newid=int(newid), name=name, full=full,
                         storage=storage if full and storage else None)

    # -- backups -----------------------------------------------------------------------------------

    def backup_storages(self, node: str) -> list[dict]:
        return self.storages(node, content="backup")

    def backups(self, node: str, vmid: int | None = None) -> list[dict]:
        """Backups on every backup storage of the node, newest first: volid, ctime, size, vmid, notes, protected…"""
        out = []
        for st in self.backup_storages(node):
            name = st.get("storage")
            for item in self.get(f"/nodes/{q(node)}/storage/{q(name)}/content", content="backup",
                                 vmid=int(vmid) if vmid is not None else None) or []:
                out.append({**item, "storage": name})
        return sorted(out, key=lambda b: b.get("ctime", 0), reverse=True)

    def backup_now(self, node: str, vmid: int, storage: str, mode: str = "snapshot", compress: str = "zstd",
                   notes: str = "", protected: bool = False) -> str:
        if mode not in BACKUP_MODES:
            raise ValueError(mode)
        return self.post(f"/nodes/{q(node)}/vzdump", vmid=str(int(vmid)), storage=storage, mode=mode,
                         compress=compress, protected=True if protected else None,
                         **({"notes-template": notes} if notes else {}))

    def restore(self, node: str, kind: str, vmid: int, archive: str, storage: str = "", replace: bool = False,
                start: bool = False, unique: bool | None = None) -> str:
        """Restore a backup as guest `vmid`: over the existing one (replace, it must be stopped) or as a new one
        (new MAC addresses, so it can run beside the original). unique=False keeps the addresses of a new one — for a
        guest deleted since: nothing to clash with, and the router gives it its old IP."""
        _check_kind(kind)
        if unique is None:
            unique = not replace
        params = {"vmid": int(vmid), "storage": storage or None, "force": True if replace else None,
                  "unique": True if unique else None, "start": True if start else None}
        if kind == "qemu":
            return self.post(f"/nodes/{q(node)}/qemu", archive=archive, **params)
        return self.post(f"/nodes/{q(node)}/lxc", ostemplate=archive, restore=True, **params)

    def delete_backup(self, node: str, storage: str, volid: str) -> str:
        return self.delete(f"/nodes/{q(node)}/storage/{q(storage)}/content/{q(volid)}")

    def deleted_guests_backups(self) -> list[dict]:
        """Backups whose guest no longer exists, from every online node — each once (a shared storage answers on all
        of them) and with the node it was found through, to restore or delete it there. Newest first."""
        existing = {int(g["vmid"]) for g in self.guests()}
        out, seen = [], set()
        for n in self.nodes():
            if n.get("status", "online") != "online":
                continue
            for b in self.backups(n["node"]):
                if b.get("vmid") in (None, "") or int(b["vmid"]) in existing or b["volid"] in seen:
                    continue
                seen.add(b["volid"])
                out.append({**b, "node": n["node"]})
        return sorted(out, key=lambda b: b.get("ctime", 0), reverse=True)

    def delete_backups(self, node: str, backups: list[dict], timeout: float = 600.0) -> list[tuple[dict, str]]:
        """Deletes these backups one after another, each to the end. Protected ones are left alone (Proxmox refuses
        them anyway); one that fails does not stop the rest. Returns the failures, each with Proxmox's words."""
        failed = []
        for b in backups:
            if b.get("protected"):
                continue
            try:
                upid = self.delete_backup(node, b["storage"], b["volid"])
                if isinstance(upid, str) and upid.startswith("UPID:"):
                    self.wait_task(node, upid, timeout=timeout)
            except (PveError, OSError) as e:
                failed.append((b, str(e)))
        return failed

    def protect_backup(self, node: str, storage: str, volid: str, protected: bool) -> None:
        """A protected backup is never pruned or deleted until it is unprotected."""
        self.put(f"/nodes/{q(node)}/storage/{q(storage)}/content/{q(volid)}", protected=bool(protected))

    # -- scheduled backups (Datacenter → Backup) ----------------------------------------------------

    def backup_jobs(self) -> list[dict]:
        return self.get("/cluster/backup") or []

    def create_backup_job(self, params: dict) -> None:
        self.post("/cluster/backup", **params)

    def update_backup_job(self, job_id: str, params: dict) -> None:
        self.put(f"/cluster/backup/{q(job_id)}", **params)

    def delete_backup_job(self, job_id: str) -> None:
        self.delete(f"/cluster/backup/{q(job_id)}")

    def not_backed_up(self) -> list[dict]:
        """Guests that no backup job covers: vmid, name, type."""
        return self.get("/cluster/backup-info/not-backed-up") or []

    def run_job_now(self, node: str, job: dict) -> str:
        """Run a job's backup at once on `node`, as the Proxmox web UI's "Run now" does."""
        params = {k: job[k] for k in ("storage", "mode", "compress", "notes-template", "exclude", "pool")
                  if job.get(k) not in (None, "")}
        if str(job.get("all", "0")) in ("1", "true", "True"):
            params["all"] = True
        else:
            params["vmid"] = str(job.get("vmid", ""))
        keep = job.get("prune-backups")
        if keep:
            params["prune-backups"] = keep if isinstance(keep, str) else ",".join(f"{k}={v}" for k, v in keep.items())
        return self.post(f"/nodes/{q(node)}/vzdump", **params)

    def task_log(self, node: str, upid: str, start: int = 0, limit: int = 500) -> list[dict]:
        """Lines `start`… of a task's log, at most `limit` of them: [{"n": line number, "t": text}, …]."""
        return self.get(f"/nodes/{q(node)}/tasks/{q(upid)}/log", start=start, limit=limit) or []

    # -- bulk actions and the task list -------------------------------------------------------------

    def start_all(self, node: str, vmids: list[int]) -> str:
        """Start several guests in one task, in their boot order and with their delays (Proxmox's Bulk Start)."""
        return self.post(f"/nodes/{q(node)}/startall", vms=",".join(str(int(v)) for v in vmids), force=True)

    def stop_all(self, node: str, vmids: list[int], timeout: int = 180, force_stop: bool = True) -> str:
        """Shut several guests down in one task, in reverse boot order (Proxmox's Bulk Shutdown); those still up
        after `timeout` seconds are stopped when `force_stop`."""
        return self.post(f"/nodes/{q(node)}/stopall", vms=",".join(str(int(v)) for v in vmids), timeout=int(timeout),
                         **{"force-stop": bool(force_stop)})

    def tasks(self, node: str, limit: int = 50) -> list[dict]:
        """The node's recent tasks, newest first: upid, type, id, user, starttime, endtime, status. Running ones too
        (source=all): Proxmox lists only finished tasks unless asked, and gives a running one no endtime."""
        rows = self.get(f"/nodes/{q(node)}/tasks", limit=int(limit), source="all") or []
        return sorted(rows, key=lambda t: int(t.get("starttime") or 0), reverse=True)

    def stop_task(self, node: str, upid: str) -> None:
        self.delete(f"/nodes/{q(node)}/tasks/{q(upid)}")

    # -- tasks -------------------------------------------------------------------------------------

    def task_status(self, node: str, upid: str) -> dict:
        return self.get(f"/nodes/{q(node)}/tasks/{q(upid)}/status") or {}

    def wait_task(self, node: str, upid: str, timeout: float = 600.0, poll: float = 1.0, on_log=None) -> dict:
        """Wait for a task to finish. Raises PveError if it failed or took too long. `on_log(line)` hears each new
        line of the task's log (a backup's progress) as it comes."""
        end = time.monotonic() + timeout
        seen = 0
        while True:
            st = self.task_status(node, upid)
            if on_log is not None:  # after the status: a finished task's last lines are read too
                for entry in self.task_log(node, upid, start=seen):
                    seen = max(seen, int(entry.get("n", seen)))
                    if entry.get("t") not in (None, "", "no content"):
                        on_log(str(entry["t"]))
            if st.get("status") == "stopped":
                if not tasks.done(st.get("exitstatus") or ""):  # (done with warnings is done: the VM did start)
                    raise PveError(f"The task failed: {st.get('exitstatus') or 'unknown error'}")
                return st
            if time.monotonic() > end:
                raise PveError("The task is still running after the time limit; check it in Proxmox.")
            time.sleep(poll)

    # -- inside a VM, through the QEMU guest agent ---------------------------------------------------

    def agent_exec(self, node: str, vmid: int, command: list[str], input_data: str = "") -> int:
        """Starts a program inside a running VM with the guest agent; returns its process number in the guest."""
        params = {"command": [str(c) for c in command]}
        if input_data:
            params["input-data"] = input_data
        data = self.request("POST", f"/nodes/{q(node)}/qemu/{int(vmid)}/agent/exec", params, as_json=True) or {}
        return int(data["pid"])

    def agent_exec_status(self, node: str, vmid: int, pid: int) -> dict:
        """{"exited": 0|1, "exitcode", "out-data", "err-data", "out-truncated", "err-truncated", …}"""
        return self.get(f"/nodes/{q(node)}/qemu/{int(vmid)}/agent/exec-status", pid=int(pid)) or {}

    def agent_ping(self, node: str, vmid: int) -> bool:
        """Whether the VM's QEMU guest agent answers now."""
        try:
            self.post(f"/nodes/{q(node)}/qemu/{int(vmid)}/agent/ping")
            return True
        except PveError:
            return False

    def agent_file_read(self, node: str, vmid: int, path: str, offset: int = 0, count: int = 16 << 20) -> bytes:
        """Up to `count` bytes (16 MiB at most) of a file inside the VM, from `offset`, through the guest agent."""
        params = {"file": path, "count": int(count), "decode": 0}
        if offset:
            params["offset"] = int(offset)  # (Proxmox 9; asked for only when needed)
        data = self.get(f"/nodes/{q(node)}/qemu/{int(vmid)}/agent/file-read", **params) or {}
        return base64.b64decode(data.get("content", "") or "")

    def agent_file_write(self, node: str, vmid: int, path: str, content_b64: str) -> None:
        """Writes a file inside the VM (replacing it) through the guest agent: at most 60 KiB of base64 a call."""
        self.post(f"/nodes/{q(node)}/qemu/{int(vmid)}/agent/file-write", file=path, content=content_b64, encode=0)

    def console_url(self, node: str, kind: str, vmid: int) -> str:
        _check_kind(kind)
        h = self.host
        what = "lxc&xtermjs=1" if kind == "lxc" else "kvm&novnc=1"
        return f"https://{h.hostname}:{h.port}/?console={what}&vmid={int(vmid)}&node={quote(node)}"


def q(segment: str) -> str:
    return quote(str(segment), safe="")


def upload_name(path: str) -> str:
    """The file name the host will store: Proxmox accepts letters, digits, '.', '-' and '_' only."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(path))
    if not name.lower().endswith(".iso"):
        raise ValueError("Only ISO images (.iso) can be uploaded.")
    return name


_MAC_IN_NET = re.compile(r"(?:^|,)(?:[a-z0-9_]+=)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?=,|$)")
IGNORED_IFACES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "kube", "tailscale", "zt")


def guest_macs(cfg: dict) -> list[str]:
    """MAC addresses of a guest's network cards, from its config: VMs write `virtio=BC:24:…,bridge=vmbr0`,
    containers `name=eth0,hwaddr=BC:24:…,…`."""
    out = []
    for key in sorted(k for k in cfg if re.fullmatch(r"net\d+", k)):
        m = _MAC_IN_NET.search(str(cfg[key]))
        if m:
            out.append(m.group(1).lower())
    return out


def agent_enabled(cfg: dict) -> bool:
    """Whether a VM has the QEMU guest agent turned on (`agent: 1` or `agent: enabled=1,fstrim_cloned_disks=1`)."""
    value = str(cfg.get("agent", "0")).strip()
    first = value.split(",")[0]
    return first in ("1", "enabled=1", "enabled=true", "true")


BACKUP_MODES = ("snapshot", "suspend", "stop")


def _check_kind(kind: str) -> None:
    if kind not in KINDS:
        raise ValueError(f"unknown guest type {kind!r}")


def _form_value(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _error_text(status: int, reason: str, payload) -> str:
    detail = ""
    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, dict) and errors:
            detail = "; ".join(f"{k}: {str(v).strip()}" for k, v in errors.items())
        elif payload.get("message"):
            detail = str(payload["message"]).strip()
    if status == 401:
        return "Proxmox refused the API token (401). Check the token ID and secret."
    if status == 403:
        return f"The API token is not allowed to do this ({reason or 'permission check failed'})."
    text = reason or f"HTTP {status}"
    return f"{text} — {detail}" if detail else text
