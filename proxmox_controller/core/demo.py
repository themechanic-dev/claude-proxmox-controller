"""Demo mode: the same Pve client, answered by an in-memory pretend cluster. Nothing touches the network."""

from __future__ import annotations

import os
import socket
import time
from urllib.parse import unquote

from .fakecluster import FakeCluster
from .fakevnc import FakeVncServer
from .websocket import WebSocket
from .pve import Host, Pve, PveError, _error_text, _form_value, upload_name

DEMO_HOSTS = [
    Host(id="demo-pve", name="Home server (demo)", address="192.0.2.80", token_id="root@pam!controller",
         token_secret="secret", fingerprint="DEMO", mac="02:00:00:00:00:80"),
    Host(id="demo-pc", name="Old desktop PC (demo)", address="192.0.2.90", token_id="root@pam!controller",
         token_secret="secret", fingerprint="DEMO", mac="02:00:00:00:00:90"),
]


class DemoPve(Pve):
    _clusters: dict[str, FakeCluster] = {}

    def __init__(self, host: Host, timeout: float = 20.0):
        super().__init__(host, timeout)
        if host.id not in self._clusters:
            self._clusters[host.id] = FakeCluster(profile="desktop" if host.id == "demo-pc" else "server")
        self.cluster = self._clusters[host.id]

    def request(self, method: str, path: str, params: dict | None = None, as_json: bool = False):
        params = {k: (v if as_json or isinstance(v, bytes) else _form_value(v))  # (bytes: an upload's file)
                  for k, v in (params or {}).items() if v is not None}
        h = self.host  # the host's own token: Claude's token gets only its privileges, as on a real Proxmox
        status, reason, payload = self.cluster.handle(method, unquote(path), params,
                                                      f"PVEAPIToken={h.token_id}={h.token_secret}")
        if status >= 400:
            raise PveError(_error_text(status, reason, payload), status=status, reason=reason)
        return payload.get("data")

    def open_vnc(self, node: str, kind: str, vmid: int):
        """A pretend screen through a socket pair: the console window works in demo mode without any network."""
        data = self.request("POST", f"/nodes/{node}/{kind}/{vmid}/vncproxy",
                            {"websocket": 1, "generate-password": 1 if kind == "qemu" else None})
        password = data.get("password") or data["ticket"]
        mine, theirs = socket.socketpair()
        name = next((g["name"] for g in self.cluster.guests.values() if g["vmid"] == int(vmid)), "")
        srv = FakeVncServer(WebSocket(theirs, client=False), password, name=f"{vmid} {name}",
                            ext_keys=kind == "qemu").start()
        self.cluster.consoles.append(srv)
        return WebSocket(mine), password

    def has_spice(self, node: str, vmid: int) -> bool:
        return False  # nothing real to connect remote-viewer to: "automatic" picks the built-in console

    def spice_config(self, node: str, vmid: int) -> dict:
        raise PveError("Demo mode: SPICE needs a real Proxmox host.")

    def upload(self, node: str, storage: str, path: str, content: str = "iso",
               progress=None, cancelled=None, chunk: int = 1 << 20) -> str:
        name, size = upload_name(path), os.path.getsize(path)
        sent = 0
        while sent < size:  # pretend to send it, so the progress bar moves
            if cancelled is not None and cancelled():
                raise PveError("The upload was cancelled.")
            sent = min(size, sent + max(chunk, size // 20))
            if progress is not None:
                progress(sent, size)
            time.sleep(0.02)
        return self.request("POST", f"/nodes/{node}/storage/{storage}/upload",
                            {"content": content, "filename": name, "size": size})

    def _upload(self, node: str, storage: str, name: str, size: int, fh, content: str = "iso",
                progress=None, cancelled=None, chunk: int = 1 << 20) -> str:
        data = fh.read()  # (a small file made here: kept whole, for the tests to read)
        return self.request("POST", f"/nodes/{node}/storage/{storage}/upload",
                            {"content": content, "filename": name, "size": len(data), "data": data})
