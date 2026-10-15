"""The private line between the connector's bridge (started by Claude) and the running app: a Unix socket in the
user's runtime folder, readable by this user only. One request a connection, one JSON line each way."""

from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path
from typing import Callable

MAX_LINE = 64 << 20  # a screenshot answer is the biggest: well under this


MAX_SOCKET_PATH = 100  # Unix sockets take about 108 bytes of path


def _private_folder(folder: Path) -> Path:
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = folder.stat()
    if st.st_uid != os.getuid():  # someone else's folder in /tmp: never use it
        raise PermissionError(f"{folder} belongs to another user.")
    os.chmod(folder, 0o700)
    return folder


def socket_path() -> Path:
    """$XDG_RUNTIME_DIR/proxmox-controller/connector.sock (/run/user/<uid>: this user's alone); a private folder in
    /tmp when that is missing or too long a path for a socket."""
    base = os.environ.get("XDG_RUNTIME_DIR", "")
    path = Path(base) / "proxmox-controller" / "connector.sock" if base else None
    if path is None or len(str(path)) > MAX_SOCKET_PATH:
        path = Path(f"/tmp/proxmox-controller-{os.getuid()}") / "connector.sock"
    _private_folder(path.parent)
    return path


class AppNotRunning(Exception):
    pass


def _read_line(sock: socket.socket) -> bytes:
    buf = bytearray()
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1 << 16)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_LINE:
            raise ValueError("The answer is too big.")
    return bytes(buf)


def request(message: dict, timeout: float = 600.0, path: Path | None = None) -> dict:
    """Sends one request to the app and waits for its answer. AppNotRunning if the app is not open."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect(str(path or socket_path()))
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise AppNotRunning("Proxmox Controller is not running.") from e
        sock.sendall(json.dumps(message).encode() + b"\n")
        line = _read_line(sock)
        if not line:
            raise AppNotRunning("Proxmox Controller closed the connection.")
        return json.loads(line)
    finally:
        sock.close()


class LinkServer:
    """In the app: hears the bridges. handler(message) runs on the connection's own thread and returns the answer."""

    def __init__(self, handler: Callable[[dict], dict], path: Path | None = None):
        self.handler = handler
        self.path = path or socket_path()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stopping = False

    def start(self) -> bool:
        """False when another Proxmox Controller already answers on the socket (it keeps the connector)."""
        if self.path.exists():
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                probe.settimeout(1)
                probe.connect(str(self.path))
                probe.close()
                return False
            except OSError:
                self.path.unlink(missing_ok=True)  # left by an app that ended without tidying (a power cut)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)  # the socket is born readable by this user only
        try:
            sock.bind(str(self.path))
        finally:
            os.umask(old)
        sock.listen(8)
        self.sock = sock
        self.thread = threading.Thread(target=self._accept, daemon=True, name="connector")
        self.thread.start()
        return True

    def _accept(self) -> None:
        while not self.stopping:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True, name="connector-request").start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            line = _read_line(conn)
            if not line:
                return
            try:
                answer = self.handler(json.loads(line))
            except Exception as e:  # never leave a bridge without an answer
                answer = {"error": f"{type(e).__name__}: {e}"}
            conn.sendall(json.dumps(answer).encode() + b"\n")
        except OSError:
            pass  # the bridge went away (Claude cancelled)
        finally:
            conn.close()

    def stop(self) -> None:
        self.stopping = True
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
                self.path.unlink(missing_ok=True)
