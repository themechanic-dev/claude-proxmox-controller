r"""The private line between the connector's bridge (started by Claude) and the running app: a Unix socket in the
user's runtime folder, readable by this user only. One request a connection, one JSON line each way.

On Windows, whose Python has no Unix sockets, it is a named pipe instead — \\.\pipe\proxmox-controller-<user>, which
only its maker (with Administrators and SYSTEM) may write to — one message each way."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import socket
import stat
import sys
import threading
from pathlib import Path
from typing import Callable

WINDOWS = sys.platform.startswith("win")

MAX_LINE = 64 << 20  # a screenshot answer is the biggest: well under this


MAX_SOCKET_PATH = 100  # Unix sockets take about 108 bytes of path


def _private_folder(folder: Path) -> Path:
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = folder.stat()
    if st.st_uid != os.getuid():  # someone else's folder in /tmp: never use it
        raise PermissionError(f"{folder} belongs to another user.")
    os.chmod(folder, 0o700)
    return folder


def user_runtime_dir(root: str = "/run/user") -> str:
    """/run/user/<uid> — the folder XDG_RUNTIME_DIR names on a systemd system — when it is there and this user's;
    else ''."""
    if not hasattr(os, "getuid"):
        return ""
    folder = Path(root) / str(os.getuid())
    try:
        st = folder.stat()
    except OSError:
        return ""
    return str(folder) if stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() else ""


def socket_path() -> Path:
    """$XDG_RUNTIME_DIR/proxmox-controller/connector.sock (/run/user/<uid>: this user's alone). Without
    XDG_RUNTIME_DIR — Claude Desktop starts the bridge with a bare environment, while the app has it — the same
    /run/user/<uid>, so the two still meet; a private folder in /tmp when neither is there or the path is too long
    for a socket."""
    base = os.environ.get("XDG_RUNTIME_DIR", "") or user_runtime_dir()
    path = Path(base) / "proxmox-controller" / "connector.sock" if base else None
    if path is None or len(str(path)) > MAX_SOCKET_PATH:
        path = Path(f"/tmp/proxmox-controller-{os.getuid()}") / "connector.sock"
    _private_folder(path.parent)
    return path


def pipe_name() -> str:
    """Windows: the app's named pipe. A runtime folder named in XDG_RUNTIME_DIR — not set on Windows, but each test
    names its own — gets a pipe of its own."""
    user = re.sub(r"[^A-Za-z0-9_.-]", "_", getpass.getuser() or "user")
    name = f"proxmox-controller-{user}"
    if os.environ.get("XDG_RUNTIME_DIR"):
        name += "-" + hashlib.sha256(os.environ["XDG_RUNTIME_DIR"].encode()).hexdigest()[:12]
    return "\\\\.\\pipe\\" + name


def link_address() -> str:
    return pipe_name() if WINDOWS else str(socket_path())


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


def request(message: dict, timeout: float = 600.0, path: Path | str | None = None) -> dict:
    """Sends one request to the app and waits for its answer. AppNotRunning if the app is not open."""
    if WINDOWS:
        return _pipe_request(message, timeout, str(path) if path else pipe_name())
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


def _pipe_request(message: dict, timeout: float, address: str) -> dict:
    from multiprocessing.connection import Client
    try:
        conn = Client(address, family="AF_PIPE")
    except FileNotFoundError as e:  # no pipe of that name: the app is not open
        raise AppNotRunning("Proxmox Controller is not running.") from e
    try:
        conn.send_bytes(json.dumps(message).encode())
        if not conn.poll(timeout):
            raise TimeoutError("Proxmox Controller gave no answer in time.")
        data = conn.recv_bytes(MAX_LINE)
    except (EOFError, BrokenPipeError) as e:
        raise AppNotRunning("Proxmox Controller closed the connection.") from e
    finally:
        conn.close()
    return json.loads(data)


class LinkServer:
    """In the app: hears the bridges. handler(message) runs on the connection's own thread and returns the answer."""

    def __init__(self, handler: Callable[[dict], dict], path: Path | str | None = None):
        self.handler = handler
        self.address = str(path) if path else link_address()
        self.path = Path(self.address)  # (the Unix socket's file)
        self.sock: socket.socket | None = None
        self.listener = None  # Windows: the pipe's listener
        self.thread: threading.Thread | None = None
        self.stopping = False

    def start(self) -> bool:
        """False when another Proxmox Controller already answers on the socket (it keeps the connector)."""
        if WINDOWS:
            return self._start_pipe()
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

    # -- Windows: the named pipe ------------------------------------------------------------------

    def _start_pipe(self) -> bool:
        from multiprocessing.connection import Listener
        try:
            self.listener = Listener(self.address, family="AF_PIPE")
        except PermissionError:  # the first pipe of that name is another app's (FILE_FLAG_FIRST_PIPE_INSTANCE)
            return False
        self.thread = threading.Thread(target=self._accept_pipe, daemon=True, name="connector")
        self.thread.start()
        return True

    def _accept_pipe(self) -> None:
        while not self.stopping:
            try:
                conn = self.listener.accept()
            except (OSError, EOFError):
                return
            if self.stopping:  # stop()'s own knock
                conn.close()
                return
            threading.Thread(target=self._serve_pipe, args=(conn,), daemon=True, name="connector-request").start()

    def _serve_pipe(self, conn) -> None:
        try:
            data = conn.recv_bytes(MAX_LINE)
            try:
                answer = self.handler(json.loads(data))
            except Exception as e:  # never leave a bridge without an answer
                answer = {"error": f"{type(e).__name__}: {e}"}
            conn.send_bytes(json.dumps(answer).encode())
        except (OSError, EOFError):
            pass  # the bridge went away (Claude cancelled)
        finally:
            conn.close()

    def stop(self) -> None:
        self.stopping = True
        if self.listener is not None:
            from multiprocessing.connection import Client
            try:  # accept() waits on the pipe without a timeout: a knock wakes it to see it should end
                Client(self.address, family="AF_PIPE").close()
            except OSError:
                pass
            try:
                self.listener.close()
            finally:
                self.listener = None
            return
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
                self.path.unlink(missing_ok=True)
