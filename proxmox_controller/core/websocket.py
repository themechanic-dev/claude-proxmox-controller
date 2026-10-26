"""A small WebSocket (RFC 6455) speaker over an already connected socket — Proxmox carries consoles through one.

    ws = client_handshake(tls_socket, "192.168.1.10:8006", "/api2/json/…/vncwebsocket?…", {"Authorization": …})
    ws.send(b"…");  data = ws.recv()   # None once the other side closed
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class HandshakeError(Exception):
    """The server did not switch to WebSocket; the message is its status line (for example '401 No ticket')."""


def _mask(data: bytes, key: bytes) -> bytes:
    if not data:
        return b""
    pad = (key * (len(data) // 4 + 1))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(pad, "big")).to_bytes(len(data), "big")


class WebSocket:
    def __init__(self, sock: socket.socket, leftover: bytes = b"", client: bool = True):
        self.sock = sock
        self.buf = bytearray(leftover)
        self.client = client  # a client masks what it sends; a server does not
        self.lock = threading.Lock()
        self.closed = False

    def send(self, data: bytes, opcode: int = 2) -> None:
        n = len(data)
        head = bytearray([0x80 | opcode])
        flag = 0x80 if self.client else 0
        if n < 126:
            head.append(flag | n)
        elif n < 65536:
            head.append(flag | 126)
            head += n.to_bytes(2, "big")
        else:
            head.append(flag | 127)
            head += n.to_bytes(8, "big")
        if self.client:
            key = os.urandom(4)
            head += key
            data = _mask(data, key)
        with self.lock:
            self.sock.sendall(bytes(head) + data)

    def recv(self) -> bytes | None:
        """The next whole message, or None when the other side closed the connection."""
        message = bytearray()
        while True:
            try:
                b0, b1 = self._read(2)
            except (ConnectionError, OSError):
                self.closed = True
                return None
            opcode = b0 & 0x0F
            n = b1 & 0x7F
            if n == 126:
                n = int.from_bytes(self._read(2), "big")
            elif n == 127:
                n = int.from_bytes(self._read(8), "big")
            key = self._read(4) if b1 & 0x80 else None
            payload = self._read(n)
            if key:
                payload = _mask(payload, key)
            if opcode == 8:  # close
                self.closed = True
                try:
                    self.send(payload[:2], opcode=8)
                except OSError:
                    pass
                return None
            if opcode == 9:  # ping
                self.send(payload, opcode=10)
                continue
            if opcode == 10:  # pong
                continue
            message += payload
            if b0 & 0x80:
                return bytes(message)

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise ConnectionError("The connection was closed.")
            self.buf += chunk
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.send(b"\x03\xe8", opcode=8)  # 1000: normal closure
            except OSError:
                pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)  # wakes a thread waiting in recv()
        except OSError:
            pass
        self.sock.close()


def client_handshake(sock: socket.socket, host: str, path: str, headers: dict, protocol: str = "binary") -> WebSocket:
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket", "Connection: Upgrade",
             f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13", f"Sec-WebSocket-Protocol: {protocol}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    answer = b""
    while b"\r\n\r\n" not in answer:
        chunk = sock.recv(4096)
        if not chunk:
            raise HandshakeError("the server closed the connection")
        answer += chunk
        if len(answer) > 65536:
            raise HandshakeError("the answer was too long")
    head, _, rest = answer.partition(b"\r\n\r\n")
    status, *header_lines = head.decode("latin-1").split("\r\n")
    parts = status.split(" ", 2)
    if len(parts) < 2 or parts[1] != "101":
        raise HandshakeError(" ".join(parts[1:]) or status)
    fields = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in header_lines)}
    expected = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    if fields.get("sec-websocket-accept") != expected:
        raise HandshakeError("the server's answer did not match the request")
    return WebSocket(sock, rest)


def server_accept_value(key: str) -> str:
    """For a WebSocket server (the tests' pretend Proxmox): the Sec-WebSocket-Accept for a client's key."""
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
