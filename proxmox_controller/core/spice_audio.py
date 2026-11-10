"""A VM's sound over SPICE, for recording its console: only SPICE's main and playback channels, through Proxmox's
spiceproxy, with the same one-time ticket remote-viewer gets (VM.Console).

QEMU gives a Proxmox VM's sound only to SPICE (`-audiodev spice`; its VNC has none — measured, PVE 9.2, 10/11/2026),
so the picture of a recording comes from VNC and its sound from here. The playback channel is opened without the
Opus capability, so QEMU sends plain 16-bit PCM.

A SPICE server takes one client: a new connection ends the one before (spice-server's reds_handle_main_link), so an
open remote-viewer of the same VM and this cannot both have the sound."""

from __future__ import annotations

import socket
import ssl
import struct
import threading
import time
from typing import Callable
from urllib.parse import urlsplit

MAGIC, MAJOR, MINOR = b"REDQ", 2, 2
CAP_MINI_HEADER = 1 << 3                  # common capability: 6-byte message headers
CHANNEL_MAIN, CHANNEL_PLAYBACK = 1, 5
MSG_SET_ACK, MSG_PING, MSG_DISCONNECTING, MSG_NOTIFY = 3, 4, 6, 7
MSGC_ACK_SYNC, MSGC_ACK, MSGC_PONG = 1, 2, 3
MSG_MAIN_INIT, MSGC_MAIN_ATTACH_CHANNELS = 103, 104
MSG_PLAYBACK_DATA, MSG_PLAYBACK_MODE, MSG_PLAYBACK_START, MSG_PLAYBACK_STOP = 101, 102, 103, 104
AUDIO_FMT_S16 = 1
DATA_MODE_RAW = 1


class SpiceError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("The SPICE connection was closed.")
        data += chunk
    return bytes(data)


def _subject(cert: dict) -> dict:
    return {k: v for part in cert.get("subject", ()) for k, v in part}


def _wanted_subject(text: str) -> dict:
    names = {"CN": "commonName", "O": "organizationName", "OU": "organizationalUnitName", "C": "countryName",
             "ST": "stateOrProvinceName", "L": "localityName"}
    out = {}
    for part in text.split(","):
        k, _, v = part.strip().partition("=")
        if k.strip() in names:
            out[names[k.strip()]] = v.strip()
    return out


def connect_request(cfg: dict) -> bytes:
    """The proxy's CONNECT. spiceproxy reads the ticket from the Host header, not from the CONNECT line (PVE
    APIServer/AnyEvent.pm): without it, '401 invalid ticket' (measured 10/11/2026)."""
    target = f"{cfg['host']}:{cfg['tls-port']}"
    return f"CONNECT {target} HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()


def open_channel_socket(cfg: dict, timeout: float = 10.0) -> ssl.SSLSocket:
    """Through spiceproxy (an HTTP proxy on the host, port 3128) to the VM's SPICE TLS port, checked against Proxmox's
    own CA and the node's certificate subject, as remote-viewer checks them."""
    proxy = urlsplit(str(cfg["proxy"]))
    sock = socket.create_connection((proxy.hostname, proxy.port or 3128), timeout=timeout)
    try:
        sock.sendall(connect_request(cfg))
        answer = b""
        while b"\r\n\r\n" not in answer:
            chunk = sock.recv(1024)
            if not chunk:
                raise SpiceError("Proxmox's SPICE proxy closed the connection.")
            answer += chunk
        status = answer.split(b"\r\n", 1)[0]
        if b" 200" not in status:
            raise SpiceError(f"Proxmox's SPICE proxy refused it: {status.decode('latin-1')}")
        ctx = ssl.create_default_context(cadata=str(cfg["ca"]).replace("\\n", "\n"))
        ctx.check_hostname = False  # the host here is a ticket, not a name; the subject is checked instead
        tls = ctx.wrap_socket(sock)
        wanted = _wanted_subject(str(cfg.get("host-subject", "")))
        got = _subject(tls.getpeercert() or {})
        if wanted and any(got.get(k) != v for k, v in wanted.items()):
            tls.close()
            raise SpiceError("The SPICE certificate is not the node's.")
        return tls
    except BaseException:
        sock.close()
        raise


def link(sock: ssl.SSLSocket, password: str, connection_id: int, channel_type: int,
         channel_caps: tuple = ()) -> None:
    """SPICE's link: the channel asked for, the server's RSA key, the ticket encrypted with it (RSA-OAEP, SHA-1)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    caps = (CAP_MINI_HEADER,) + tuple(channel_caps)
    body = struct.pack("<IBBIII", connection_id, channel_type, 0, 1, len(channel_caps), 18)
    body += b"".join(struct.pack("<I", c) for c in caps)
    sock.sendall(struct.pack("<4sIII", MAGIC, MAJOR, MINOR, len(body)) + body)
    magic, major, _minor, size = struct.unpack("<4sIII", _recv_exact(sock, 16))
    if magic != MAGIC or major != MAJOR:
        raise SpiceError("This is not a SPICE server this app knows.")
    reply = _recv_exact(sock, size)
    error = struct.unpack_from("<I", reply)[0]
    if error:
        raise SpiceError(f"The SPICE server refused the channel (error {error}).")
    n_common, _n_channel, offset = struct.unpack_from("<III", reply, 166)
    common = struct.unpack_from("<I", reply, offset)[0] if n_common else 0
    if not common & CAP_MINI_HEADER:
        raise SpiceError("The SPICE server has no mini headers.")
    key = serialization.load_der_public_key(reply[4:166])
    sock.sendall(key.encrypt(password.encode() + b"\0", padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)))
    result = struct.unpack("<I", _recv_exact(sock, 4))[0]
    if result:
        raise SpiceError(f"The SPICE server refused the ticket (error {result}).")


class Channel:
    """One linked channel: messages in, the acknowledgements and pongs SPICE expects out."""

    def __init__(self, sock: ssl.SSLSocket):
        self.sock = sock
        self.window = 0
        self.unacked = 0
        self.lock = threading.Lock()

    def send(self, kind: int, payload: bytes = b"") -> None:
        with self.lock:
            self.sock.sendall(struct.pack("<HI", kind, len(payload)) + payload)

    def receive(self) -> tuple[int, bytes]:
        """The next message for the caller; the channel's own bookkeeping answered here."""
        while True:
            kind, size = struct.unpack("<HI", _recv_exact(self.sock, 6))
            payload = _recv_exact(self.sock, size) if size else b""
            if self.window:
                self.unacked += 1
                if self.unacked >= self.window:
                    self.unacked = 0
                    self.send(MSGC_ACK)
            if kind == MSG_SET_ACK:
                generation, self.window = struct.unpack_from("<II", payload)
                self.send(MSGC_ACK_SYNC, struct.pack("<I", generation))
            elif kind == MSG_PING:
                self.send(MSGC_PONG, payload[:12])
            else:
                return kind, payload

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class SpiceAudio:
    """The sound of a running VM: on_start(channels, rate) once the guest plays, then on_data(pcm) with 16-bit
    little-endian samples, interleaved. stop() ends it; `ended` says why it ended, if not by stop()."""

    def __init__(self, cfg: dict, on_start: Callable[[int, int], None], on_data: Callable[[bytes], None],
                 timeout: float = 10.0, opener: Callable[[dict, float], socket.socket] = open_channel_socket):
        self.cfg, self.on_start, self.on_data, self.timeout = cfg, on_start, on_data, timeout
        self.opener = opener  # (the tests give a plain socket to a pretend SPICE server)
        self.main: Channel | None = None
        self.playback: Channel | None = None
        self.session = 0
        self.stopping = False
        self.ended = ""

    def start(self) -> None:
        sock = self.opener(self.cfg, self.timeout)
        link(sock, str(self.cfg["password"]), 0, CHANNEL_MAIN)
        self.main = Channel(sock)
        deadline = time.monotonic() + self.timeout
        while not self.session:
            if time.monotonic() > deadline:
                raise SpiceError("The SPICE server did not start the session.")
            kind, payload = self.main.receive()
            if kind == MSG_MAIN_INIT:
                self.session = struct.unpack_from("<I", payload)[0]
        self.main.send(MSGC_MAIN_ATTACH_CHANNELS)
        sock = self.opener(self.cfg, self.timeout)
        link(sock, str(self.cfg["password"]), self.session, CHANNEL_PLAYBACK)  # no Opus: plain PCM
        self.playback = Channel(sock)
        for ch in (self.main, self.playback):
            ch.sock.settimeout(None)
        threading.Thread(target=self._read_main, daemon=True, name="spice-main").start()
        threading.Thread(target=self._read_playback, daemon=True, name="spice-playback").start()

    def _end(self, why: str) -> None:
        if not self.stopping and not self.ended:
            self.ended = why

    def _read_main(self) -> None:
        try:
            while True:
                kind, _ = self.main.receive()
                if kind == MSG_DISCONNECTING:
                    self._end("the SPICE server ended the session (another viewer connected?)")
                    return
        except (OSError, ConnectionError, struct.error) as e:
            self._end(f"the SPICE connection closed ({e})")

    def _read_playback(self) -> None:
        try:
            while True:
                kind, payload = self.playback.receive()
                if kind == MSG_PLAYBACK_START:
                    channels, fmt, rate, _t = struct.unpack_from("<IHII", payload)
                    if fmt != AUDIO_FMT_S16:
                        self._end(f"the guest's sound came in a format this app does not know ({fmt})")
                        return
                    self.on_start(channels, rate)
                elif kind == MSG_PLAYBACK_MODE:
                    mode = struct.unpack_from("<IH", payload)[1]
                    if mode != DATA_MODE_RAW:
                        self._end(f"the guest's sound came compressed ({mode})")
                        return
                elif kind == MSG_PLAYBACK_DATA:
                    self.on_data(payload[4:])
        except (OSError, ConnectionError, struct.error) as e:
            self._end(f"the SPICE sound closed ({e})")

    def stop(self) -> None:
        self.stopping = True
        for ch in (self.playback, self.main):
            if ch is not None:
                ch.close()
