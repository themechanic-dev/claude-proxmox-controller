"""A local HTTPS server that answers like the Proxmox API (FakeCluster behind it), for the tests.

The certificate is self-signed and made with the `openssl` command on the fly.
"""

from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from proxmox_controller.core.fakecluster import FakeCluster
from proxmox_controller.core.fakevnc import FakeVncServer
from proxmox_controller.core.websocket import WebSocket, server_accept_value


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def parse_multipart(body: bytes, boundary: str) -> dict:
    """Just enough of multipart/form-data for an upload: plain fields, and a file part as its name and size."""
    out = {}
    for part in body.split(b"--" + boundary.encode())[1:]:
        if part.startswith(b"--"):
            break
        head, _, data = part.partition(b"\r\n\r\n")
        data = data[:-2] if data.endswith(b"\r\n") else data
        disposition = head.decode(errors="replace")
        name = disposition.split('name="', 1)[1].split('"', 1)[0]
        if 'filename="' in disposition:
            out[name] = disposition.split('filename="', 1)[1].split('"', 1)[0]
            out["size"] = str(len(data))
            out["data"] = data
        else:
            out[name] = data.decode()
    return out


class FakePveServer:
    def __init__(self):
        self.cluster = FakeCluster()
        self.requests: list[tuple[str, str, str]] = []  # (method, path, auth header)
        self.drop: list[str] = []  # the next requests whose path ends so get no answer: the connection just closes
        self.consoles: list[FakeVncServer] = []
        self.tmp = tempfile.TemporaryDirectory()
        key, cert = Path(self.tmp.name) / "key.pem", Path(self.tmp.name) / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-days", "2", "-subj", "/CN=pve.test"],
                       check=True, capture_output=True)
        self.cert_der = ssl.PEM_cert_to_DER_cert(cert.read_text())
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _console(self, path, params, auth):
                """vncwebsocket: check the token and the ticket like Proxmox, switch to WebSocket, then be the VM's
                screen (FakeVncServer) on this connection until the client leaves."""
                port = int(params.get("port", 0))
                session = server.cluster.vnc.get(port)
                if auth != f"PVEAPIToken={server.cluster.token}" or not session or \
                        params.get("vncticket") != session["ticket"]:
                    self.send_response(401, "No ticket")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(101, "Switching Protocols")
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", server_accept_value(self.headers["Sec-WebSocket-Key"]))
                self.send_header("Sec-WebSocket-Protocol", "binary")
                self.end_headers()
                self.wfile.flush()
                vnc = FakeVncServer(WebSocket(self.connection, client=False), session["password"], 80, 60,
                                    ext_keys=session["kind"] == "qemu")
                server.consoles.append(vnc)
                vnc.serve()
                self.close_connection = True

            def _serve(self):
                parts = urlsplit(self.path)
                params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parts.query).items()}
                length = int(self.headers.get("Content-Length") or 0)
                ctype = self.headers.get("Content-Type", "")
                if length and ctype.startswith("application/json"):
                    params.update(json.loads(self.rfile.read(length)))
                elif length and ctype.startswith("multipart/form-data"):
                    body = self.rfile.read(length)
                    if len(body) < length:  # the client stopped mid-upload (cancelled): Proxmox keeps nothing
                        self.close_connection = True
                        return
                    params.update(parse_multipart(body, ctype.split("boundary=", 1)[1]))
                elif length:
                    params.update({k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()})
                auth = self.headers.get("Authorization", "")
                path = unquote(parts.path.removeprefix("/api2/json"))
                server.requests.append((self.command, path, auth))
                if server.drop and path.endswith(server.drop[0]):  # an answer lost on the way (the network)
                    server.drop.pop(0)
                    self.close_connection = True
                    return
                if self.headers.get("Upgrade", "").lower() == "websocket" and path.endswith("/vncwebsocket"):
                    self._console(path, params, auth)
                    return
                status, reason, payload = server.cluster.handle(self.command, path, params, auth)
                body = json.dumps(payload).encode()
                self.send_response(status, reason)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_DELETE = _serve

        class QuietServer(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass  # clients that hang up on purpose (certificate mismatch tests) are not errors

        self.httpd = QuietServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()
