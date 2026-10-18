"""The connector as Claude sees it: an MCP server on standard input and output, started by Claude Desktop, Claude Code
or Cowork as `proxmox-controller --mcp`. It holds no key and decides nothing: each request goes to the running app,
which checks the switches, asks the user when a switch says Ask, and does it with Claude's own token.

The protocol is JSON-RPC 2.0, one message a line (MCP's stdio transport). Only tools are offered."""

from __future__ import annotations

import json
import sys
import threading
import uuid

from .. import VERSION
from . import connector_link
from .connector_tools import INSTRUCTIONS, TOOLS

PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")  # newest first
PROGRESS_EVERY_S = 10  # while a request waits (for the user's approval, a long task), so the caller keeps waiting
NOT_RUNNING = ("Proxmox Controller is not running on the user's computer (or is still locked). Ask the user to open "
               "and unlock it, then try again.")


def tool_error(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def tool_list() -> list[dict]:
    out = []
    for t in TOOLS.values():
        kind = t.kind if isinstance(t.kind, str) else "change"
        out.append({"name": t.name, "description": t.description, "inputSchema": t.schema(),
                    "annotations": {"readOnlyHint": kind == "read",
                                    "destructiveHint": kind in ("destroy", "host") or callable(t.kind),
                                    "idempotentHint": kind == "read", "openWorldHint": False}})
    return out


class Bridge:
    def __init__(self, out=None, call=connector_link.request):
        self.out = out or sys.stdout
        self.call = call
        self.lock = threading.Lock()
        self.client = "Claude"
        self.inflight: dict = {}  # JSON-RPC id → the key the app knows the request by
        self.threads: list[threading.Thread] = []

    def send(self, message: dict) -> None:
        with self.lock:
            self.out.write(json.dumps(message, ensure_ascii=False) + "\n")
            self.out.flush()

    def reply(self, mid, result: dict) -> None:
        self.send({"jsonrpc": "2.0", "id": mid, "result": result})

    def fail(self, mid, code: int, message: str) -> None:
        self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})

    def handle(self, msg: dict) -> None:
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if method == "initialize":
            asked = params.get("protocolVersion")
            info = params.get("clientInfo") or {}
            self.client = str(info.get("title") or info.get("name") or "Claude")
            self.reply(mid, {"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                             "capabilities": {"tools": {"listChanged": False}},
                             "serverInfo": {"name": "proxmox-controller", "title": "Proxmox Controller",
                                            "version": VERSION},
                             "instructions": INSTRUCTIONS})
        elif method == "ping":
            self.reply(mid, {})
        elif method == "tools/list":
            self.reply(mid, {"tools": tool_list()})
        elif method == "tools/call":
            t = threading.Thread(target=self._call, args=(mid, params), daemon=False, name="mcp-call")
            self.threads.append(t)
            t.start()
        elif method == "notifications/cancelled":  # Claude gave up waiting: the app closes its approval window
            key = self.inflight.get(params.get("requestId"))
            if key:
                try:
                    self.call({"cancel": key}, timeout=5)
                except (connector_link.AppNotRunning, OSError, ValueError):
                    pass
        elif mid is None:
            pass  # other notifications need no answer
        else:
            self.fail(mid, -32601, f"Method not found: {method}")

    def _call(self, mid, params: dict) -> None:
        key = uuid.uuid4().hex
        self.inflight[mid] = key
        token = (params.get("_meta") or {}).get("progressToken")
        stop = threading.Event()
        if token is not None:
            threading.Thread(target=self._progress, args=(token, stop), daemon=True).start()
        try:
            answer = self.call({"key": key, "tool": params.get("name"), "args": params.get("arguments") or {},
                                "client": self.client})
            result = answer.get("result") or tool_error(str(answer.get("error") or "Proxmox Controller gave no answer."))
        except connector_link.AppNotRunning:
            result = tool_error(NOT_RUNNING)
        except (OSError, ValueError) as e:
            result = tool_error(f"The connection to Proxmox Controller failed: {e}")
        finally:
            stop.set()
            self.inflight.pop(mid, None)
        self.reply(mid, result)

    def _progress(self, token, stop: threading.Event) -> None:
        n = 0
        while not stop.wait(PROGRESS_EVERY_S):
            n += 1
            self.send({"jsonrpc": "2.0", "method": "notifications/progress",
                       "params": {"progressToken": token, "progress": n,
                                  "message": "Waiting for Proxmox Controller (the user's approval, or a task)…"}})


def serve(lines, bridge: Bridge) -> None:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            bridge.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        if not isinstance(msg, dict):
            bridge.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}})
            continue
        bridge.handle(msg)
    for t in bridge.threads:  # answers still owed when Claude closed the input
        t.join()


def use_utf8(stdin, stdout) -> None:
    """MCP talks UTF-8, one message a line. Windows would give a program's pipes its ANSI code page instead — cp1252
    turned the — of the tools' descriptions into the byte 0x97 (measured), which is not UTF-8 — and \r\n for \n."""
    for stream, newline in ((stdin, None), (stdout, "\n")):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", newline=newline)


def main() -> int:
    use_utf8(sys.stdin, sys.stdout)
    serve(sys.stdin, Bridge())
    return 0
