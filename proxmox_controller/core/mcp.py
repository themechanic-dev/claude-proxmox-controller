"""The connector as Claude sees it: an MCP server on standard input and output, started by Claude Desktop, Claude Code
or Cowork as `proxmox-controller --mcp`. It holds no key and decides nothing: each request goes to the running app,
which checks the switches, asks the user when a switch says Ask, and does it with Claude's own token.

The protocol is JSON-RPC 2.0, one message a line (MCP's stdio transport). Only tools are offered.

A request still going after ANSWER_BY_S — the user has not answered its approval window yet, or its work goes on — is
answered "waiting", with an id: Claude goes on with wait_for_request (answered here, by the bridge). Some clients give
up on a request at 60 seconds whatever the progress notes say (measured 26/10: Claude's desktop app, 60.0 s each
time), while the approval window gives the user two minutes — and a request approved at 58 s went on to make its VM
after Claude had been told it timed out, so it was asked again and made twice."""

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
ANSWER_BY_S = 45  # a request not done by then is answered "waiting" (well inside a client's 60 s)
WAIT_TOOL = "wait_for_request"
NOT_RUNNING = ("Proxmox Controller is not running on the user's computer (or is still locked). Ask the user to open "
               "and unlock it, then try again.")


def tool_error(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def wait_tool() -> dict:
    return {"name": WAIT_TOOL,
            "description": ("Go on waiting for a request that came back with status 'waiting' (the user has not "
                            "answered its approval window yet, or its work is still going): gives that request's "
                            "answer when there is one, or 'waiting' again after about 45 seconds — then call this "
                            "again. Nothing is asked of the user, and no reason is needed."),
            "inputSchema": {"type": "object",
                            "properties": {"request": {"type": "string",
                                                       "description": "The id the 'waiting' answer gave."}},
                            "required": ["request"], "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
                            "openWorldHint": False}}


def waiting_result(job: Job) -> dict:
    text = json.dumps({"status": "waiting", "request": job.ticket, "tool": job.tool,
                       "note": ("Not answered yet: the user has not decided in the app's approval window (it gives "
                                "them two minutes), or the work is still going. Call wait_for_request with this "
                                "request to go on waiting. Do not send the request again: it would be asked, or "
                                "done, twice.")}, ensure_ascii=False, indent=1)
    return {"content": [{"type": "text", "text": text}], "isError": False}


class Job:
    """One request handed to the app, and its answer once the app gives it."""

    def __init__(self, tool: str):
        self.key = uuid.uuid4().hex  # what the app knows it by
        self.ticket = self.key[:12]  # what Claude is given to wait for it with
        self.tool = tool
        self.result: dict | None = None
        self.done = threading.Event()


def tool_list() -> list[dict]:
    out = []
    for t in TOOLS.values():
        kind = t.kind if isinstance(t.kind, str) else "change"
        out.append({"name": t.name, "description": t.description, "inputSchema": t.schema(),
                    "annotations": {"readOnlyHint": kind == "read",
                                    "destructiveHint": kind in ("destroy", "host") or callable(t.kind),
                                    "idempotentHint": kind == "read", "openWorldHint": False}})
    out.append(wait_tool())
    return out


class Bridge:
    def __init__(self, out=None, call=connector_link.request):
        self.out = out or sys.stdout
        self.call = call
        self.lock = threading.Lock()
        self.client = "Claude"
        self.inflight: dict = {}  # JSON-RPC id → the key the app knows the request by
        self.pending: dict[str, Job] = {}  # ticket → a request answered "waiting"
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
        if params.get("name") == WAIT_TOOL:
            ticket = str((params.get("arguments") or {}).get("request", ""))
            job = self.pending.get(ticket)
            if job is None:
                self.reply(mid, tool_error(f"No request '{ticket}' is waiting: it was answered already, or the "
                                           "connector started again since. If you do not know how it ended, check "
                                           "(list_guests, list_tasks) before asking again."))
                return
        else:
            job = Job(str(params.get("name")))
            threading.Thread(target=self._ask_app, args=(job, params), daemon=True, name="mcp-app").start()
        self._answer(mid, job, params)

    def _ask_app(self, job: Job, params: dict) -> None:
        try:
            answer = self.call({"key": job.key, "tool": job.tool, "args": params.get("arguments") or {},
                                "client": self.client})
            result = answer.get("result") or tool_error(str(answer.get("error") or "Proxmox Controller gave no answer."))
        except connector_link.AppNotRunning:
            result = tool_error(NOT_RUNNING)
        except (OSError, ValueError) as e:
            result = tool_error(f"The connection to Proxmox Controller failed: {e}")
        job.result = result
        job.done.set()

    def _answer(self, mid, job: Job, params: dict) -> None:
        """The request's answer to call mid — or, not done within ANSWER_BY_S, "waiting" and its ticket."""
        self.inflight[mid] = job.key  # (a cancel of a wait gives up the request too: Claude was stopped)
        token = (params.get("_meta") or {}).get("progressToken")
        stop = threading.Event()
        if token is not None:
            threading.Thread(target=self._progress, args=(token, stop), daemon=True).start()
        try:
            finished = job.done.wait(ANSWER_BY_S)
        finally:
            stop.set()
            self.inflight.pop(mid, None)
        if finished:
            self.pending.pop(job.ticket, None)
            self.reply(mid, job.result)
        else:
            self.pending[job.ticket] = job
            self.reply(mid, waiting_result(job))

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
