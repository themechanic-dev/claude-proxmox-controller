"""The connector's tools: what Claude can ask the app to do. Each belongs to one of the kinds of claude_policy,
says what it needs (JSON Schema, for Claude) and says in words what it would do (for the user's approval window and
the log).

They run off the window's thread with Claude's own token (ctx.pve), so Proxmox checks every one of them against the
privileges the switches give that token. The user's token (ctx.admin) is used only by the app itself: to find which
node a guest is on, and to read what a change would replace so the user sees it before allowing it. Nothing read with
the user's token is handed to Claude."""

from __future__ import annotations

import base64
import math
import re
import shlex
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from . import (claude_policy, cloudseed, cloudvm, guestfiles, screen, setupdisc, ssh, startup, tasks, timezones, vmhw,
               winsetup, wol)
from .cloudvm import CLOUD_IMAGES, CLOUD_URL, USERNAME
from .details import read_details
from .pve import Host, Pve, PveError, backup_kind, backup_name
from .vmspec import PROFILES, VIRTIO_AS_SYSTEM, VMNAME, WINDOWS, is_virtio_disc, iso_name_from_url, vm_params

WAIT_S = 60          # a request waits this long for its Proxmox task; longer ones are followed with task_log
LOG_LINES = 200      # the most lines task_log returns at a time
EXEC_WAIT_S = 120    # the longest a command inside a VM (or on the host) may run
HOST_OUTPUT_MAX = 20000  # characters of a host command's output (and of its errors) given back: its start and end
SNAPNAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,39}$")
HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
CIDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# Ubuntu's official cloud images (cloud-images.ubuntu.com): release → size in MB (measured 14/10/2026)


class ToolError(Exception):
    """A request that cannot be done as asked: the message goes back to Claude."""


@dataclass
class Tool:
    name: str
    kind: str | Callable[[dict], str]       # one of claude_policy.KEYS, or chosen from the arguments
    description: str
    params: dict
    required: tuple = ()
    run: Callable | None = None              # (ctx, args) → result (JSON-able, or an Image)
    words: Callable | None = None            # (ctx, args) → (what, [details]) for the user
    reason: bool = True                      # a non-read request must say why
    secret: str | Callable[[dict], str] = ""  # a password the USER types in the app's window (never Claude): the prompt
    secret_repeat: bool | Callable[[dict], bool] = True  # asked twice (a new password) or once (an existing one)
    secret_min: int = 1                      # Proxmox's own minimum, where it has one (a container's root: 5)
    also: tuple | Callable[[dict], tuple] = ()  # other kinds a request may use in passing (a new VM's start: power)
    doc_kinds: tuple = ()                    # where a tool whose kind comes from its arguments is listed (Help, docs)

    def also_of(self, args: dict) -> tuple:
        return self.also(args) if callable(self.also) else self.also

    def secret_prompt(self, args: dict) -> str:
        return self.secret(args) if callable(self.secret) else self.secret

    def repeat_secret(self, args: dict) -> bool:
        return self.secret_repeat(args) if callable(self.secret_repeat) else self.secret_repeat

    def kind_of(self, args: dict) -> str:
        return self.kind(args) if callable(self.kind) else self.kind

    def schema(self) -> dict:
        props = dict(self.params)
        req = list(self.required)
        if self.reason:
            props["reason"] = REASON
            req.append("reason")
        return {"type": "object", "properties": props, "required": req, "additionalProperties": False}


@dataclass
class Image:
    png: bytes
    text: str = ""

    def b64(self) -> str:
        return base64.b64encode(self.png).decode("ascii")


@dataclass
class Context:
    host: Host
    pve: Pve                       # Claude's token
    admin: Pve | None = None       # the user's token: finding guests, showing the user what changes
    wake: Callable[[str, str], None] = wol.send
    secret: str = field(default="", repr=False)  # what the user typed in the app's window, for this request only
    kinds: frozenset = frozenset(("read", "power", "change", "destroy", "host", "console", "commands"))  # not Off
    showing: bool = False          # the request goes to the user's window: its words may bring a picture
    _guests: list | None = field(default=None, repr=False)
    pointers: dict = field(default_factory=dict, repr=False)  # vmid → (state, mouse), read once a request
    remember: Callable[[dict], None] | None = None  # the app keeps a new VM's setup disc, to take it away when set up

    def guests(self) -> list[dict]:
        if self._guests is None:
            self._guests = (self.admin or self.pve).guests()
        return self._guests

    def guest(self, vmid) -> dict:
        try:
            vmid = int(vmid)
        except (TypeError, ValueError) as e:
            raise ToolError("vmid must be a number.") from e
        for g in self.guests():
            if g["vmid"] == vmid:
                return g
        raise ToolError(f"There is no guest {vmid} on {self.host.name}.")

    def node(self, wanted: str = "") -> str:
        nodes = [n["node"] for n in (self.admin or self.pve).nodes() if n.get("status", "online") == "online"]
        if wanted:
            if wanted not in nodes:
                raise ToolError(f"No online node '{wanted}'. Nodes: {', '.join(nodes) or 'none'}.")
            return wanted
        if not nodes:
            raise ToolError(f"{self.host.name} has no online node.")
        return nodes[0]


def what(g: dict) -> str:
    return f"{'Container' if g['type'] == 'lxc' else 'VM'} {g['vmid']} ({g.get('name', '')})"


# -- arguments -------------------------------------------------------------------------------------

HOST = {"type": "string", "description": "The host's id, from list_hosts."}
VMID = {"type": "integer", "description": "The guest's ID (VMID)."}
REASON = {"type": "string", "description": "Why you are doing this, in a sentence. The user sees it in the approval "
                                           "window and in the log."}


def check(tool: Tool, args: dict) -> dict:
    """The arguments as the schema says, or ToolError naming what is wrong."""
    if not isinstance(args, dict):
        raise ToolError("The arguments must be an object.")
    schema = tool.schema()
    unknown = [k for k in args if k not in schema["properties"]]
    if unknown:
        raise ToolError(f"Unknown argument(s): {', '.join(unknown)}.")
    missing = [k for k in schema["required"] if args.get(k) in (None, "")]
    if missing:
        raise ToolError(f"Missing: {', '.join(missing)}.")
    types = {"string": str, "integer": int, "boolean": bool, "array": list, "object": dict, "number": (int, float)}
    for k, v in args.items():
        spec = schema["properties"][k]
        want = types.get(spec.get("type"))
        if want and (not isinstance(v, want) or (spec.get("type") in ("integer", "number") and isinstance(v, bool))):
            raise ToolError(f"{k} must be {spec['type']}.")
        if "enum" in spec and v not in spec["enum"]:
            raise ToolError(f"{k} must be one of: {', '.join(map(str, spec['enum']))}.")
        if spec.get("type") == "integer":
            if "minimum" in spec and v < spec["minimum"] or "maximum" in spec and v > spec["maximum"]:
                raise ToolError(f"{k} must be from {spec.get('minimum')} to {spec.get('maximum')}.")
    return args


# -- waiting for Proxmox -----------------------------------------------------------------------------

def finish(ctx: Context, node: str, upid, wait: float = WAIT_S) -> dict:
    """Waits for the task a request started. A failure is a ToolError with Proxmox's own words; a task still running
    after `wait` comes back as running, to be followed with task_log."""
    if not (isinstance(upid, str) and upid.startswith("UPID:")):
        return {"status": "done"}
    end = time.monotonic() + wait
    while True:
        st = ctx.pve.task_status(node, upid)
        if st.get("status") == "stopped":
            status = st.get("exitstatus") or ""
            if not tasks.done(status):
                tail = [e.get("t", "") for e in ctx.pve.task_log(node, upid)[-8:]]
                raise ToolError(f"The task failed: {status or 'unknown error'}.\n" + "\n".join(tail))
            if status != "OK":  # done, with warnings: what they say, the rest is in task_log
                said = [e.get("t", "") for e in ctx.pve.task_log(node, upid) if str(e.get("t", "")).startswith("WARN")]
                return {"status": "done", "task": upid, "warnings": said or [status],
                        "note": f"Done, with {status.lower()}; task_log has the whole text."}
            return {"status": "done", "task": upid}
        if time.monotonic() > end:
            return {"status": "running", "task": upid,
                    "note": f"Still running after {int(wait)} s; follow it with task_log or list_tasks."}
        time.sleep(1.0)


# -- Read ------------------------------------------------------------------------------------------

def _host_status(ctx: Context, a: dict):
    out = {"host": ctx.host.name, "version": ctx.pve.version().get("version"), "nodes": []}
    for n in ctx.pve.nodes():
        node = {"node": n["node"], "status": n.get("status")}
        if n.get("status", "online") == "online":
            st = ctx.pve.node_status(n["node"])
            mem, root = st.get("memory") or {}, st.get("rootfs") or {}
            node.update(cpu_percent=round(st.get("cpu", 0) * 100, 1), cpus=(st.get("cpuinfo") or {}).get("cpus"),
                        memory_used_gib=round(mem.get("used", 0) / 2**30, 1),
                        memory_total_gib=round(mem.get("total", 0) / 2**30, 1),
                        system_disk_used_gib=round(root.get("used", 0) / 2**30, 1),
                        system_disk_total_gib=round(root.get("total", 0) / 2**30, 1),
                        uptime_s=st.get("uptime"), load=st.get("loadavg"),
                        storages=[{"storage": s["storage"], "type": s.get("type"), "content": s.get("content"),
                                   "used_gib": round(s.get("used", 0) / 2**30, 1),
                                   "total_gib": round(s.get("total", 0) / 2**30, 1)}
                                  for s in ctx.pve.storages(n["node"]) if s.get("total")])
        out["nodes"].append(node)
    return out


def _list_guests(ctx: Context, a: dict):
    guests = sorted(ctx.pve.guests(), key=lambda g: g["vmid"])
    details = read_details(ctx.pve, guests)
    out = []
    for g in guests:
        d = details.get(g["vmid"], {})
        running = g.get("status") == "running"
        out.append({"vmid": g["vmid"], "name": g.get("name", ""), "type": "container" if g["type"] == "lxc" else "vm",
                    "status": g.get("status"), "template": bool(g.get("template")), "node": g.get("node"),
                    "cpu_percent": round(g.get("cpu", 0) * 100, 1) if running else None, "cores": g.get("maxcpu"),
                    "memory_mib": round((g.get("mem") or 0) / 2**20) if running else None,
                    "memory_max_mib": round((g.get("maxmem") or 0) / 2**20),
                    "disk_gib": round((g.get("maxdisk") or 0) / 2**30, 1), "uptime_s": g.get("uptime") if running else None,
                    "tags": [t for t in re.split(r"[;,\s]+", g.get("tags", "")) if t], "ips": d.get("ips", []),
                    "start_at_boot": d.get("onboot", False), "boot_order": startup.parse(d.get("startup", ""))["order"],
                    "notes": d.get("notes", "")})
    return out


def _guest_details(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    cfg = ctx.pve.guest_config(g["node"], g["type"], g["vmid"])
    out = {"guest": what(g), "status": g.get("status"), "node": g["node"], "config": cfg}
    if g["type"] == "qemu":
        try:
            out["pending_until_next_start"] = ctx.pve.pending(g["node"], g["vmid"])
        except PveError:
            pass
    return out


def _snapshots(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    snaps = ctx.pve.snapshots(g["node"], g["type"], g["vmid"])
    return [{"name": s["name"], "description": s.get("description", ""), "time": s.get("snaptime"),
             "parent": s.get("parent")} for s in snaps if s.get("name") != "current"]


def _backups(ctx: Context, a: dict):
    """Read with the user's token: Proxmox leaves out, without a word, the backups a token may not make (VM.Backup) —
    and Claude's token only reads at rest, so with it every guest looked as if it had none. A guest deleted since
    is looked for by its old ID on every node (its backups stay — the protected ones always)."""
    reader = ctx.admin or ctx.pve
    try:
        g = ctx.guest(a["vmid"])
        vmid, nodes = g["vmid"], [g["node"]]
    except ToolError:
        vmid = int(a["vmid"])  # (a number: ctx.guest refuses anything else)
        nodes = [n["node"] for n in reader.nodes() if n.get("status", "online") == "online"]
    out, seen = [], set()
    for node in nodes:
        for b in reader.backups(node, vmid):
            if b["volid"] not in seen:  # a shared storage answers on every node
                seen.add(b["volid"])
                out.append({"volid": b["volid"], "storage": b.get("storage"), "time": b.get("ctime"),
                            "size_gib": round((b.get("size") or 0) / 2**30, 2), "notes": b.get("notes", ""),
                            "protected": bool(b.get("protected"))})
    return sorted(out, key=lambda b: b["time"] or 0, reverse=True)


def _backup_jobs(ctx: Context, a: dict):
    from . import jobs
    names = {g["vmid"]: g.get("name", "") for g in ctx.guests()}
    out = [{"id": j.get("id"), "enabled": str(j.get("enabled", 1)) == "1",
            "when": jobs.describe_schedule(j.get("schedule", "")), "schedule": j.get("schedule"),
            "guests": jobs.describe_guests(j, names), "storage": j.get("storage"), "mode": j.get("mode"),
            "keeps": jobs.describe_keep(j.get("prune-backups")), "comment": j.get("comment", "")}
           for j in ctx.pve.backup_jobs()]
    uncovered = [{"vmid": g["vmid"], "name": g.get("name")} for g in ctx.pve.not_backed_up()]
    return {"jobs": out, "guests_no_job_covers": uncovered}


def _list_tasks(ctx: Context, a: dict):
    names = {g["vmid"]: g for g in ctx.guests()}
    rows = []
    for node in [n["node"] for n in ctx.pve.nodes() if n.get("status", "online") == "online"]:
        rows += ctx.pve.tasks(node, limit=int(a.get("limit", 20)))
    rows.sort(key=lambda t: int(t.get("starttime") or 0), reverse=True)
    return [{"upid": t.get("upid"), "node": t.get("node"), "what": tasks.describe(t, names),
             "started": t.get("starttime"), "ended": t.get("endtime"), "status": tasks.outcome(t),
             "user": t.get("user")} for t in rows[:int(a.get("limit", 20))]]


def _task_log(ctx: Context, a: dict):
    upid = a["upid"]
    node = upid.split(":")[1] if upid.count(":") > 2 else ctx.node()
    start = int(a.get("start", 0))
    entries = ctx.pve.task_log(node, upid, start=start, limit=LOG_LINES)
    st = ctx.pve.task_status(node, upid)
    lines = [e.get("t", "") for e in entries]
    return {"status": st.get("status"), "exit": st.get("exitstatus"), "lines": lines,
            "next_start": start + len(lines) if len(lines) >= LOG_LINES else None}


def _usage(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    rows = [r for r in ctx.pve.rrd(g["node"], g["type"], g["vmid"], a.get("timeframe", "hour")) if r.get("time")]

    def stats(key, scale=1.0, digits=1):
        vals = [r[key] * scale for r in rows if isinstance(r.get(key), (int, float))]
        return {"avg": round(sum(vals) / len(vals), digits), "max": round(max(vals), digits)} if vals else None

    return {"guest": what(g), "timeframe": a.get("timeframe", "hour"), "points": len(rows),
            "cpu_percent": stats("cpu", 100), "memory_gib": stats("mem", 1 / 2**30, 2),
            "net_in_kib_s": stats("netin", 1 / 1024), "net_out_kib_s": stats("netout", 1 / 1024),
            "disk_read_kib_s": stats("diskread", 1 / 1024), "disk_write_kib_s": stats("diskwrite", 1 / 1024)}


def _media(ctx: Context, a: dict):
    node = ctx.node(a.get("node", ""))
    return {"node": node, "next_free_vmid": ctx.pve.next_id(),
            "isos": [i["volid"] for i in ctx.pve.isos(node) if not setupdisc.is_setup_disc(i["volid"] or "")],
            "cloud_images": [i["volid"] for i in ctx.pve.images(node)],
            "cloud_images_offered": {v: CLOUD_URL.format(v=v) for v in CLOUD_IMAGES},
            "container_templates": [t["volid"] for t in ctx.pve.templates(node)],
            "vm_disk_storages": [s["storage"] for s in ctx.pve.storages(node, content="images")],
            "container_storages": [s["storage"] for s in ctx.pve.storages(node, content="rootdir")],
            "backup_storages": [s["storage"] for s in ctx.pve.backup_storages(node)],
            "bridges": ctx.pve.bridges(node)}


# -- Power -----------------------------------------------------------------------------------------

POWER_WORDS = {"start": "Start", "shutdown": "Shut down", "stop": "Stop", "reboot": "Reboot"}


def _power_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    more = {"stop": ["Cuts it off at once, like pulling the plug: unsaved work inside is lost."],
            "shutdown": ["Asks the operating system inside to shut down cleanly."]}.get(a["action"], [])
    return f"{POWER_WORDS[a['action']]} {what(g)}", more


def _power(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if g.get("template"):
        raise ToolError(f"{what(g)} is a template: templates are copied, not started.")
    upid = ctx.pve.guest_action(g["node"], g["type"], g["vmid"], a["action"])
    return {"guest": what(g), "action": a["action"], **finish(ctx, g["node"], upid)}


def _bulk_words(ctx: Context, a: dict):
    gs = [ctx.guest(v) for v in a["vmids"]]
    word = "Start" if a["action"] == "start" else "Shut down"
    more = [", ".join(what(g) for g in gs), "One after the other, in their boot order" if a["action"] == "start"
            else "In reverse boot order"]
    if a["action"] == "shutdown":
        more.append(f"Each may take {int(a.get('timeout_s', 180))} s; " +
                    ("then it is stopped like pulling the plug." if a.get("force_stop", True) else
                     "one still running after that is left running."))
    return f"{word} {len(gs)} guest{'s' if len(gs) != 1 else ''}", more


def _bulk(ctx: Context, a: dict):
    if not a["vmids"]:
        raise ToolError("vmids is empty.")
    by_node: dict[str, list[int]] = {}
    for v in a["vmids"]:
        g = ctx.guest(v)
        by_node.setdefault(g["node"], []).append(g["vmid"])
    out = []
    for node, ids in by_node.items():
        if a["action"] == "start":
            upid = ctx.pve.start_all(node, ids)
        else:
            upid = ctx.pve.stop_all(node, ids, int(a.get("timeout_s", 180)), bool(a.get("force_stop", True)))
        out.append({"node": node, "vmids": ids, **finish(ctx, node, upid, wait=WAIT_S * 3)})
    return out


def _wake(ctx: Context, a: dict):
    if not ctx.host.mac:
        raise ToolError(f"{ctx.host.name} has no MAC address set in Proxmox Controller (its Edit… window).")
    ctx.wake(ctx.host.mac, ctx.host.broadcast or "255.255.255.255")
    return {"sent": True, "note": "A Wake-on-LAN packet was sent. A host takes a few minutes to boot; check it with "
                                  "host_status."}


# -- Change ----------------------------------------------------------------------------------------

EDITABLE = {
    "cores": {"type": "integer", "minimum": 1, "maximum": 512, "description": "CPU cores."},
    "memory_mib": {"type": "integer", "minimum": 64, "maximum": 4194304, "description": "Memory in MiB."},
    "swap_mib": {"type": "integer", "minimum": 0, "maximum": 4194304, "description": "Containers: swap in MiB."},
    "name": {"type": "string", "description": "The VM's name, or the container's hostname."},
    "start_at_boot": {"type": "boolean", "description": "Start when the host starts."},
    "boot_order": {"type": "integer", "minimum": 0, "maximum": 9999, "description": "Lower starts first; 0 = any."},
    "boot_delay_s": {"type": "integer", "minimum": 0, "maximum": 3600,
                     "description": "Seconds Proxmox waits after starting this one before the next."},
    "shutdown_timeout_s": {"type": "integer", "minimum": 0, "maximum": 3600,
                           "description": "Seconds it may take to shut down when the host does; 0 = default."},
    "tags": {"type": "array", "items": {"type": "string"}, "description": "Proxmox tags (replaces them)."},
    "notes": {"type": "string", "description": "The guest's notes (Markdown; replaces them)."},
    "tablet": {"type": "boolean", "description": "VMs: the USB tablet, an absolute pointer — console_click needs it "
               "(Windows has no other). The SPICE display leaves it out unless it is set. Plugged in at once where "
               "USB hotplug is on, otherwise at the next start."},
}


def _edit_changes(g: dict, cfg: dict, ch: dict) -> dict:
    """The Proxmox settings a request changes (only those that differ)."""
    if not isinstance(ch, dict) or not ch:
        raise ToolError(f"changes must name at least one of: {', '.join(EDITABLE)}.")
    inner = Tool("edit", "change", "", EDITABLE, reason=False)
    check(inner, ch)
    out = {}
    if "cores" in ch:
        out["cores"] = ch["cores"]
    if "memory_mib" in ch:
        out["memory"] = ch["memory_mib"]
    if "swap_mib" in ch:
        if g["type"] != "lxc":
            raise ToolError("swap_mib is for containers.")
        out["swap"] = ch["swap_mib"]
    if "name" in ch:
        if not (VMNAME if g["type"] == "qemu" else HOSTNAME).match(ch["name"]):
            raise ToolError("name: letters, digits, '-' (and '.' for VMs).")
        out["name" if g["type"] == "qemu" else "hostname"] = ch["name"]
    if "start_at_boot" in ch:
        out["onboot"] = 1 if ch["start_at_boot"] else 0
    if any(k in ch for k in ("boot_order", "boot_delay_s", "shutdown_timeout_s")):
        s = startup.parse(cfg.get("startup", ""))
        out.update(startup.change(cfg, ch.get("boot_order", s["order"] or 0), ch.get("boot_delay_s", s["up"] or 0),
                                  ch.get("shutdown_timeout_s", s["down"] or 0)))
    if "tags" in ch:
        bad = [t for t in ch["tags"] if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_+.-]*", t)]
        if bad:
            raise ToolError(f"Tags may hold letters, digits and _ + . - only: {', '.join(bad)}.")
        out["tags"] = ";".join(ch["tags"])
    if "notes" in ch:
        out["description"] = ch["notes"]
    if "tablet" in ch:
        if g["type"] != "qemu":
            raise ToolError("tablet is for VMs.")
        if vmhw.tablet_of(cfg) != ch["tablet"]:  # what it has now: its own setting or Proxmox's default for the display
            out["tablet"] = 1 if ch["tablet"] else 0
    return {k: v for k, v in out.items() if k in ("delete", "tablet") or str(cfg.get(k, "")) != str(v)}


LABELS = {"cores": "CPU cores", "memory": "Memory (MiB)", "swap": "Swap (MiB)", "name": "Name", "hostname": "Hostname",
          "onboot": "Start at boot", "startup": "Boot order", "tags": "Tags", "description": "Notes",
          "tablet": "USB tablet"}


def _edit_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    cfg = (ctx.admin or ctx.pve).guest_config(g["node"], g["type"], g["vmid"])
    changes = _edit_changes(g, cfg, a["changes"])
    lines = []
    for k, v in changes.items():
        if k == "delete":
            lines.append(f"Remove: {v}")
        elif k == "description":
            lines.append(f"Notes: {len(str(cfg.get(k, '')))} → {len(str(v))} characters")
        elif k == "tablet":
            lines.append(f"USB tablet: {'on' if vmhw.tablet_of(cfg) else 'off'} → {'on' if v else 'off'}")
        else:
            lines.append(f"{LABELS.get(k, k)}: {cfg.get(k, '—')} → {v}")
    if g.get("status") == "running" and any(k in changes for k in ("cores", "memory")) and g["type"] == "qemu":
        lines.append("Running VM: CPU and memory changes may wait for its next start.")
    if g.get("status") == "running" and "tablet" in changes:
        lines.append("Running VM: the tablet is plugged in at once where USB hotplug is on, otherwise at its next "
                     "start.")
    return f"Edit {what(g)}", lines or ["Nothing would change."]


def _edit(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    cfg = ctx.pve.guest_config(g["node"], g["type"], g["vmid"])
    changes = _edit_changes(g, cfg, a["changes"])
    if not changes:
        return {"guest": what(g), "changed": [], "note": "Nothing differed from the current settings."}
    ctx.pve.update_config(g["node"], g["type"], g["vmid"], changes)
    out = {"guest": what(g), "changed": sorted(changes)}
    if "tablet" in changes and g.get("status") == "running":
        try:
            later = "tablet" in (ctx.admin or ctx.pve).pending(g["node"], g["vmid"])
        except PveError:
            later = None
        out["tablet"] = ("waits for the VM's next start (USB hotplug is off for it): reboot it from Proxmox — a "
                         "restart inside the guest is not enough" if later else
                         "plugged in now" if later is False else "set; whether it is in already could not be read")
    return out


def _grow_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    return f"Grow disk {a['disk']} of {what(g)} by {a['add_gb']} GB", ["A disk can only grow, never shrink back."]


def _grow(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    ctx.pve.resize_disk(g["node"], g["type"], g["vmid"], a["disk"], a["add_gb"])
    return {"guest": what(g), "disk": a["disk"], "grown_by_gb": a["add_gb"]}


def _snap_words(ctx: Context, a: dict):
    return f"Take snapshot '{a['name']}' of {what(ctx.guest(a['vmid']))}", (
        [f"Description: {a['description']}"] if a.get("description") else [])


def _snap(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if not SNAPNAME.match(a["name"]):
        raise ToolError("name: a letter, then letters, digits, '_' or '-' (2–40 characters).")
    upid = ctx.pve.create_snapshot(g["node"], g["type"], g["vmid"], a["name"], a.get("description", ""))
    return {"guest": what(g), "snapshot": a["name"], **finish(ctx, g["node"], upid)}


def _backup_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    where = a.get("storage") or "the first backup storage"
    return f"Back up {what(g)} now", [f"Mode: {a.get('mode', 'snapshot')}, storage: {where}" +
                                      (", protected" if a.get("protected") else "")]


def _backup(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    storage = a.get("storage") or next((s["storage"] for s in ctx.pve.backup_storages(g["node"])), "")
    if not storage:
        raise ToolError(f"No storage on {g['node']} takes backups.")
    upid = ctx.pve.backup_now(g["node"], g["vmid"], storage, a.get("mode", "snapshot"), "zstd",
                              a.get("note", "{{guestname}}"), bool(a.get("protected")))
    return {"guest": what(g), "storage": storage, **finish(ctx, g["node"], upid)}


NOT_STARTED = "no — Power requests are Off for this host: the user can start it"


def _power_for_start(a: dict) -> tuple:
    """A guest made or restored with start is a power request on it too: Proxmox checks VM.PowerMgmt for it."""
    return ("power",) if a.get("start") else ()


def _start(ctx: Context, a: dict) -> bool:
    """Start it once made — only where Power is not Off (otherwise Proxmox would refuse the whole request)."""
    return bool(a.get("start")) and "power" in ctx.kinds


def _start_note(ctx: Context, a: dict) -> str:
    if not a.get("start"):
        return ""
    return "starts when created" if _start(ctx, a) else "not started: Power requests are Off for this host"


def _vm_params(ctx: Context, a: dict) -> tuple[str, dict]:
    node = ctx.node(a.get("node", ""))
    if not VMNAME.match(a["name"]):
        raise ToolError("name: letters, digits, '-' and '.'.")
    profile = a.get("profile", "linux")
    prof = PROFILES[profile]
    if profile in WINDOWS and is_virtio_disc(a["iso"]):
        raise ToolError(VIRTIO_AS_SYSTEM)
    storage = a.get("storage") or next((s["storage"] for s in (ctx.admin or ctx.pve).storages(node, content="images")),
                                       "")
    if not storage:
        raise ToolError(f"No storage on {node} takes VM disks.")
    p = vm_params(vmid=a.get("vmid") or (ctx.admin or ctx.pve).next_id(), name=a["name"], profile=profile,
                  iso=a["iso"], virtio_iso=a.get("virtio_iso", ""), cores=a.get("cores", prof["cores"]),
                  host_cpu=bool(a.get("host_cpu")), memory=a.get("memory_mib", prof["memory"]),
                  disk_gb=a.get("disk_gb", prof["disk"]), storage=storage, bridge=a.get("bridge", "vmbr0"),
                  agent=a.get("guest_agent", True), onboot=bool(a.get("start_at_boot")), start=_start(ctx, a))
    # as the New VM window: SPICE display and sound — and the USB tablet, which Proxmox leaves out with SPICE (without
    # it a click from console_click lands wherever the pointer already is)
    p.update(vga="qxl", audio0="device=ich9-intel-hda,driver=spice", tablet=1)
    return node, p


def _windows_setup(a: dict) -> dict | None:
    """The answer file's settings when Windows is to install itself (windows_user given), checked; else None."""
    if not a.get("windows_user"):
        for key in ("edition", "language", "remote_desktop", "dark_theme"):
            if key in a:
                raise ToolError(f"{key} is for a Windows that installs itself: give windows_user too.")
        return None
    profile = a.get("profile", "linux")
    if profile not in WINDOWS:
        raise ToolError("windows_user: only with the win11 or win10 profile.")
    edition = a.get("edition") or winsetup.default_edition(profile)
    rdp = bool(a.get("remote_desktop"))
    problem = winsetup.check_user(a["windows_user"], "password", rdp, edition)  # (the user types the real one)
    if problem:
        raise ToolError(problem)
    language = a.get("language") or winsetup.language_of_iso(a["iso"])
    if language not in winsetup.LANGUAGES and not re.fullmatch(r"[a-z]{2,3}-[A-Z]{2}", language):
        raise ToolError("language: a code such as en-US or el-GR.")
    return {"user": a["windows_user"], "edition": edition, "language": language, "remote_desktop": rdp,
            "dark": bool(a.get("dark_theme")), "virtio": bool(a.get("virtio_iso")),
            "guest_tools": a.get("guest_agent", True)}


def _create_vm_words(ctx: Context, a: dict):
    node, p = _vm_params(ctx, a)
    lines = [f"{PROFILES[a.get('profile', 'linux')]['label']}: {p['cores']} cores, {p['memory']} MiB, disk "
             f"{next(v for k, v in p.items() if k in ('scsi0', 'sata0'))}", f"Boots {a['iso']}"
             + (f", {_start_note(ctx, a)}" if a.get("start") else "")]
    win = _windows_setup(a)
    if win:
        extras = [x for x, on in (("Remote Desktop on", win["remote_desktop"]), ("dark theme", win["dark"]),
                                  ("VirtIO guest tools and agent", win["virtio"] and win["guest_tools"])) if on]
        lines += [f"Windows installs itself: {win['edition']}, {win['language']}, user '{win['user']}' with the "
                  "password you type below (Claude does not see it)" + (f"; {', '.join(extras)}" if extras else ""),
                  "Its answer disc (with that password) is deleted by the app as soon as Windows is ready"]
        if a.get("start") and _start(ctx, a):
            lines.append("The app itself presses Enter at the installer's 'Press any key to boot from CD or DVD' "
                         "(it waits only ~5 s: no second approval, whatever the Console switch says)")
    return f"Create VM {p['vmid']} ({p['name']}) on {node}", lines


def _create_vm(ctx: Context, a: dict):
    node, p = _vm_params(ctx, a)
    win = _windows_setup(a)
    if not win:
        upid = ctx.pve.create_vm(node, p)
        out = {"vmid": p["vmid"], "name": p["name"], "node": node, **finish(ctx, node, upid, wait=WAIT_S * 3),
               "next": "Open its console (Console in the app, or console_screenshot) to install the operating system."}
        if a.get("start") and not p["start"]:
            out["started"] = NOT_STARTED
        return out
    if not ctx.secret:
        raise ToolError("No password was typed.")
    place = timezones.region(timezones.host_zone(ctx.admin or ctx.pve, node))
    xml = winsetup.answer_file(password=ctx.secret, computer=winsetup.computer_name(p["name"]),
                               uefi=p.get("bios") == "ovmf", time_zone=place["windows"], region=place["locale"], **win)
    vmid, start = p["vmid"], p.pop("start")
    drive = setupdisc.free_slot(p)
    volid = setupdisc.upload(ctx.pve, node, setupdisc.storage_of(a["iso"]), vmid, {winsetup.ANSWER_NAME: xml.encode()},
                             "autounattend")
    p[drive] = f"{volid},media=cdrom"
    try:
        made = finish(ctx, node, ctx.pve.create_vm(node, p), wait=WAIT_S * 3)
    except Exception:
        setupdisc.delete(ctx.admin or ctx.pve, node, volid)  # (deleting an ISO needs the user's token)
        raise
    if ctx.remember is not None:
        ctx.remember(setupdisc.entry(ctx.host.id, node, vmid, volid, drive, win["virtio"] and win["guest_tools"]))
    out = {"vmid": vmid, "name": p["name"], "node": node, **made, "windows": {
        "edition": win["edition"], "language": win["language"], "user": win["user"],
        "password": "set by the user (not shown to you)", "remote_desktop": win["remote_desktop"],
        "answer_disc": f"{volid} on {drive} — the app deletes it once Windows is ready"}}
    if made["status"] != "done":
        out["note"] = "The VM is still being made: start it when task_log shows it finished, and press Enter in its " \
                      "console at 'Press any key to boot from CD or DVD' (about 10 s after the start)."
        return out
    if start:
        out["started"] = finish(ctx, node, ctx.pve.guest_action(node, "qemu", vmid, "start"))["status"]
        # The app answers the boot question itself, with the user's token: it waits only ~5 s, so no approval could
        # come in time (the user's exception, 24/10) — part of this approved request. In the background: it may
        # come a minute later, and a missed one is retried through the firmware's Boot Manager.
        pve = ctx.admin or ctx.pve
        threading.Thread(target=lambda: setupdisc.answer_boot_prompt(pve, node, vmid), daemon=True,
                         name=f"boot-prompt-{vmid}").start()
        out["boot_key"] = ("the app watches its screen and presses Enter when 'Press any key to boot from CD or DVD' "
                           f"shows (within {setupdisc.BOOT_PROMPT_WAIT_S // 60} minutes; if missed, it tries again "
                           "through the firmware's Boot Manager); check with console_screenshot")
    elif a.get("start"):
        out["started"] = NOT_STARTED
    out["next"] = ("Windows installs itself (about 15–30 minutes, with restarts); watch it with console_screenshot. "
                   "Done when it shows the desktop" + (" and the guest agent answers (run_command works)"
                                                       if win["virtio"] and win["guest_tools"] else "") + ".")
    return out


def _ct_params(ctx: Context, a: dict) -> tuple[str, dict]:
    node = ctx.node(a.get("node", ""))
    if not HOSTNAME.match(a["hostname"]):
        raise ToolError("hostname: letters, digits and hyphens.")
    storage = a.get("storage") or next((s["storage"] for s in (ctx.admin or ctx.pve).storages(node, content="rootdir")),
                                       "")
    if not storage:
        raise ToolError(f"No storage on {node} takes containers.")
    net = {"name": "eth0", "bridge": a.get("bridge", "vmbr0"), "firewall": 1}
    ip = a.get("ip", "dhcp")
    if ip != "dhcp" and not CIDR.match(ip):
        raise ToolError("ip: 'dhcp' or an address with its prefix, such as 192.168.1.50/24.")
    net["ip"] = ip
    if a.get("gateway"):
        if not IPV4.match(a["gateway"]):
            raise ToolError("gateway must be an IPv4 address.")
        net["gw"] = a["gateway"]
    p = {"vmid": a.get("vmid") or (ctx.admin or ctx.pve).next_id(), "hostname": a["hostname"],
         "ostemplate": a["template"], "cores": a.get("cores", 1), "memory": a.get("memory_mib", 512),
         "swap": a.get("swap_mib", 512), "rootfs": f"{storage}:{a.get('disk_gb', 8)}",
         "net0": ",".join(f"{k}={v}" for k, v in net.items()), "unprivileged": True,
         "onboot": bool(a.get("start_at_boot")), "start": _start(ctx, a)}
    if ctx.secret:
        p["password"] = ctx.secret
    if a.get("nesting"):
        p["features"] = "nesting=1"
    if a.get("ssh_public_key"):
        p["ssh-public-keys"] = a["ssh_public_key"]
    return node, p


def _create_ct_words(ctx: Context, a: dict):
    node, p = _ct_params(ctx, a)
    return f"Create container {p['vmid']} ({p['hostname']}) on {node}", [
        f"{a['template']}" + (f", {_start_note(ctx, a)}" if a.get("start") else ""),
        f"{p['cores']} cores, {p['memory']} MiB, disk {p['rootfs']}, network {p['net0']}",
        "Unprivileged; its root password is the one you type below (Claude does not see it)"]


def _create_ct(ctx: Context, a: dict):
    node, p = _ct_params(ctx, a)
    upid = ctx.pve.create_container(node, p)
    out = {"vmid": p["vmid"], "hostname": p["hostname"], "node": node, **finish(ctx, node, upid, wait=WAIT_S * 3),
           "root_password": "set by the user (not shown to you)"}
    if a.get("start") and not p["start"]:
        out["started"] = NOT_STARTED
    return out


def _cloud_words(ctx: Context, a: dict):
    v = a.get("release", "24.04")
    return f"Download Ubuntu {v} Server (cloud image, {CLOUD_IMAGES[v]} MB) onto {ctx.host.name}", [
        CLOUD_URL.format(v=v), "Downloaded once; new VMs are made from it in about a minute."]


def _cloud_image(ctx: Context, a: dict):
    node, v = ctx.node(a.get("node", "")), a.get("release", "24.04")
    name = cloudvm.image_name(v)
    there = cloudvm.find_image(ctx.pve.images(node), v)
    if there:
        return {"image": there, "status": "already on the host"}
    storage = a.get("storage") or next((s["storage"] for s in ctx.pve.storages(node, content="import")), "")
    if not storage:
        raise ToolError(f"No storage on {node} takes disk images (content 'Import'): the user can add it in Proxmox, "
                        "Datacenter → Storage → local → Content.")
    upid = ctx.pve.download_url(node, storage, CLOUD_URL.format(v=v), name, content="import")
    return {"image": f"{storage}:import/{name}", **finish(ctx, node, upid)}


def _cloud_vm_params(ctx: Context, a: dict) -> tuple[str, dict, int]:
    node = ctx.node(a.get("node", ""))
    if not VMNAME.match(a["name"]):
        raise ToolError("name: letters, digits, '-' and '.'.")
    user = a.get("username", "user")
    if not USERNAME.match(user):
        raise ToolError("username: small letters, digits, '_' and '-', starting with a letter.")
    images = [i["volid"] for i in (ctx.admin or ctx.pve).images(node)]
    if a["image"] not in images:
        raise ToolError(f"No image {a['image']} on {node} (get_cloud_image downloads one; list_install_media lists "
                        "them).")
    edition = a.get("edition", "server")
    desktop = edition == "desktop"
    if a.get("remote_desktop") and not desktop:
        raise ToolError("remote_desktop needs edition 'desktop' (a server has no desktop to show).")
    if a.get("dark_theme") and not desktop:
        raise ToolError("dark_theme needs edition 'desktop'.")
    storage = a.get("storage") or next((s["storage"] for s in (ctx.admin or ctx.pve).storages(node, content="images")),
                                       "")
    if not storage:
        raise ToolError(f"No storage on {node} takes VM disks.")
    size = cloudvm.SIZES[edition]
    disk = a.get("disk_gb", size["disk"])
    p = cloudvm.vm_params(vmid=a.get("vmid") or (ctx.admin or ctx.pve).next_id(), name=a["name"], image=a["image"],
                          storage=storage, bridge=a.get("bridge", "vmbr0"), cores=a.get("cores", size["cores"]),
                          memory=a.get("memory_mib", size["memory"]), user=user,
                          ssh_key=a.get("ssh_public_key", ""), desktop=desktop, onboot=bool(a.get("start_at_boot")),
                          seed="pending" if desktop else "")  # (the desktop's disc is made when it is created)
    return node, p, disk


def _seed_storage(ctx: Context, node: str) -> str:
    """Where the desktop's setup disc goes: the first storage that takes ISO images."""
    found = next((s["storage"] for s in (ctx.admin or ctx.pve).storages(node, content="iso")), "")
    if not found:
        raise ToolError(f"No storage on {node} takes ISO images, which the desktop's setup disc needs.")
    return found


def _cloud_vm_words(ctx: Context, a: dict):
    node, p, disk = _cloud_vm_params(ctx, a)
    desktop = a.get("edition", "server") == "desktop"
    user = a.get("username", "user")
    lines = [f"From {a['image']}: {p['cores']} cores, {p['memory']} MiB, disk {disk} GB, network by DHCP",
             f"User '{user}', with the password you type below (Claude does not see it)" +
             (" and an SSH key" if a.get("ssh_public_key") else "")]
    if desktop:
        lines += [f"On the first start it installs Ubuntu Desktop and the QEMU guest agent" +
                  (", and turns on Ubuntu's own Remote Desktop (RDP, with that user and password)"
                   if a.get("remote_desktop") else "") + (", with the dark theme" if a.get("dark_theme") else "") +
                  ", then restarts by itself",
                  f"From a setup disc on {_seed_storage(ctx, node)} (the password as a hash" +
                  ("; for Remote Desktop the password itself too" if a.get("remote_desktop") else "") +
                  "), deleted by the app once the agent answers"]
    else:
        lines.append("Ready about a minute after it starts")
    return f"Create VM {p['vmid']} ({p['name']}) — Ubuntu {'Desktop' if desktop else 'Server'} — on {node}", lines


def _cloud_vm(ctx: Context, a: dict):
    node, p, disk = _cloud_vm_params(ctx, a)
    vmid, desktop, rdp = p["vmid"], a.get("edition") == "desktop", bool(a.get("remote_desktop"))
    user = a.get("username", "user")
    volid = ""
    if desktop:
        place = timezones.region(timezones.host_zone(ctx.admin or ctx.pve, node))
        seed = cloudseed.seed_files(vm_name=p["name"], vmid=vmid, user=user, password=ctx.secret,
                                    ssh_keys=[a.get("ssh_public_key", "")], remote_desktop=rdp,
                                    dark=bool(a.get("dark_theme")), time_zone=place["iana"],
                                    keyboard=place["keyboard"])
        volid = setupdisc.upload(ctx.pve, node, _seed_storage(ctx, node), vmid, seed, cloudseed.SEED_LABEL)
        p["ide2"] = f"{volid},media=cdrom"
    elif ctx.secret:
        p["cipassword"] = ctx.secret  # (Proxmox keeps only a hash of it)
    try:
        made = finish(ctx, node, ctx.pve.create_vm(node, p), wait=WAIT_S * 3)
    except Exception:
        if volid:
            setupdisc.delete(ctx.admin or ctx.pve, node, volid)  # (deleting an ISO needs the user's token)
        raise
    if volid and ctx.remember is not None:
        ctx.remember(setupdisc.entry(ctx.host.id, node, vmid, volid, "ide2", True))
    out = {"vmid": vmid, "name": p["name"], "node": node, "user": user,
           "password": "set by the user (not shown to you)" if ctx.secret else "none", **made}
    if made["status"] != "done":
        out["note"] = "The disk is still being made from the image: start the VM when task_log shows it finished."
        return out
    if disk > 3:
        ctx.pve.request("PUT", f"/nodes/{node}/qemu/{vmid}/resize", {"disk": "scsi0", "size": f"{disk}G"})
    if a.get("start", True) and "power" in ctx.kinds:
        out["started"] = finish(ctx, node, ctx.pve.guest_action(node, "qemu", vmid, "start"))["status"]
    elif a.get("start", True):
        out["started"] = NOT_STARTED
    if desktop:
        next_steps = ["On the first start cloud-init sets the user and the network, then installs Ubuntu Desktop and "
                      "the QEMU guest agent" + (" and Remote Desktop" if rdp else "") + " — 10 to 20 minutes — and "
                      "restarts by itself into the login screen. The app deletes the setup disc once the agent "
                      "answers; its address then shows in Proxmox Controller."]
        if rdp:
            next_steps.append(f"Remote Desktop (Ubuntu's own, GNOME Remote Desktop): connect to its address, port "
                              f"{cloudseed.RDP_PORT}, with any Remote Desktop app; accept its self-signed certificate "
                              "and sign in with the user and its password, then once more at the Ubuntu login screen. "
                              "Sound comes over it too (in Remmina: Audio output mode Local).")
    else:
        next_steps = ["It boots in about a minute; cloud-init sets the user, the password and the network on the first "
                      "start. Its console (console_screenshot) shows the address it got.",
                      "qemu-guest-agent is not in Ubuntu's cloud image: install it (sudo apt install -y "
                      "qemu-guest-agent) so its address shows in Proxmox Controller and Commands can work."]
    out["next_steps"] = next_steps
    return out


def _confirm_point(a: dict) -> tuple[int, int] | None:
    """confirm_at as (x, y), or None. ToolError for anything else — and for both ways of confirming at once."""
    at = a.get("confirm_at")
    if at is None:
        return None
    if a.get("confirm"):
        raise ToolError("Give confirm or confirm_at, not both.")
    if not (isinstance(at, list) and len(at) == 2 and all(isinstance(n, int) and not isinstance(n, bool) and n >= 0
                                                            for n in at)):
        raise ToolError("confirm_at must be [x, y]: two whole numbers from the console_screenshot picture.")
    return at[0], at[1]


def _type_password_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    at = _confirm_point(a)
    if at is not None and g.get("status") == "running":
        _need_pointer(ctx, g, "Nothing was typed.")  # the click on the second field could not land
    picture = None
    try:  # the screen as it is now, so the user sees where the password would go
        w, h, pixels = screen.capture(lambda: (ctx.admin or ctx.pve).open_vnc(g["node"], g["type"], g["vmid"]))
    except Exception:
        w = h = 0
    if w:
        if at is not None:  # checked before anything is typed — and the second field shown with a red mark
            step = screen.scale_of(w)
            if not (at[0] * step < w and at[1] * step < h):
                raise ToolError(f"confirm_at {list(at)} is outside the screen: the picture of it is "
                                f"{math.ceil(w / step)}×{math.ceil(h / step)}. Nothing was typed.")
            pixels = screen.mark(w, h, pixels, at[0] * step, at[1] * step)
        picture, _, _ = screen.png(w, h, pixels, max_width=640)
    enter = " and presses Enter" if a.get("enter", True) else ""
    if at is not None:
        how = ("You type it twice below (so a typo shows); the app types it into the field where the cursor is, "
               f"clicks the second field — the red mark — and types it again there{enter}. Claude does not see it.")
    elif a.get("confirm"):
        how = ("You type it twice below (so a typo shows); the app types it into the field where the cursor is, "
               f"presses Tab, and types it again into the next{enter}. Claude does not see it.")
    else:
        how = f"You type it below; the app types it into the guest{enter}. Claude does not see it."
    return f"Type a password into the console of {what(g)}", [
        how, "Check the picture: it is where the password goes.",
        "Only what an English (US) keyboard has: the guest gets it as typed there."], picture


def _type_password(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if not ctx.secret:
        raise ToolError("No password was typed.")
    if any(not " " <= c <= "~" for c in ctx.secret):  # typed as US keys: anything else would come out as other signs
        raise ToolError("The password has characters an English (US) keyboard does not have (letters of another "
                        "language, for example), so the guest would get a different password. Nothing was typed; "
                        "the user can choose one with English letters, digits and signs only.")
    at = _confirm_point(a)
    enter = ["enter"] if a.get("enter", True) else []
    if at is not None:  # the first field, a click on the second, the second
        opener = _opener(ctx, g)
        _need_pointer(ctx, g, "Nothing was typed.")
        screen.send(opener, ctx.secret)
        try:
            screen.click(opener, at[0], at[1])
        except ValueError as e:
            raise ToolError(f"It went into the first field only: {e}") from e
        screen.send(opener, ctx.secret, enter)
        return {"guest": what(g), "typed": "the password the user typed (not shown to you), a click on the second "
                                           "field, and the password again"}
    text = ctx.secret + "\t" + ctx.secret if a.get("confirm") else ctx.secret
    screen.send(_opener(ctx, g), text, enter)
    return {"guest": what(g), "typed": "the password the user typed (not shown to you)" +
            (", Tab, and again" if a.get("confirm") else "")}


def _clone_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    return f"Copy {what(g)} as '{a['new_name']}'", ["Full copy (stands on its own)" if a.get("full", True)
                                                     else "Linked copy (shares the template's disk)"]


def _clone(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if g["type"] != "qemu":
        raise ToolError("Only VMs can be copied here.")
    if not VMNAME.match(a["new_name"]):
        raise ToolError("new_name: letters, digits, '-' and '.'.")
    newid = a.get("new_vmid") or (ctx.admin or ctx.pve).next_id()
    upid = ctx.pve.clone_vm(g["node"], g["vmid"], newid, a["new_name"], full=a.get("full", True),
                            storage=a.get("storage", ""))
    return {"source": what(g), "new_vmid": newid, "name": a["new_name"],
            **finish(ctx, g["node"], upid, wait=WAIT_S * 5)}


def _download_words(ctx: Context, a: dict):
    return f"Download an ISO image onto {ctx.host.name}", [a["url"], f"as {a.get('filename') or iso_name_from_url(a['url'])}"]


def _download(ctx: Context, a: dict):
    node = ctx.node(a.get("node", ""))
    if not re.match(r"^https?://\S+$", a["url"]):
        raise ToolError("url must start with http:// or https://.")
    name = a.get("filename") or iso_name_from_url(a["url"])
    if not name.lower().endswith(".iso"):
        raise ToolError("The file name must end in .iso (give filename).")
    storage = a.get("storage") or next((s["storage"] for s in ctx.pve.storages(node, content="iso")), "")
    if not storage:
        raise ToolError(f"No storage on {node} takes ISO images.")
    upid = ctx.pve.download_url(node, storage, a["url"], name, checksum=a.get("checksum_sha256", ""))
    return {"file": f"{storage}:iso/{name}", **finish(ctx, node, upid, wait=WAIT_S)}


def _restore_kind(a: dict) -> str:
    return "destroy" if a.get("replace") else "change"


def _deleted_backup(ctx: Context, a: dict) -> dict:
    """The backup asked for, when its guest no longer exists — with the node it is reached through."""
    vmid = int(a["vmid"])
    b = next((b for b in (ctx.admin or ctx.pve).deleted_guests_backups() if b["volid"] == a["volid"]), None)
    if b is None or int(b["vmid"]) != vmid:
        raise ToolError(f"There is no guest {vmid} on {ctx.host.name}, nor a backup {a['volid']} of a guest {vmid} "
                        "deleted since (list_backups with its old ID shows them).")
    if a.get("replace"):
        raise ToolError(f"Guest {vmid} no longer exists: there is nothing to restore over. Leave replace out — it "
                        "comes back as itself.")
    return b


def _restore_target(ctx: Context, a: dict) -> tuple[dict | None, dict | None]:
    """(the guest, None) — or (None, its backup) for a guest deleted since."""
    try:
        return ctx.guest(a["vmid"]), None
    except ToolError:
        return None, _deleted_backup(ctx, a)


def _comeback_id(ctx: Context, a: dict, b: dict) -> int:
    """Its old ID while that is free; otherwise new_vmid, or the next free one."""
    old = int(b["vmid"])
    if a.get("new_vmid"):
        return int(a["new_vmid"])
    return old if old not in {int(g["vmid"]) for g in ctx.guests()} else int((ctx.admin or ctx.pve).next_id())


def _restore_words(ctx: Context, a: dict):
    g, b = _restore_target(ctx, a)
    if b is not None:
        name = backup_name(b)
        label = f"{'VM' if backup_kind(b) == 'qemu' else 'Container'} {b['vmid']}" + (f" ({name})" if name else "")
        return f"Bring back {label}, deleted since, from its backup", [
            a["volid"], f"As {_comeback_id(ctx, a, b)}, with its old network addresses (MAC): the router gives it "
                        "the IP it had."] + _start_line(ctx, a)
    if a.get("replace"):
        return f"Restore {what(g)} from a backup, over itself", [a["volid"], "Everything that changed since the backup "
                                                                 "is lost."] + _start_line(ctx, a)
    return f"Restore a backup of {what(g)} as a new guest", [a["volid"]] + _start_line(ctx, a)


def _start_line(ctx: Context, a: dict) -> list[str]:
    note = _start_note(ctx, a)
    return [note[0].upper() + note[1:]] if note else []


def _restore(ctx: Context, a: dict):
    g, b = _restore_target(ctx, a)
    start = _start(ctx, a)
    if b is not None:  # a guest deleted since comes back: its old ID while free, its old MAC addresses
        node, vmid = b["node"], _comeback_id(ctx, a, b)
        upid = ctx.pve.restore(node, backup_kind(b), vmid, a["volid"], a.get("storage", ""), False, start,
                               unique=False)
        out = {"vmid": vmid, "brought_back": f"guest {b['vmid']} ({backup_name(b) or 'no name'}), deleted since",
               "network_addresses": "its old ones (MAC)", **finish(ctx, node, upid, wait=WAIT_S * 3)}
    else:
        if a.get("replace") and g.get("status") == "running":
            raise ToolError(f"{what(g)} is running: shut it down before restoring over it.")
        vmid = g["vmid"] if a.get("replace") else (a.get("new_vmid") or (ctx.admin or ctx.pve).next_id())
        upid = ctx.pve.restore(g["node"], g["type"], vmid, a["volid"], a.get("storage", ""), bool(a.get("replace")),
                               start)
        out = {"vmid": vmid, **finish(ctx, g["node"], upid, wait=WAIT_S * 3)}
    if a.get("start") and not start:
        out["started"] = NOT_STARTED
    return out


# -- Destroy ---------------------------------------------------------------------------------------

def _gib(n) -> str:
    return f"{(n or 0) / 2**30:.1f} GiB"


def _delete_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    lines = ["With all its disks and snapshots, for good."]
    if a.get("keep_backups"):
        return f"Delete {what(g)}", lines + ["Its backups are kept."]
    try:
        backups = (ctx.admin or ctx.pve).backups(g["node"], g["vmid"])
    except PveError:
        return f"Delete {what(g)}", lines + ["Its backups could not be listed now."]
    free = [b for b in backups if not b.get("protected")]
    kept = len(backups) - len(free)
    if free:
        lines.append(f"And its {len(free)} backup(s), {_gib(sum(b.get('size') or 0 for b in free))}.")
    if kept:
        lines.append(f"Its {kept} protected backup(s) stay.")
    if not backups:
        lines.append("It has no backups.")
    return f"Delete {what(g)}", lines


def _delete(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if g.get("status") == "running":
        raise ToolError(f"{what(g)} is running: shut it down first.")
    upid = ctx.pve.delete_guest(g["node"], g["type"], g["vmid"])
    out = {"deleted": what(g), **finish(ctx, g["node"], upid)}
    if a.get("keep_backups"):
        out["backups"] = "kept, as asked"
    elif out["status"] != "done":
        out["backups"] = "not touched: the guest is still being deleted. Delete them with delete_backup afterwards."
    else:  # only once the guest itself is gone
        try:
            backups = (ctx.admin or ctx.pve).backups(g["node"], g["vmid"])
        except PveError as e:
            out["backups"] = f"could not be listed, so none were deleted: {e}"
            return out
        failed = ctx.pve.delete_backups(g["node"], backups)
        out["backups_deleted"] = sum(1 for b in backups if not b.get("protected")) - len(failed)
        out["backups_kept_protected"] = [b["volid"] for b in backups if b.get("protected")]
        if failed:
            out["backups_failed"] = [{"volid": b["volid"], "error": why} for b, why in failed]
    return out


def _rollback_words(ctx: Context, a: dict):
    return f"Roll {what(ctx.guest(a['vmid']))} back to snapshot '{a['snapshot']}'", [
        "Everything after that snapshot is lost."]


def _rollback(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    upid = ctx.pve.rollback_snapshot(g["node"], g["type"], g["vmid"], a["snapshot"])
    return {"guest": what(g), "snapshot": a["snapshot"], **finish(ctx, g["node"], upid)}


def _delsnap_words(ctx: Context, a: dict):
    return f"Delete snapshot '{a['snapshot']}' of {what(ctx.guest(a['vmid']))}", []


def _delsnap(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    upid = ctx.pve.delete_snapshot(g["node"], g["type"], g["vmid"], a["snapshot"])
    return {"guest": what(g), "deleted_snapshot": a["snapshot"], **finish(ctx, g["node"], upid)}


def _find_backup(ctx: Context, volid: str) -> tuple[str, dict]:
    for node in [n["node"] for n in (ctx.admin or ctx.pve).nodes() if n.get("status", "online") == "online"]:
        for b in (ctx.admin or ctx.pve).backups(node):
            if b.get("volid") == volid:
                return node, b
    raise ToolError(f"No backup {volid} on {ctx.host.name}.")


def _delbackup_words(ctx: Context, a: dict):
    _, b = _find_backup(ctx, a["volid"])
    return "Delete a backup", [f"{a['volid']} ({round((b.get('size') or 0) / 2**30, 1)} GiB)", "For good."]


def _delbackup(ctx: Context, a: dict):
    node, b = _find_backup(ctx, a["volid"])
    if b.get("protected"):
        raise ToolError("That backup is protected: the user must unprotect it first.")
    upid = ctx.pve.delete_backup(node, b["storage"], b["volid"])
    return {"deleted": b["volid"], **finish(ctx, node, upid)}


def _stoptask_words(ctx: Context, a: dict):
    return "Stop a running task", [a["upid"]]


def _stoptask(ctx: Context, a: dict):
    node = a["upid"].split(":")[1] if a["upid"].count(":") > 2 else ctx.node()
    ctx.pve.stop_task(node, a["upid"])
    return {"stopped": a["upid"]}


# -- Host ------------------------------------------------------------------------------------------

def _host_words(ctx: Context, a: dict):
    word = "Shut down" if a["action"] == "shutdown" else "Reboot"
    return f"{word} the host {ctx.host.name}", ["Its running guests are shut down first."] + (
        ["It can be woken again with Wake-on-LAN."] if a["action"] == "shutdown" and ctx.host.mac else [])


def _host_power(ctx: Context, a: dict):
    node = ctx.node(a.get("node", ""))
    ctx.pve.node_command(node, a["action"])
    return {"node": node, "sent": a["action"]}


# -- Console ---------------------------------------------------------------------------------------

def pointer_state(text: str) -> tuple[str, str]:
    """From QEMU's 'info mice': ('absolute' | 'relative' | 'unknown', the mouse in use — the line marked '*')."""
    for line in (text or "").splitlines():
        if line.lstrip().startswith("*"):
            return ("absolute" if "(absolute)" in line else "relative"), line.split(":", 1)[-1].strip()
    return "unknown", ""


def _pointer(ctx: Context, g: dict) -> tuple[str, str]:
    """Whether a click can land where it is sent: the guest's mouse in use, read from QEMU's monitor. Without an
    absolute one (no USB tablet) the console can only move the pointer by steps from where the same connection last
    put it — and each click is a connection of its own — so the click lands wherever the pointer already is. Asked
    once a request. ('unknown', why) where it cannot be read (a container, an older Proxmox)."""
    if g["vmid"] not in ctx.pointers:
        if g["type"] != "qemu":
            ctx.pointers[g["vmid"]] = ("unknown", "a container")
        else:
            try:
                ctx.pointers[g["vmid"]] = pointer_state((ctx.admin or ctx.pve).monitor(g["node"], g["vmid"],
                                                                                       "info mice"))
            except PveError as e:
                ctx.pointers[g["vmid"]] = ("unknown", str(e)[:160])
    return ctx.pointers[g["vmid"]]


def _need_pointer(ctx: Context, g: dict, nothing_done: str) -> str:
    """ToolError where a click cannot land (rather than a click that only seems done); a note where it was not known."""
    state, mouse = _pointer(ctx, g)
    if state == "relative":
        raise ToolError(f"{what(g)} has no absolute pointer: its mouse is '{mouse}', which moves only by steps, so a "
                        f"click sent to a point would land wherever the pointer already is. {nothing_done} Give the VM "
                        "a USB tablet: edit_guest with changes {\"tablet\": true} — Proxmox plugs it in at once where "
                        "USB hotplug is on, otherwise at the VM's next start (the SPICE display leaves it out unless "
                        "it is set). Keys (console_send) work meanwhile.")
    if state == "unknown" and g["type"] == "qemu":
        return (f"The guest's pointer could not be checked ({mouse or 'no answer'}). If console_screenshot shows the "
                "click elsewhere, the VM needs a USB tablet: edit_guest with changes {\"tablet\": true}.")
    return ""


def _opener(ctx: Context, g: dict) -> Callable[[], tuple]:
    if g.get("status") != "running":
        raise ToolError(f"{what(g)} is not running.")
    return lambda: ctx.pve.open_vnc(g["node"], g["type"], g["vmid"])


def _screenshot_words(ctx: Context, a: dict):
    return f"See the screen of {what(ctx.guest(a['vmid']))}", []


def _screenshot(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    w, h, pixels = screen.capture(_opener(ctx, g))
    image, sw, sh = screen.png(w, h, pixels)
    return Image(image, f"The screen of {what(g)}: {w}×{h}" + (f", shown at {sw}×{sh}" if (sw, sh) != (w, h) else ""))


def _click_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if g.get("status") == "running":
        _need_pointer(ctx, g, "Nothing was clicked.")  # before the user is asked about a click that cannot land
    if a.get("scroll"):
        how = f"Scroll {'up' if a['scroll'] > 0 else 'down'} {abs(a['scroll'])}"
    else:
        how = ("Double-click" if a.get("double") else "Click") + (
            f" ({a['button']} button)" if a.get("button", "left") != "left" else "")
    picture = None
    if ctx.showing:  # the screen with a red mark where it lands (only when a window will show it: it takes a moment)
        try:
            w, h, pixels = screen.capture(lambda: (ctx.admin or ctx.pve).open_vnc(g["node"], g["type"], g["vmid"]))
            step = screen.scale_of(w)
            picture, _, _ = screen.png(w, h, screen.mark(w, h, pixels, a["x"] * step, a["y"] * step), max_width=640)
        except Exception:
            pass
    return f"{how} on the screen of {what(g)}", [
        f"At {a['x']}, {a['y']}" + (" — the red mark in the picture." if picture else ".")], picture


def _click(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    opener = _opener(ctx, g)
    note = _need_pointer(ctx, g, "Nothing was clicked.")
    try:
        sx, sy = screen.click(opener, a["x"], a["y"], a.get("button", "left"), bool(a.get("double")),
                              a.get("scroll", 0))
    except ValueError as e:
        raise ToolError(str(e)) from e
    out = {"guest": what(g), "done": "scrolled" if a.get("scroll") else "clicked", "at_screen_pixel": [sx, sy],
           "next": "console_screenshot shows what it did."}
    if note:
        out["note"] = note
    return out


def _send_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    lines = []
    if a.get("text"):
        shown = a["text"] if len(a["text"]) <= 200 else a["text"][:200] + "…"
        lines.append(f"Type: {shown!r}")
    if a.get("keys"):
        lines.append("Press: " + ", ".join(a["keys"]))
    return f"Type into the console of {what(g)}", lines


def _send(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if not a.get("text") and not a.get("keys"):
        raise ToolError("Give text, keys, or both.")
    try:
        pressed = screen.send(_opener(ctx, g), a.get("text", ""), a.get("keys", []))
    except ValueError as e:
        raise ToolError(str(e)) from e
    return {"guest": what(g), "keys_pressed": pressed}


# -- Commands --------------------------------------------------------------------------------------

def _exec_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    return f"Run a command inside {what(g)}", [" ".join(a["command"])] + (
        [f"With {len(a['input'])} characters of input"] if a.get("input") else [])


def _exec(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    if g["type"] != "qemu":
        raise ToolError("Commands run inside VMs through the QEMU guest agent; containers have no such way here.")
    if g.get("status") != "running":
        raise ToolError(f"{what(g)} is not running.")
    if not a["command"] or not all(isinstance(c, str) for c in a["command"]):
        raise ToolError("command is the program and its arguments, as a list of strings.")
    pid = ctx.pve.agent_exec(g["node"], g["vmid"], a["command"], a.get("input", ""))
    end = time.monotonic() + min(int(a.get("timeout_s", 60)), EXEC_WAIT_S)
    while True:
        st = ctx.pve.agent_exec_status(g["node"], g["vmid"], pid)
        if st.get("exited"):
            return {"exit_code": st.get("exitcode"), "stdout": st.get("out-data", ""), "stderr": st.get("err-data", ""),
                    **({"output_truncated": True} if st.get("out-truncated") or st.get("err-truncated") else {})}
        if time.monotonic() > end:
            return {"still_running": True, "pid": pid, "note": "It goes on inside the VM; its output is not read."}
        time.sleep(0.5)


# -- Files ----------------------------------------------------------------------------------------

def _files_of(ctx: Context, g: dict):
    """The guest's side of a copy: a running VM whose agent answers (through it, Claude's token with Files lent), or
    a running container (over the host's SSH with the app's key). ToolError before anything is done otherwise."""
    if g.get("status") != "running":
        raise ToolError(f"{what(g)} is not running.")
    if g["type"] == "lxc":
        address, port, user = _host_ssh(ctx)
        return guestfiles.ContainerFiles(address, port, user, g["vmid"])
    reader = ctx.admin or ctx.pve
    if not reader.agent_ping(g["node"], g["vmid"]):
        raise ToolError(f"The QEMU guest agent of {what(g)} does not answer: the user can install it with Install "
                        "Guest Agent… in Proxmox Controller (on the VM's row). Nothing was done.")
    os_name = guestfiles.os_of(reader.guest_config(g["node"], "qemu", g["vmid"]))
    return guestfiles.VmFiles(ctx.pve, g["node"], g["vmid"], os_name,
                              guestfiles.address_towards(ctx.host.hostname, ctx.host.port))


def _local_paths(a: dict) -> list:
    from pathlib import Path
    paths = [Path(p).expanduser() for p in a["paths"]]
    if not paths:
        raise ToolError("paths: at least one file or folder of the user's computer.")
    for p in paths:
        if not p.is_absolute():
            raise ToolError(f"{p}: give whole paths (from / or a drive letter).")
        if not p.exists():
            raise ToolError(f"{p}: there is no such file or folder on the user's computer.")
    return paths


def _local_folder(a: dict):
    from pathlib import Path
    to = Path(a["to"]).expanduser()
    if not to.is_absolute() or not to.is_dir():
        raise ToolError(f"{to}: give a folder of the user's computer that exists, as a whole path.")
    clash = sorted(n for n in a["names"] if (to / n).exists())
    if clash and not a.get("replace"):
        raise ToolError(f"Already in {to}: {', '.join(clash)}. Nothing was copied; ask with replace: true to "
                        "replace them.")
    return to


def _bad_names(names: list[str]) -> None:
    for n in names:
        if not n or "/" in n or "\\" in n or n in (".", ".."):
            raise ToolError(f"names: '{n}' — names inside the folder, without slashes.")


def _list_files_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    return f"List the folder {a.get('folder') or '(its home)'} of {what(g)}", []


def _list_files(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    files = _files_of(ctx, g)
    try:
        folder, entries = files.list(a.get("folder") or files.home())
    except guestfiles.GuestError as e:
        raise ToolError(str(e)) from e
    return {"guest": what(g), "folder": folder, "entries": [
        {"name": e.name, "folder": e.is_dir, **({} if e.is_dir else {"size": e.size}),
         "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(e.mtime)) if e.mtime else ""}
        for e in entries]}


def _send_files_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    paths = _local_paths(a)
    size = guestfiles.total_size(paths)
    return f"Copy {len(paths)} item{'s' if len(paths) != 1 else ''} from this computer into {what(g)}", [
        *(f"{p}" for p in paths[:12]), *([f"… and {len(paths) - 12} more"] if len(paths) > 12 else []),
        f"Into: {a['folder']}  ({_bytes(size)})",
        "Replaces items of the same name there." if a.get("replace") else "Nothing there is replaced."]


def _send_files(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    paths = _local_paths(a)
    files = _files_of(ctx, g)
    try:
        folder, entries = files.list(a["folder"])
        clash = sorted({p.name for p in paths} & {e.name for e in entries})
        if clash and not a.get("replace"):
            raise ToolError(f"Already in {folder}: {', '.join(clash)}. Nothing was copied; ask with replace: true to "
                            "replace them.")
        t0 = time.monotonic()
        way = files.send(paths, folder, lambda *_: None, _never())
    except guestfiles.GuestError as e:
        raise ToolError(str(e)) from e
    return {"guest": what(g), "sent": [p.name for p in paths], "into": folder, "bytes": guestfiles.total_size(paths),
            "seconds": round(time.monotonic() - t0, 1), "way": way}


def _receive_files_words(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    _bad_names(a["names"])
    to = _local_folder(a)
    names = a["names"]
    return f"Copy {len(names)} item{'s' if len(names) != 1 else ''} from {what(g)} to this computer", [
        f"From: {a['folder']}", *(f"• {n}" for n in names[:12]),
        *([f"… and {len(names) - 12} more"] if len(names) > 12 else []), f"Into: {to}",
        "Replaces items of the same name there." if a.get("replace") else "Nothing there is replaced."]


def _receive_files(ctx: Context, a: dict):
    g = ctx.guest(a["vmid"])
    _bad_names(a["names"])
    to = _local_folder(a)
    files = _files_of(ctx, g)
    try:
        t0 = time.monotonic()
        moved = [0]
        way = files.receive(a["folder"], list(a["names"]), to, lambda done, *_: moved.__setitem__(0, done), _never())
    except guestfiles.GuestError as e:
        raise ToolError(str(e)) from e
    return {"guest": what(g), "received": list(a["names"]), "into": str(to), "bytes": moved[0],
            "seconds": round(time.monotonic() - t0, 1), "way": way}


def _never():
    import threading
    return threading.Event()


def _bytes(n: int) -> str:
    for unit, step in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= step:
            return f"{n / step:.1f} {unit}"
    return f"{n} B"


def _host_ssh(ctx: Context) -> tuple[str, int, str]:
    """(address, port, user) for a command on the host — when the user set up SSH with the app's key for it and the
    host's key is still the one they confirmed. ToolError otherwise, before anything is asked or run."""
    s = ctx.host.extra.get("ssh") if isinstance(ctx.host.extra.get("ssh"), dict) else {}
    if not s or not s.get("key"):
        raise ToolError(f"SSH with this app's key is not set up for {ctx.host.name}. The user sets it up in Proxmox "
                        "Controller: Console → Connect by SSH, with 'Use a key'. Nothing was run.")
    port = int(s.get("port", 22))
    if not ssh.trusted_host_key(ctx.host.hostname, port):
        raise ToolError(f"The SSH key of {ctx.host.name} is no longer the one the user confirmed: they confirm it again "
                        "in Proxmox Controller (Console → Connect by SSH). Nothing was run.")
    return ctx.host.hostname, port, str(s.get("user") or "root")


def _clip(text: str) -> str:
    if len(text) <= HOST_OUTPUT_MAX:
        return text
    half = HOST_OUTPUT_MAX // 2
    return f"{text[:half]}\n… ({len(text) - 2 * half} characters left out) …\n{text[-half:]}"


def _host_command_words(ctx: Context, a: dict):
    address, _, user = _host_ssh(ctx)
    if not a["command"].strip():
        raise ToolError("command is empty.")
    return f"Run a command on {ctx.host.name} itself, as {user}", [
        a["command"], f"On {address} over SSH with this app's key. Claude gets what it prints."]


def _host_command(ctx: Context, a: dict):
    address, port, user = _host_ssh(ctx)
    if not a["command"].strip():
        raise ToolError("command is empty.")
    try:
        code, out, err = ssh.run_command(address, port, user, a["command"],
                                         timeout=min(int(a.get("timeout_s", 60)), EXEC_WAIT_S))
    except ssh.SshError as e:
        raise ToolError(f"{e} Nothing more is known about the command.") from e
    return {"host": ctx.host.name, "exit_code": code, "stdout": _clip(out), "stderr": _clip(err),
            **({"output_shortened": True} if len(out) > HOST_OUTPUT_MAX or len(err) > HOST_OUTPUT_MAX else {})}


def _ct_password_target(ctx: Context, a: dict) -> tuple[dict, str, int, str]:
    """The container and the way in — refused before any window when it cannot work: not a container, not running
    (the password is set inside it), or no SSH with the app's key."""
    g = ctx.guest(a["vmid"])
    if g["type"] != "lxc":
        raise ToolError(f"{what(g)} is a VM: this sets a container's root password. A VM's is set inside it (on its "
                        "console, with console_send and console_type_password).")
    if g.get("status") != "running":
        raise ToolError(f"{what(g)} is {g.get('status') or 'not running'}: the password is set inside it, so it must "
                        "be running. Start it first (guest_power).")
    address, port, user = _host_ssh(ctx)
    return g, address, port, user


def chpasswd_script(vmid: int, node: str) -> str:
    """Sets root's password inside a container from what comes on standard input ('root:password'), so the password
    is never on a command line. pct reaches only the containers of the node it runs on: on another node of a cluster
    it would fail with a puzzling 'config file does not exist' — said plainly instead."""
    want = shlex.quote(node)
    return (f'here=$(uname -n); here=${{here%%.*}}; if [ "$here" != {want} ]; then '
            f'echo "Container {int(vmid)} is on node "{want}", but the app\'s SSH reaches node $here." >&2; exit 3; fi; '
            f"pct exec {int(vmid)} -- chpasswd")


def _ct_password_words(ctx: Context, a: dict):
    g, address, _, user = _ct_password_target(ctx, a)
    return f"Set the root password of {what(g)}", [
        f"pct exec {g['vmid']} -- chpasswd (once it has checked that the SSH reaches node {g.get('node', '')})",
        f"On {address} over SSH with this app's key, as {user}. The password you "
        "type below goes to it on its input, never on a command line; Claude does not see it."]


def _ct_password(ctx: Context, a: dict):
    g, address, port, user = _ct_password_target(ctx, a)
    password = ctx.secret
    if not password or "\n" in password or "\r" in password:
        raise ToolError("No password was given (or it has a line break). Nothing was changed.")
    try:
        code, out, err = ssh.run_command(address, port, user, chpasswd_script(g["vmid"], g.get("node", "")),
                                         timeout=60, input=f"root:{password}\n")
    except ssh.SshError as e:
        raise ToolError(f"{e} The password may not have been changed.") from e
    if code != 0:
        said = (err.strip() or out.strip() or f"exit code {code}").replace(password, "•••")  # (never echoed back)
        raise ToolError(f"The password was not changed: {_clip(said)}")
    return {"guest": what(g), "user": "root", "password": "changed to the one the user typed (not shown to you)",
            "ssh": "Logging in as root with a password over SSH also needs the container's SSH to allow it "
                   "(PermitRootLogin yes). Debian's and Ubuntu's own setting lets root in with a key only."}


# -- the registry ----------------------------------------------------------------------------------

def _tools() -> list[Tool]:
    vm, host = {"host": HOST, "vmid": VMID}, {"host": HOST}
    return [
        Tool("list_hosts", "read", "The Proxmox hosts Proxmox Controller lets you use, whether each is online, and "
             "what you may do on each (each kind of request is off, ask — the user approves it — or on). Call this "
             "first.", {}, reason=False),
        Tool("host_status", "read", "A host's nodes: CPU, memory, system disk, uptime, load, and storage use.", host,
             ("host",), _host_status, reason=False),
        Tool("list_guests", "read", "Every VM and container of a host: state, CPU, memory, disk, IP addresses, tags, "
             "start at boot and boot order, notes.", host, ("host",), _list_guests, reason=False),
        Tool("guest_details", "read", "One guest's full Proxmox configuration, and for a VM the settings waiting for "
             "its next start.", vm, ("host", "vmid"), _guest_details, reason=False),
        Tool("list_snapshots", "read", "A guest's snapshots.", vm, ("host", "vmid"), _snapshots, reason=False),
        Tool("list_backups", "read", "A guest's backups, newest first — also of a guest deleted since, by its old ID.",
             vm, ("host", "vmid"), _backups, reason=False),
        Tool("list_backup_jobs", "read", "The scheduled backups (Datacenter → Backup) and the guests no job covers. "
             "Jobs are changed by the user in the app, not through this connector.", host, ("host",), _backup_jobs,
             reason=False),
        Tool("list_tasks", "read", "The host's recent tasks, newest first, with how they ended.",
             {**host, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, ("host",), _list_tasks,
             reason=False),
        Tool("task_log", "read", "A task's log (a backup's progress, an error).",
             {**host, "upid": {"type": "string", "description": "The task's UPID."},
              "start": {"type": "integer", "minimum": 0, "description": "Line to start from (for long logs)."}},
             ("host", "upid"), _task_log, reason=False),
        Tool("guest_usage", "read", "A guest's average and peak CPU, memory, network and disk use over the last hour, "
             "day, week or month.", {**vm, "timeframe": {"type": "string", "enum": ["hour", "day", "week", "month"]}},
             ("host", "vmid"), _usage, reason=False),
        Tool("list_install_media", "read", "What new guests can be made from: ISO images, container templates, "
             "storages, network bridges and the next free VMID.",
             {**host, "node": {"type": "string"}}, ("host",), _media, reason=False),
        Tool("guest_power", "power", "Start, shut down (clean), stop (at once, like pulling the plug — only if shut "
             "down does not work) or reboot a guest.",
             {**vm, "action": {"type": "string", "enum": ["start", "shutdown", "stop", "reboot"]}},
             ("host", "vmid", "action"), _power, _power_words),
        Tool("bulk_power", "power", "Start several guests one after the other in their boot order, or shut them down "
             "in reverse order — one Proxmox task, like the web UI's Bulk Actions.",
             {**host, "action": {"type": "string", "enum": ["start", "shutdown"]},
              "vmids": {"type": "array", "items": {"type": "integer"}},
              "timeout_s": {"type": "integer", "minimum": 10, "maximum": 7200,
                            "description": "Shut down: how long each guest may take (default 180)."},
              "force_stop": {"type": "boolean", "description": "Shut down: stop those still running after the "
                                                               "timeout (default true)."}},
             ("host", "action", "vmids"), _bulk, _bulk_words),
        Tool("wake_host", "power", "Turn the host on with Wake-on-LAN (it must support it and be set up for it).",
             host, ("host",), _wake, lambda ctx, a: (f"Wake {ctx.host.name} with Wake-on-LAN", [ctx.host.mac or "—"])),
        Tool("edit_guest", "change", "Change a guest's settings: " + ", ".join(EDITABLE) + ". Only what is given "
             "changes.", {**vm, "changes": {"type": "object", "properties": EDITABLE, "additionalProperties": False}},
             ("host", "vmid", "changes"), _edit, _edit_words),
        Tool("grow_disk", "change", "Make a guest's disk bigger (never smaller).",
             {**vm, "disk": {"type": "string", "description": "scsi0, virtio0, sata0, rootfs, mp0…"},
              "add_gb": {"type": "integer", "minimum": 1, "maximum": 65536}},
             ("host", "vmid", "disk", "add_gb"), _grow, _grow_words),
        Tool("take_snapshot", "change", "Take a snapshot of a guest.",
             {**vm, "name": {"type": "string"}, "description": {"type": "string"}}, ("host", "vmid", "name"), _snap,
             _snap_words),
        Tool("backup_now", "change", "Back a guest up now (it keeps running in snapshot mode).",
             {**vm, "storage": {"type": "string"}, "mode": {"type": "string", "enum": ["snapshot", "suspend", "stop"]},
              "protected": {"type": "boolean"}, "note": {"type": "string"}}, ("host", "vmid"), _backup, _backup_words),
        Tool("create_vm", "change", "Create a VM that boots an ISO image (see list_install_media). Profiles: linux, "
             "win11 (UEFI, Secure Boot, TPM 2.0), win10, other. It gets a SPICE display, sound and a USB tablet. "
             "Windows (win11/win10) installs itself with windows_user: the app puts an answer file on a disc of its "
             "own — VirtIO drivers from virtio_iso, the edition, no setup questions, that user with a password the "
             "USER types in Proxmox Controller's window (you never give or see it), optionally Remote Desktop and the "
             "dark theme, and the VirtIO guest tools with the QEMU guest agent last; with start, the app presses "
             "Enter at the installer's 'Press any key to boot from CD' itself (it waits only seconds). The disc is "
             "deleted once Windows is ready.",
             {**host, "name": {"type": "string"}, "iso": {"type": "string", "description": "An ISO's volid."},
              "profile": {"type": "string", "enum": list(PROFILES)}, "vmid": {"type": "integer", "minimum": 100},
              "cores": {"type": "integer", "minimum": 1, "maximum": 512},
              "memory_mib": {"type": "integer", "minimum": 64}, "disk_gb": {"type": "integer", "minimum": 1},
              "storage": {"type": "string"}, "bridge": {"type": "string"}, "virtio_iso": {"type": "string"},
              "host_cpu": {"type": "boolean"}, "guest_agent": {"type": "boolean"},
              "start_at_boot": {"type": "boolean"}, "start": {"type": "boolean"}, "node": {"type": "string"},
              "windows_user": {"type": "string", "description": "Windows installs itself with this user (an "
                               "administrator); the user types its password."},
              "edition": {"type": "string", "description": "As the installer lists it. Default: Windows 11 Pro "
                          "(win10: Windows 10 Pro). Remote Desktop needs Pro, Education, Enterprise or Server."},
              "language": {"type": "string", "description": "Such as en-US or el-GR. Default: from the ISO's name, "
                           "else en-US. The keyboard is English (US)."},
              "remote_desktop": {"type": "boolean"}, "dark_theme": {"type": "boolean"}},
             ("host", "name", "iso"), _create_vm, _create_vm_words, also=_power_for_start,
             secret=lambda a: f"Password for the Windows user '{a['windows_user']}' in the new VM {a.get('name', '')}"
             if a.get("windows_user") else ""),
        Tool("get_cloud_image", "change", "Have the host download Ubuntu Server's official cloud image (24.04 or "
             "26.04), once, to make VMs from with create_cloud_vm.",
             {**host, "release": {"type": "string", "enum": list(CLOUD_IMAGES)}, "storage": {"type": "string"},
              "node": {"type": "string"}}, ("host",), _cloud_image, _cloud_words),
        Tool("create_cloud_vm", "change", "Create an Ubuntu VM from a cloud image (see get_cloud_image) — ready in "
             "about a minute, no installer: a user, its password (the USER types it in Proxmox Controller's window; "
             "you never give or see a password), optionally an SSH public key, network by DHCP. edition 'desktop' "
             "adds a SPICE display, sound and a USB tablet, and installs Ubuntu Desktop and the QEMU guest agent by "
             "itself on the first start (from a setup disc the app makes and deletes afterwards); remote_desktop "
             "turns on Ubuntu's own Remote Desktop (GNOME Remote Desktop: RDP, port 3389, the Ubuntu desktop itself "
             "with its sound) with the same user and password; dark_theme makes the desktop dark.",
             {**host, "name": {"type": "string"}, "image": {"type": "string", "description": "The image's volid."},
              "edition": {"type": "string", "enum": ["server", "desktop"]},
              "remote_desktop": {"type": "boolean", "description": "Desktop only."},
              "dark_theme": {"type": "boolean", "description": "Desktop only."},
              "username": {"type": "string", "description": "Default: user."}, "vmid": {"type": "integer", "minimum": 100},
              "cores": {"type": "integer", "minimum": 1, "maximum": 512}, "memory_mib": {"type": "integer", "minimum": 512},
              "disk_gb": {"type": "integer", "minimum": 4}, "storage": {"type": "string"}, "bridge": {"type": "string"},
              "ssh_public_key": {"type": "string"}, "start": {"type": "boolean", "description": "Default: true."},
              "start_at_boot": {"type": "boolean"}, "node": {"type": "string"}},
             ("host", "name", "image"), _cloud_vm, _cloud_vm_words, also=("power",),
             secret=lambda a: f"Password for the user '{a.get('username', 'user')}' in the new VM {a.get('name', '')}"),
        Tool("create_container", "change", "Create an unprivileged container from a template (see "
             "list_install_media). Its root password is typed by the USER in Proxmox Controller's window (you never "
             "give or see it); an SSH public key can be added.",
             {**host, "hostname": {"type": "string"}, "template": {"type": "string", "description": "A template's volid."},
              "vmid": {"type": "integer", "minimum": 100}, "cores": {"type": "integer", "minimum": 1},
              "memory_mib": {"type": "integer", "minimum": 16}, "swap_mib": {"type": "integer", "minimum": 0},
              "disk_gb": {"type": "integer", "minimum": 1}, "storage": {"type": "string"},
              "bridge": {"type": "string"}, "ip": {"type": "string", "description": "dhcp, or like 192.168.1.50/24."},
              "gateway": {"type": "string"}, "ssh_public_key": {"type": "string"}, "nesting": {"type": "boolean"},
              "start_at_boot": {"type": "boolean"}, "start": {"type": "boolean"}, "node": {"type": "string"}},
             ("host", "hostname", "template"), _create_ct, _create_ct_words, also=_power_for_start,
             secret=lambda a: f"Root password of the new container {a.get('hostname', '')}", secret_min=5),
        Tool("clone_vm", "change", "Copy a VM or a template as a new VM.",
             {**vm, "new_name": {"type": "string"}, "new_vmid": {"type": "integer", "minimum": 100},
              "full": {"type": "boolean"}, "storage": {"type": "string"}}, ("host", "vmid", "new_name"), _clone,
             _clone_words),
        Tool("download_iso", "change", "Have the host download an ISO image from a web address.",
             {**host, "url": {"type": "string"}, "filename": {"type": "string"}, "storage": {"type": "string"},
              "checksum_sha256": {"type": "string"}, "node": {"type": "string"}}, ("host", "url"), _download,
             _download_words),
        Tool("restore_backup", _restore_kind, "Restore a guest's backup as a new guest — or over the guest itself "
             "(replace: true; it must be stopped, and that is a Destroy request). A guest deleted since (its backup "
             "found by list_backups with its old ID) comes back as itself: its old ID while free, its old MAC.",
             {**vm, "volid": {"type": "string"}, "replace": {"type": "boolean"},
              "new_vmid": {"type": "integer", "minimum": 100}, "storage": {"type": "string"},
              "start": {"type": "boolean"}}, ("host", "vmid", "volid"), _restore, _restore_words,
             also=_power_for_start, doc_kinds=("change", "destroy")),
        Tool("delete_guest", "destroy", "Delete a stopped guest with all its disks and snapshots — and its backups, "
             "which Proxmox would keep (protected ones always stay), unless keep_backups is true.",
             {**vm, "keep_backups": {"type": "boolean", "description": "Keep its backups."}}, ("host", "vmid"),
             _delete, _delete_words),
        Tool("rollback_snapshot", "destroy", "Roll a guest back to a snapshot (what came after it is lost).",
             {**vm, "snapshot": {"type": "string"}}, ("host", "vmid", "snapshot"), _rollback, _rollback_words),
        Tool("delete_snapshot", "destroy", "Delete a snapshot.", {**vm, "snapshot": {"type": "string"}},
             ("host", "vmid", "snapshot"), _delsnap, _delsnap_words),
        Tool("delete_backup", "destroy", "Delete a backup (not a protected one).", {**host, "volid": {"type": "string"}},
             ("host", "volid"), _delbackup, _delbackup_words),
        Tool("stop_task", "destroy", "Stop a running task (one started through this connector).",
             {**host, "upid": {"type": "string"}}, ("host", "upid"), _stoptask, _stoptask_words),
        Tool("host_power", "host", "Shut down or reboot the host itself (its guests are shut down first).",
             {**host, "action": {"type": "string", "enum": ["shutdown", "reboot"]}, "node": {"type": "string"}},
             ("host", "action"), _host_power, _host_words),
        Tool("console_screenshot", "console", "A picture of a running guest's screen.", vm, ("host", "vmid"),
             _screenshot, _screenshot_words),
        Tool("console_send", "console", "Type text into a running guest's console and/or press keys: enter, tab, "
             "escape, backspace, delete, arrows (up, down, left, right), home, end, pageup, pagedown, f1–f12, and "
             "combinations such as ctrl+alt+delete or ctrl+c. Text is typed as on a US keyboard.",
             {**vm, "text": {"type": "string"}, "keys": {"type": "array", "items": {"type": "string"}}},
             ("host", "vmid"), _send, _send_words),
        Tool("console_click", "console", "Click — or double-click, right-click, or turn the wheel (scroll: + up, − down) — "
             "on a running guest's screen at x, y of the latest console_screenshot picture (take a fresh one first: "
             "the click lands where things are now). For installers and desktops that need the mouse; keys "
             "(console_send) are surer where they work. The user sees a red mark where it will land. It needs an "
             "absolute pointer in the VM (a USB tablet; Linux also has QEMU's vmmouse): without one it says so "
             "and clicks nothing.",
             {**vm, "x": {"type": "integer", "minimum": 0}, "y": {"type": "integer", "minimum": 0},
              "button": {"type": "string", "enum": list(screen.BUTTONS)}, "double": {"type": "boolean"},
              "scroll": {"type": "integer", "minimum": -50, "maximum": 50,
                         "description": "Wheel steps instead of a click."}},
             ("host", "vmid", "x", "y"), _click, _click_words),
        Tool("console_type_password", "console", "Type a password into a running guest's console — at a login, a "
             "sudo prompt, or an installer's password screen. The USER types it in Proxmox Controller's window (with "
             "a picture of the screen); you never give or see it. Enter is pressed after it unless enter is false. "
             "A screen with a second field to repeat it (an installer's 'Confirm password'): put the cursor in the "
             "first and give confirm_at = [x, y] of the second, from the latest console_screenshot picture — the user "
             "types it twice in the window (so a typo shows); the app types it, clicks there, and types it again. "
             "confirm (Tab instead of the click) only where Tab goes straight to the second field — check that first "
             "with an empty field: a 'Show' button between them would get it. Where the repeat is on a screen of its "
             "own, call this twice instead.",
             {**vm, "enter": {"type": "boolean"}, "confirm": {"type": "boolean"},
              "confirm_at": {"type": "array", "items": {"type": "integer"},
                             "description": "[x, y] of the confirmation field."}},
             ("host", "vmid"), _type_password, _type_password_words,
             secret=lambda a: "The new password (it goes into both fields)" if a.get("confirm") or a.get("confirm_at")
             else "The password to type",
             secret_repeat=lambda a: bool(a.get("confirm") or a.get("confirm_at"))),
        Tool("list_guest_files", "files", "The files and folders in a folder of a running VM (through its QEMU guest "
             "agent) or container (over the host's SSH): name, folder or not, size, modified. Without folder: /home "
             "on Linux, C:\\Users on Windows, /root in a container; on Windows an empty folder lists the drives.",
             {**vm, "folder": {"type": "string"}}, ("host", "vmid"), _list_files, _list_files_words),
        Tool("send_files", "files", "Copy files and folders of the user's computer (whole paths) into a folder of a "
             "running VM or container — names and times kept, folders whole. Fast over the network when the guest "
             "can reach the computer, otherwise through Proxmox (about 1 MB/s). What is there already is not "
             "replaced unless replace is true. The user sees every path in the approval window.",
             {**vm, "paths": {"type": "array", "items": {"type": "string"}},
              "folder": {"type": "string", "description": "The guest's folder it goes into."},
              "replace": {"type": "boolean"}}, ("host", "vmid", "paths", "folder"), _send_files, _send_files_words),
        Tool("receive_files", "files", "Copy files and folders (names) from a folder of a running VM or container into "
             "a folder of the user's computer (a whole path that exists). What is there already is not replaced "
             "unless replace is true.",
             {**vm, "folder": {"type": "string", "description": "The guest's folder they are in."},
              "names": {"type": "array", "items": {"type": "string"}},
              "to": {"type": "string", "description": "The folder of the user's computer they go into."},
              "replace": {"type": "boolean"}}, ("host", "vmid", "folder", "names", "to"), _receive_files,
             _receive_files_words),
        Tool("run_command", "commands", "Run a program inside a running VM through the QEMU guest agent and get its "
             "output (for example [\"systemctl\", \"status\", \"nginx\"], or [\"sh\", \"-c\", \"df -h\"]).",
             {**vm, "command": {"type": "array", "items": {"type": "string"}},
              "input": {"type": "string", "description": "Text given to the program's standard input."},
              "timeout_s": {"type": "integer", "minimum": 1, "maximum": EXEC_WAIT_S}},
             ("host", "vmid", "command"), _exec, _exec_words),
        Tool("host_command", "host_commands", "Run a shell command on the Proxmox host itself, as root, over the SSH "
             "key the user set up in Proxmox Controller, and get its output and exit code — for what the API cannot "
             "do (installed programs, services, logs, files). One command line a request: the user sees it as it is "
             "in the approval window, every time. It runs on the host at the address the app connects to.",
             {**host, "command": {"type": "string", "description": "A shell command line, run by the user's shell "
                                  "on the host (pipes and ; work)."},
              "timeout_s": {"type": "integer", "minimum": 1, "maximum": EXEC_WAIT_S}},
             ("host", "command"), _host_command, _host_command_words),
        Tool("set_container_root_password", "host_commands", "Set a running container's root password to one the "
             "USER types in Proxmox Controller's window (you never give or see it) — for a container whose root "
             "password is lost, or to give it a new one. It runs pct exec <vmid> -- chpasswd on the host over the "
             "app's SSH key, so it is a host command; the container must be on the node the app connects to.",
             vm, ("host", "vmid"), _ct_password, _ct_password_words,
             secret=lambda a: f"New root password of container {a.get('vmid', '')}", secret_min=5),
    ]


TOOLS: dict[str, Tool] = {t.name: t for t in _tools()}


def _summary(text: str) -> str:
    """A tool's description up to the end of its first sentence."""
    m = re.match(r"(.+?[.!?])(\s|$)", text, re.S)
    return (m.group(1) if m else text).strip()


def access_table() -> list[dict]:
    """Every switch with every tool under it, from the code itself — so Help and docs/claude-access.md always say
    what the connector really does (the user's wish, 17/10: anyone who downloads the app sees which switch opens what)."""
    out = []
    for key, title, covers, default in claude_policy.CATEGORIES:
        tools = []
        for t in TOOLS.values():
            kinds = t.doc_kinds or ((t.kind,) if isinstance(t.kind, str) else (t.kind_of({}),))
            if key not in kinds:
                continue
            notes = []
            if "power" in t.also_of({"start": True}):
                notes.append("starting it also needs Power not Off")
            if t.secret_prompt({}):
                notes.append("asks you for a password")
            if len(kinds) > 1:
                notes.append(" or ".join(claude_policy.TITLES[k] for k in kinds) + ", by its arguments")
            tools.append({"name": t.name, "does": _summary(t.description), "notes": notes})
        privs = claude_policy.PRIVILEGES[key]
        if key == "host_commands":
            enforced = ("This app only: the commands go over SSH with the app's key, not through Proxmox's API, so "
                        "Proxmox cannot refuse them on its own. Each one is shown in the approval window, every time "
                        "(no 'Allow This Kind for 1 Hour', nor longer). The app's SSH key file itself is not encrypted: a program "
                        "running as you on this computer (Claude Code with a shell, too) could read it and use it "
                        "without asking — Off stops the connector, not that.")
        elif key == "files":
            enforced = ("VMs — this app and Proxmox: lent to Claude's token only for a request the app allows: "
                        f"{', '.join(privs)}; only the app's own copy and listing commands run with it. Containers — "
                        "this app only: over the app's SSH key, as host commands. Paths on the user's computer are "
                        "shown whole in the approval window; nothing is replaced unless replace is asked.")
        elif key == "read":
            enforced = "This app and Proxmox: Claude's token holds these privileges while Read is On: " + ", ".join(privs)
        else:
            enforced = ("This app and Proxmox: lent to Claude's token only for a request the app allows: " +
                        ", ".join(privs))
        out.append({"key": key, "title": title, "covers": covers, "default": default, "enforced": enforced,
                    "tools": tools})
    return out

def access_markdown() -> str:
    """docs/claude-access.md — what each switch lets Claude do, for anyone who downloads the app. Written by
    tools/claude_access_doc.py from access_table(); a test fails if the file falls behind the code."""
    lines = ["# What Claude may do — the switches", "",
             "<!-- Made by tools/claude_access_doc.py from the code (connector_tools.access_table): do not edit. -->", "",
             "Claude reaches your Proxmox hosts only through Proxmox Controller, and only as far as each host's switches "
             "let it. Every switch is **Off** (refused), **Ask** (a window of the app asks you: *Allow*, *Allow This "
             "Kind for 1 Hour* — its arrow: 3, 8 or 12 hours — or *Deny*; no answer in two minutes is a No) or **On** "
             "(done at once). Above them, "
             "*Let Claude use Proxmox Controller* turns all of it off. Passwords never go through Claude: where one is "
             "needed, the app asks you for it in its own window. Every request is logged with the reason Claude gave.",
             ""]
    for row in access_table():
        lines += [f"## {row['title']} — default: {row['default'].capitalize()}", "", f"{row['covers']}.", "",
                  f"*{row['enforced']}*", "", "| Tool | What it does |", "|---|---|"]
        for t in row["tools"]:
            notes = f" *({'; '.join(t['notes'])})*" if t["notes"] else ""
            lines.append(f"| `{t['name']}` | {t['does'].replace('|', '/')}{notes} |")
        lines.append("")
    return "\n".join(lines)


INSTRUCTIONS = (
    "Proxmox Controller lets you manage the user's Proxmox VE hosts. Call list_hosts first: it gives each host's id "
    "and, per kind of request (read, power, change, destroy, host, console, commands, host_commands), whether it is "
    "off, ask or on. "
    "'ask' means the user approves each request in a window of the app (it may take a while, and they may deny it); "
    "'off' means it will be refused — tell the user instead of trying another way. Every request other than reading "
    "needs a short reason, shown to the user. Long Proxmox tasks come back as running: follow them with task_log. "
    "You never give or see a password: where one is needed (a new VM's user, a container's root, a console prompt) "
    "the user types it in the app's window.")
