"""What Claude may do through the connector: nine kinds of request, each Off, Ask or On, per host, under one
switch for all. The Proxmox privileges of Claude's own token follow the same switches (core/claude_access.py), so a
kind that is Off is refused by Proxmox too — not only by this app. Host commands are the exception: they go over
SSH with the app's key, not through the API, so only this app refuses them.

Privileges are the ones each API call checks (read from Proxmox's API schema, PVE 9). Some are shared — deleting a
guest needs VM.Allocate, as creating one does — so there only the app tells Change from Destroy."""

from __future__ import annotations

import time

OFF, ASK, ON = "off", "ask", "on"
STATES = (OFF, ASK, ON)

# key, title, what it covers (shown beside its switch), default
CATEGORIES = (  # (each description fits one line beside its switch; Help has the whole list)
    ("read", "Read", "State, addresses, settings, notes, snapshots, backups, jobs, tasks, graphs", ON),
    ("power", "Power", "Start, shut down, stop, reboot; Bulk Start and Shut Down; wake the host", ASK),
    ("change", "Change", "Edit, notes, snapshots, Back Up Now, new VMs and containers, copies, ISOs", ASK),
    ("destroy", "Destroy", "Delete guests, roll back or delete snapshots, delete backups, restore over", OFF),
    ("host", "Host", "Shut down or reboot the host itself", OFF),
    ("console", "Console", "See a guest's screen, type into it and click on it", OFF),
    ("commands", "Commands", "Run commands inside VMs that have the QEMU guest agent", OFF),
    ("files", "Files", "Copy files between this computer and VMs or containers, and list their folders", OFF),
    ("host_commands", "Host commands", "Run commands on the host itself, as root, over the app's SSH key", OFF),
)
KEYS = tuple(c[0] for c in CATEGORIES)
TITLES = {c[0]: c[1] for c in CATEGORIES}
DEFAULTS = {c[0]: c[3] for c in CATEGORIES}

PRIVILEGES = {
    "read": ("VM.Audit", "Sys.Audit", "Datastore.Audit", "VM.GuestAgent.Audit",
             "SDN.Audit"),  # without it Proxmox lists no network bridges at all, and says nothing (Network.pm)
    "power": ("VM.PowerMgmt",),
    "change": ("VM.Config.CPU", "VM.Config.Memory", "VM.Config.Disk", "VM.Config.Network", "VM.Config.Options",
               "VM.Config.HWType", "VM.Config.CDROM", "VM.Config.Cloudinit", "VM.Snapshot", "VM.Backup", "VM.Clone",
               "VM.Allocate", "Datastore.AllocateSpace", "Datastore.AllocateTemplate", "SDN.Use",
               "Sys.AccessNetwork"),  # (the newer privilege for downloads by URL; left out where Proxmox lacks it)
    "destroy": ("VM.Allocate", "VM.Snapshot", "VM.Snapshot.Rollback", "VM.Backup", "Datastore.AllocateSpace"),
    "host": ("Sys.PowerMgmt",),
    "console": ("VM.Console",),
    "commands": ("VM.GuestAgent.Unrestricted",),
    # VMs: the agent's exec and file calls (Unrestricted covers both); only the app's own copy commands run.
    # Containers go over the app's SSH key, as host commands do.
    "files": ("VM.GuestAgent.Unrestricted",),
    "host_commands": (),  # over SSH with the app's key: no API privilege to lend (and none Proxmox could refuse)
}
NOT_HOUR = ("host_commands",)  # each one seen: no "Allow this kind for 1 hour" (the user's rule for the host)
OPTIONAL_PRIVILEGES = ("Sys.AccessNetwork",)  # not in every Proxmox VE 9 release
TEMP_ALLOW_S = 3600  # "Allow this kind for 1 hour"
TEMP_ALLOW_HOURS = (1, 3, 8, 12)  # the button: 1 hour; its arrow: the rest (the user's, 19/10: Claude works through the night)


def host_switches(settings: dict, host_id: str) -> dict:
    """The switches of one host: what was chosen, else the defaults (a switch added later starts at its default)."""
    saved = ((settings.get("claude") or {}).get("hosts") or {}).get(host_id) or {}
    return {k: saved.get(k) if saved.get(k) in STATES else DEFAULTS[k] for k in KEYS}


def set_switch(settings: dict, host_id: str, key: str, state: str) -> None:
    if key not in KEYS or state not in STATES:
        raise ValueError(f"{key}={state}")
    claude = settings.setdefault("claude", {})
    hosts = claude.setdefault("hosts", {})
    hosts.setdefault(host_id, dict(DEFAULTS))[key] = state


def enabled(settings: dict) -> bool:
    """The switch for all: off until the user turns the connector on."""
    return bool((settings.get("claude") or {}).get("enabled"))


def privileges(switches: dict, available: tuple | None = None) -> list[str]:
    """Claude's token gets the privileges of every kind that is not Off (Ask needs them too: the app asks first)."""
    out = []
    for key in KEYS:
        if switches.get(key, OFF) != OFF:
            for p in PRIVILEGES[key]:
                if p not in out and (available is None or p in available or p not in OPTIONAL_PRIVILEGES):
                    out.append(p)
    return out


class Allowances:
    """'Allow this kind for 1, 3, 8 or 12 hours', remembered only while the app runs."""

    def __init__(self):
        self.until: dict[tuple[str, str], float] = {}

    def grant(self, host_id: str, key: str, seconds: float = TEMP_ALLOW_S) -> None:
        self.until[(host_id, key)] = time.monotonic() + seconds

    def active(self, host_id: str, key: str) -> bool:
        return self.until.get((host_id, key), 0) > time.monotonic()

    def remaining(self, host_id: str, key: str) -> float:
        """Seconds left of what was granted for hours (0: none)."""
        return max(0.0, self.until.get((host_id, key), 0) - time.monotonic())

    def clear(self) -> None:
        self.until.clear()


def decide(settings: dict, host_id: str, key: str, allowances: Allowances | None = None) -> str:
    """'off' | 'ask' | 'on' for one request; everything is off while the switch for all is off."""
    if not enabled(settings):
        return OFF
    state = host_switches(settings, host_id)[key]
    if state == ASK and allowances is not None and allowances.active(host_id, key):
        return ON
    return state
