"""Claude's own way into a Proxmox host, made with the user's token when the user presses Set Up:

    user   claude-controller@pve        cannot log in to the web interface (it has no password)
    role   ProxmoxControllerClaude      what Claude's token may do
    acl    /  → that role, for that user (inherited everywhere)
    token  claude-controller@pve!connector   privilege separation off: exactly the role's privileges

At rest the role holds only reading (when Read is On). Everything else is lent: just before a request the switches
allow (or the user approved) runs, the role gets that kind's privileges, and they are taken back the moment it ends.
A privilege meant for one place only (Datastore.Allocate on a backup job's storage) is lent as "privilege@path": a
second role, ProxmoxControllerClaudeScoped, holds it, with a permission on that path alone while it is lent. Proxmox
lets a permission on a deeper path REPLACE what the same user inherits from above (measured 14/11/2026: during a job
request the token no longer saw the NAS among the backup storages), so that role holds the main role's privileges
too — another request running meanwhile keeps what it was lent on that storage.
So even a request that never went through this app finds Claude's token able to read and nothing more — and what is
Off is never lent at all. (Proxmox cannot tell creating a guest from deleting one — both need VM.Allocate — so
standing privileges would have let a token meant for Change delete guests too.)"""

from __future__ import annotations

import threading
from collections import Counter
from contextlib import contextmanager
from typing import Callable

from . import claude_policy
from .pve import Pve, PveError, q

USER = "claude-controller@pve"
TOKEN = "connector"
TOKEN_ID = f"{USER}!{TOKEN}"
ROLE = "ProxmoxControllerClaude"
ROLE_SCOPED = "ProxmoxControllerClaudeScoped"  # privileges lent on one path only ("Datastore.Allocate@/storage/nas")
AT = "@"
COMMENT = "Proxmox Controller: Claude's access (follows the switches in the app)"


def scoped(priv: str, path: str) -> str:
    """A privilege lent on `path` alone, as Loans count it."""
    return f"{priv}{AT}{path}"


def _split(privs) -> tuple[list[str], dict[str, list[str]]]:
    """(privileges for everywhere, {path: privileges for that path alone})."""
    plain, paths = [], {}
    for p in privs:
        if AT in p:
            priv, path = p.split(AT, 1)
            paths.setdefault(path, [])
            if priv not in paths[path]:
                paths[path].append(priv)
        elif p not in plain:
            plain.append(p)
    return plain, paths


def _role_exists(admin: Pve, role: str = ROLE) -> bool:
    return any(r.get("roleid") == role for r in admin.get("/access/roles") or [])


def _set_role(admin: Pve, privs: list[str], role: str = ROLE) -> list[str]:
    """Creates or updates the role. A privilege this Proxmox release does not know (Sys.AccessNetwork came later) is
    left out rather than failing. Returns the privileges given."""
    tries = [privs]
    lighter = [p for p in privs if p not in claude_policy.OPTIONAL_PRIVILEGES]
    if lighter != privs:
        tries.append(lighter)
    exists = _role_exists(admin, role)
    for i, attempt in enumerate(tries):
        try:
            if exists:
                admin.put(f"/access/roles/{q(role)}", privs=",".join(attempt))
            else:
                admin.post("/access/roles", roleid=role, privs=",".join(attempt))
            return attempt
        except PveError as e:
            if i + 1 < len(tries) and "privilege" in str(e).lower():
                continue
            raise
    return []


def standing(switches: dict) -> list[str]:
    """What Claude's token holds at rest: reading, when Read is On. Everything else is lent per request."""
    return list(claude_policy.PRIVILEGES["read"]) if switches.get("read") == claude_policy.ON else []


def apply(admin: Pve, privs: list[str]) -> list[str]:
    """The role gets exactly these privileges; with none, the permission itself goes. Returns those given."""
    if not privs:
        try:
            admin.request("PUT", "/access/acl", {"path": "/", "roles": ROLE, "users": USER, "delete": 1})
        except PveError:
            pass  # not there: nothing to take away
        return []
    given = _set_role(admin, privs)
    admin.request("PUT", "/access/acl", {"path": "/", "roles": ROLE, "users": USER, "propagate": 1})
    return given


def apply_scoped(admin: Pve, paths: dict[str, list[str]], also: list[str] | tuple = ()) -> None:
    """The privileges lent on single paths: the scoped role holds them all — and `also`, what the main role holds
    now, since a permission on a path replaces what is inherited there — with a permission on each path lent now;
    a permission on a path no longer lent is taken away, and with none lent the role itself goes (it would hold the
    last request's privileges, unused but there)."""
    have = [e.get("path") for e in admin.get("/access/acl") or []
            if e.get("roleid") == ROLE_SCOPED and e.get("ugid") == USER]
    for path in have:
        if path not in paths:
            admin.request("PUT", "/access/acl", {"path": path, "roles": ROLE_SCOPED, "users": USER, "delete": 1})
    if not paths:
        if _role_exists(admin, ROLE_SCOPED):
            try:
                admin.delete(f"/access/roles/{q(ROLE_SCOPED)}")
            except PveError as e:
                if not _gone(e):
                    raise
        return
    union = []
    for privs in list(paths.values()) + [list(also)]:
        union += [p for p in privs if p not in union]
    _set_role(admin, union, ROLE_SCOPED)
    for path in paths:
        if path not in have:
            admin.request("PUT", "/access/acl", {"path": path, "roles": ROLE_SCOPED, "users": USER, "propagate": 0})


def sync(admin: Pve, switches: dict, lent: list[str] | tuple = (), scoped_too: bool = False) -> list[str]:
    """The role as the switches say at rest, plus what is lent to requests running now. Privileges lent on single
    paths are set when there are any, or tidied when asked (scoped_too: one such loan just ended, or the app starts:
    one may have been left behind)."""
    plain, paths = _split(lent)
    privs = standing(switches)
    privs += [p for p in plain if p not in privs]
    given = apply(admin, privs)
    if paths or scoped_too:
        apply_scoped(admin, paths, given)
    return given


class Loans:
    """Privileges lent to running requests, per host, counted: two requests at once share them, and they go back
    only when the last one ends — in whatever order the requests end. Role changes are made one at a time.
    Each host keeps one counter for good: one put in its place would leave a request that began before it counting
    on the old one, so its end would take back what a later request holds and give back nothing of its own
    (found 07/11: a copy refused mid-way, and the agent's privilege left on the role at rest)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.active: dict[str, Counter] = {}

    def lent(self, host_id: str) -> list[str]:
        return [p for p, n in self.active.get(host_id, Counter()).items() if n > 0]

    def tidy(self, host_id: str, admin: Pve, switches: dict) -> list[str]:
        """The role as the switches say at rest — keeping what requests running now were lent — in turn with them."""
        with self.lock:
            return sync(admin, switches, self.lent(host_id), scoped_too=True)

    @contextmanager
    def lend(self, host_id: str, admin: Pve, switches: Callable[[], dict], privs: list[str] | tuple):
        with self.lock:
            counter = self.active.setdefault(host_id, Counter())
            counter.update(privs)
            sync(admin, switches(), self.lent(host_id))
        try:
            yield
        finally:
            with self.lock:
                counter.subtract(privs)
                for p in [p for p, n in counter.items() if n <= 0]:
                    del counter[p]  # in place: the host's one counter, shared with requests still running
                sync(admin, switches(), self.lent(host_id), scoped_too=any(AT in p for p in privs))


def setup(admin: Pve, switches: dict) -> tuple[str, list[str]]:
    """Makes (or renews) the user, role, permission and token. Returns (the token's secret, the privileges given).
    A token made again replaces the old one, whose secret stops working."""
    try:
        admin.post("/access/users", userid=USER, comment=COMMENT)
    except PveError as e:
        if "exist" not in str(e).lower():
            raise
    given = sync(admin, switches)
    try:
        admin.delete(f"/access/users/{q(USER)}/token/{q(TOKEN)}")
    except PveError:
        pass  # there was none
    data = admin.post(f"/access/users/{q(USER)}/token/{q(TOKEN)}", privsep=0, comment=COMMENT) or {}
    if not data.get("value"):
        raise PveError("Proxmox made the token but did not give its secret.")
    return str(data["value"]), given


def _gone(e: PveError) -> bool:
    text = str(e).lower()
    return "exist" in text or "no such" in text


def remove(admin: Pve) -> None:
    """Takes Claude's access away from the host: token, user (and with it the permission), role."""
    for path in (f"/access/users/{q(USER)}/token/{q(TOKEN)}", f"/access/users/{q(USER)}", f"/access/roles/{q(ROLE)}",
                 f"/access/roles/{q(ROLE_SCOPED)}"):
        try:
            admin.delete(path)
        except PveError as e:
            if not _gone(e):  # already gone is fine; anything else is not
                raise
