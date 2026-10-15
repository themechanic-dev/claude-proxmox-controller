"""Claude's own way into a Proxmox host, made with the user's token when the user presses Set Up:

    user   claude-controller@pve        cannot log in to the web interface (it has no password)
    role   ProxmoxControllerClaude      what Claude's token may do
    acl    /  → that role, for that user (inherited everywhere)
    token  claude-controller@pve!connector   privilege separation off: exactly the role's privileges

At rest the role holds only reading (when Read is On). Everything else is lent: just before a request the switches
allow (or the user approved) runs, the role gets that kind's privileges, and they are taken back the moment it ends.
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
COMMENT = "Proxmox Controller: Claude's access (follows the switches in the app)"


def _role_exists(admin: Pve) -> bool:
    return any(r.get("roleid") == ROLE for r in admin.get("/access/roles") or [])


def _set_role(admin: Pve, privs: list[str]) -> list[str]:
    """Creates or updates the role. A privilege this Proxmox release does not know (Sys.AccessNetwork came later) is
    left out rather than failing. Returns the privileges given."""
    tries = [privs]
    lighter = [p for p in privs if p not in claude_policy.OPTIONAL_PRIVILEGES]
    if lighter != privs:
        tries.append(lighter)
    exists = _role_exists(admin)
    for i, attempt in enumerate(tries):
        try:
            if exists:
                admin.put(f"/access/roles/{q(ROLE)}", privs=",".join(attempt))
            else:
                admin.post("/access/roles", roleid=ROLE, privs=",".join(attempt))
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


def sync(admin: Pve, switches: dict, lent: list[str] | tuple = ()) -> list[str]:
    """The role as the switches say at rest, plus what is lent to requests running now."""
    privs = standing(switches)
    privs += [p for p in lent if p not in privs]
    return apply(admin, privs)


class Loans:
    """Privileges lent to running requests, per host, counted: two requests at once share them, and they go back
    only when the last one ends. Role changes are made one at a time."""

    def __init__(self):
        self.lock = threading.Lock()
        self.active: dict[str, Counter] = {}

    def lent(self, host_id: str) -> list[str]:
        return [p for p, n in self.active.get(host_id, Counter()).items() if n > 0]

    def tidy(self, host_id: str, admin: Pve, switches: dict) -> list[str]:
        """The role as the switches say at rest — keeping what requests running now were lent — in turn with them."""
        with self.lock:
            return sync(admin, switches, self.lent(host_id))

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
                self.active[host_id] = +counter  # (drops what reached zero)
                sync(admin, switches(), self.lent(host_id))


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
    for path in (f"/access/users/{q(USER)}/token/{q(TOKEN)}", f"/access/users/{q(USER)}", f"/access/roles/{q(ROLE)}"):
        try:
            admin.delete(path)
        except PveError as e:
            if not _gone(e):  # already gone is fine; anything else is not
                raise
