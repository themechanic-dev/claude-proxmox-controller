"""A newer Proxmox Controller: told by a small feed on the app's website, shown as a striped tab beside the ☰ button,
installed when the user clicks Install (the user's choice, 26/10: not silently, as Torque's desktop does).

The feed (FEED_URL, JSON):

    {"version": "1.1.0", "notes": ["What changed", …], "page": "https://themechanic.store/…",
     "windows": {"url": "https://themechanic.store/…/ProxmoxController-1.1.0-setup.exe", "sha256": "…", "size": …},
     "linux": {"url": "https://themechanic.store/…/proxmox-controller_1.1.0_amd64.deb", "sha256": "…", "size": …}}

It is read a few seconds after the app starts and every six hours (as Torque's), and what it said is kept, so the tab
shows at the next start too. Install downloads this system's file into the app's data folder, checks its SHA-256 —
a cut or altered file never reaches the installer — and hands it over: on Windows the setup program (it stops the
app itself, then replaces it); on Linux `pkexec apt-get install` of the .deb — the system asks for the password —
then the app starts again. An app not installed that way (run from its source) opens the download page instead.
Files come only from the app's own website, over HTTPS (core/web: the app's User-Agent and certificates)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .. import VERSION
from . import procs, store, web

FEED_URL = "https://themechanic.store/updates/proxmox-controller.json"
PAGE_URL = "https://themechanic.store/controller"
HOSTS = ("themechanic.store",)  # where the feed may send for a file
CHECK_EVERY_S = 6 * 3600
FIRST_CHECK_S = 5  # after the start: the window first
TIMEOUT_S = 10.0
PACKAGE = "proxmox-controller"  # the .deb's name


class UpdateError(Exception):
    """Something the user is told as it is."""


def version_key(v: str) -> tuple:
    """'1.10.2' → (1, 10, 2); what is not a number counts as 0 (never newer)."""
    out = []
    for part in str(v or "").strip().lstrip("vV").split("."):
        digits = "".join(c for c in part if c.isdigit())
        out.append(int(digits) if digits and digits == part else 0)
    return tuple(out) or (0,)


def newer(feed: dict | None, current: str = VERSION) -> bool:
    return bool(feed) and version_key(feed.get("version", "")) > version_key(current)


def platform_key() -> str:
    return "windows" if sys.platform.startswith("win") else "linux"


def allowed(url: str) -> bool:
    parts = urlsplit(url or "")
    return parts.scheme == "https" and (parts.hostname or "") in HOSTS


def parse(text: str) -> dict:
    """The feed, checked: a version, notes as a list of lines, this system's file only from the app's website."""
    feed = json.loads(text)
    if not isinstance(feed, dict) or version_key(feed.get("version", "")) == (0,):
        raise ValueError("no version in the update feed")
    notes = feed.get("notes") or []
    feed["notes"] = [str(n) for n in notes] if isinstance(notes, list) else [str(notes)]
    for key in ("windows", "linux"):
        item = feed.get(key)
        if item is not None and not (isinstance(item, dict) and allowed(str(item.get("url", "")))
                                     and len(str(item.get("sha256", ""))) == 64):
            feed.pop(key)  # (a file from anywhere else, or without its checksum, is not offered)
    return feed


def fetch_feed() -> str:
    with web.open_url(FEED_URL, timeout=TIMEOUT_S) as r:
        return r.read(256 * 1024).decode("utf-8")


def _cache_path() -> Path:
    return store.data_dir() / "update.json"


def kept() -> dict | None:
    """What the feed said last (shown at the start, before it is read again)."""
    try:
        return parse(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def check() -> dict | None:
    """The feed read now (kept for the next start); what was kept when it cannot be read."""
    try:
        text = fetch_feed()
        feed = parse(text)
    except (OSError, ValueError):
        return kept()
    try:
        _cache_path().parent.mkdir(parents=True, exist_ok=True)
        _cache_path().write_text(text, encoding="utf-8")
    except OSError:
        pass
    return feed


# -- installing --------------------------------------------------------------------------------------------

def how_installed() -> str:
    """'setup' — the Windows installer's build; 'deb' — the Linux package; '' — anything else (from the source)."""
    if platform_key() == "windows":
        return "setup" if getattr(sys, "frozen", False) else ""
    if not shutil.which("dpkg-query"):
        return ""
    try:
        done = subprocess.run(["dpkg-query", "-W", "-f=${Status}", PACKAGE], capture_output=True, text=True,
                              timeout=10, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    return "deb" if done.returncode == 0 and "install ok installed" in done.stdout else ""


def download(feed: dict, progress: Callable[[int, int], None], cancel: threading.Event,
             folder: Path | None = None) -> Path:
    """This system's file of the feed into the app's data folder, its SHA-256 checked. A file already there and
    whole is not fetched again."""
    item = feed.get(platform_key())
    if not item:
        raise UpdateError(f"The update has no file for this system yet: {feed.get('page') or PAGE_URL}")
    url, want = str(item["url"]), str(item["sha256"]).lower()
    if not allowed(url):
        raise UpdateError("The update's file is not on the app's website: not downloaded.")
    folder = folder or store.data_dir() / "updates"
    folder.mkdir(parents=True, exist_ok=True)
    name = os.path.basename(urlsplit(url).path) or "update"
    path = folder / name
    if path.exists() and _sha256(path) == want:
        return path
    part = path.with_name(name + ".part")
    h, done = hashlib.sha256(), 0
    try:
        with web.open_url(url, timeout=TIMEOUT_S) as r, open(part, "wb") as out:
            total = int(r.headers.get("Content-Length") or item.get("size") or 0)
            while True:
                if cancel.is_set():
                    raise UpdateError("Cancelled.")
                block = r.read(1 << 20)
                if not block:
                    break
                out.write(block)
                h.update(block)
                done += len(block)
                progress(done, total)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    if h.hexdigest() != want:
        part.unlink(missing_ok=True)
        raise UpdateError("The downloaded file is not the one the update names (its SHA-256 differs): not "
                          "installed. Try again later.")
    os.replace(part, path)
    return path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def start_setup(path: Path) -> None:
    """Windows: the setup program, on its own — it stops this app, replaces it and offers to start it again."""
    subprocess.Popen([str(path), "/SP-"], close_fds=True, **detached())


def install_deb(path: Path) -> None:
    """Linux: the package installed through the system (pkexec asks for the password in its own window)."""
    done = subprocess.run(["pkexec", "apt-get", "install", "-y", str(path)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=1800)
    if done.returncode in (126, 127):
        raise UpdateError("The system's password window was closed: nothing was installed.")
    if done.returncode:
        raise UpdateError((done.stderr or done.stdout).strip()[-400:] or f"apt-get failed ({done.returncode}).")


def detached() -> dict:
    """A program that outlives this app (the setup program stops it)."""
    if procs.WINDOWS:
        return {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def restart_command() -> list[str]:
    """How this app starts again after its package was replaced."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, str(Path(__file__).resolve().parents[2] / "bin" / "launch.py")]


def now() -> float:
    return time.time()
