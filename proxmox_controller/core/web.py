"""HTTPS from the app to the internet — its update feed and files, Ubuntu's image index: who the app says it is, and
which certificates it trusts. (The Proxmox hosts are not reached this way: their certificates are pinned, core/pve.)

Both measured 27/10, on the way to an update installing itself:
- themechanic.store is behind Cloudflare, which refuses Python's own User-Agent (403, «error code: 1010»): 1.0.0
  could read neither the feed nor an update's file. The app says who it is.
- A fresh Windows 11 has about twenty root certificates, and the one the site's certificate chains to (GTS Root R4)
  is not among them (VM 103). Windows fetches a missing root when its own programs meet it (Edge, PowerShell); Python
  never does, so 1.0.1 there failed with CERTIFICATE_VERIFY_FAILED and saw no update. The app trusts Mozilla's list
  of roots as well as the system's: data/certs/roots.pem, Ubuntu's ca-certificates (/etc/ssl/certs/
  ca-certificates.crt), renewed with the app's versions."""

from __future__ import annotations

import ssl
import sys
import urllib.request
from functools import lru_cache
from pathlib import Path

from .. import VERSION

ROOTS = Path(__file__).resolve().parents[2] / "data" / "certs" / "roots.pem"
TIMEOUT_S = 10.0


def user_agent() -> str:
    return f"ProxmoxController/{VERSION} ({'Windows' if sys.platform.startswith('win') else 'Linux'})"


@lru_cache(maxsize=1)
def context() -> ssl.SSLContext:
    """The system's roots, and Mozilla's from the app's own copy."""
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(cafile=str(ROOTS))
    except (OSError, ssl.SSLError):
        pass  # (the copy missing or damaged: the system's roots alone, as before)
    return ctx


def open_url(url: str, method: str = "GET", timeout: float = TIMEOUT_S):
    return urllib.request.urlopen(urllib.request.Request(url, method=method, headers={"User-Agent": user_agent()}),
                                  timeout=timeout, context=context())
