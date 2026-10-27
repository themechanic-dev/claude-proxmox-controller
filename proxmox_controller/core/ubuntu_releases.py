"""Which Ubuntu releases a ready-made VM can be (New VM, and Claude's get_cloud_image): every LTS from 24.04 on that
cloud-images.ubuntu.com has and that is still within its five years of standard support — read from Ubuntu's own
image index, so a new LTS (28.04, April 2028) shows by itself and an old one goes (24.04, after April 2029). The
user's choice, 26/10.

Measured 26/10: the index (index.json, 30 KB, 0.3 s) lists every release there has been (10.04 … 26.10) but not which
are supported (only the 18.7 MB product file says, too much to fetch) — for an LTS that is fixed: YY.04 with an even
YY, supported until the April five years on. An image's address takes the number (…/releases/24.04/… redirects to
noble), and its size is the answer to a HEAD request there (24.04: 621 MB, 26.04: 859 MB).

The index is read at most once a day (refresh(); New VM asks for it in the background), what it said is kept in the
app's data folder, and without the internet the last list known — or the one built in — is offered."""

from __future__ import annotations

import json
import re
import time
from datetime import date

from . import store, web

INDEX_URL = "https://cloud-images.ubuntu.com/releases/streams/v1/index.json"
IMAGES = "com.ubuntu.cloud:released:download"
PRODUCT = re.compile(r"com\.ubuntu\.cloud:server:(\d\d)\.(\d\d):amd64$")
OLDEST = "24.04"  # the oldest the app's ready-made VMs are made and tested for (the Desktop's Remote Desktop, 26/10)
SUPPORT_YEARS = 5
BUILT_IN = ("24.04", "26.04")  # what the app knew when it was made: offered until the index has been read
CHECK_EVERY_S = 24 * 3600
TIMEOUT_S = 5.0


def is_lts(v: str) -> bool:
    m = re.fullmatch(r"(\d\d)\.(\d\d)", v)
    return bool(m) and m.group(2) == "04" and int(m.group(1)) % 2 == 0


def supported(v: str, today: date | None = None) -> bool:
    """Within an LTS's five years of standard support: until the end of April, five years on."""
    today = today or date.today()
    return (today.year, today.month) <= (2000 + int(v[:2]) + SUPPORT_YEARS, 4)


def offered(versions, today: date | None = None) -> list[str]:
    """The LTS releases from OLDEST on that are still supported, oldest first (as the list always was)."""
    keep = {v for v in versions if is_lts(v) and v >= OLDEST and supported(v, today)}
    return sorted(keep)


def versions_in(index: dict) -> list[str]:
    """Every server release for amd64 that Ubuntu's image index names."""
    products = ((index.get("index") or {}).get(IMAGES) or {}).get("products") or []
    return sorted({f"{m.group(1)}.{m.group(2)}" for p in products if (m := PRODUCT.match(str(p)))})


def fetch_index() -> dict:
    with web.open_url(INDEX_URL, timeout=TIMEOUT_S) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_size_mb(url: str) -> int | None:
    """An image's size, from the server's answer to a HEAD request (redirects followed)."""
    with web.open_url(url, method="HEAD", timeout=TIMEOUT_S) as r:
        n = r.headers.get("Content-Length")
    return round(int(n) / 1_000_000) if n and n.isdigit() else None


def _cache_path():
    return store.data_dir() / "ubuntu-releases.json"


def _cached() -> dict:
    try:
        data = json.loads(_cache_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def releases(today: date | None = None) -> list[str]:
    """What is offered now, without asking the network: the list last read, or the one built in."""
    known = _cached().get("versions") or list(BUILT_IN)
    return offered(known, today) or offered(BUILT_IN, today) or list(BUILT_IN)


def size_mb(v: str) -> int | None:
    from .cloudvm import CLOUD_IMAGES
    return CLOUD_IMAGES.get(v) or (_cached().get("sizes") or {}).get(v)


def refresh(now: float | None = None, today: date | None = None) -> list[str]:
    """The index read again when the last reading is a day old (the sizes of releases the app does not know asked
    for too), then releases(). Without the internet: what was known."""
    from .cloudvm import CLOUD_IMAGES, CLOUD_URL
    now = time.time() if now is None else now
    data = _cached()
    checked = data.get("checked")
    if checked is None or now - float(checked) >= CHECK_EVERY_S:  # (never read: read now)
        try:
            versions = versions_in(fetch_index())
        except (OSError, ValueError):
            versions = []
        if versions:
            sizes = dict(data.get("sizes") or {})
            for v in offered(versions, today):
                if v not in CLOUD_IMAGES and v not in sizes:
                    try:
                        mb = fetch_size_mb(CLOUD_URL.format(v=v))
                    except (OSError, ValueError):
                        mb = None
                    if mb:
                        sizes[v] = mb
            data = {"checked": now, "versions": versions, "sizes": sizes}
            try:
                _cache_path().parent.mkdir(parents=True, exist_ok=True)
                _cache_path().write_text(json.dumps(data), encoding="utf-8")
            except OSError:
                pass
    return releases(today)
