"""Windows reopen with the size and on the screen where they were closed. Kept in the settings (base64 of Qt's own
saveGeometry), one entry per window: "main", "wall/<host>", "graphs/<host>/<vmid>"."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QByteArray
from PySide6.QtWidgets import QWidget


def restore(window: QWidget, key: str, settings: dict | None) -> bool:
    data = ((settings or {}).get("geometry") or {}).get(key)
    if not data:
        return False
    return window.restoreGeometry(QByteArray.fromBase64(data.encode("ascii")))


def remember(window: QWidget, key: str, settings: dict | None, save: Callable[[], None] | None) -> None:
    if settings is None:
        return
    settings.setdefault("geometry", {})[key] = bytes(window.saveGeometry().toBase64()).decode("ascii")
    if save is not None:
        save()
