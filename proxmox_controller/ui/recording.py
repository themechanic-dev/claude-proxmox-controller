"""Recording a guest's console from the app: Record and Stop Recording (the guest's Console menu, the console
window), and the status bar's red mark while one runs — Claude's (console_record) or the user's — with Stop.
The recording itself is core/recorder.py: nothing of it shows on this computer's screen, so the mark does."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QHBoxLayout, QLabel, QMenu, QToolButton, QWidget

from ..core import recorder, spice
from .widgets import error

SAVED_SHOWN_S = 20  # how long the bar keeps "Saved: …" with Show after a recording ends


def key_of(host_id: str, vmid) -> str:
    return f"{host_id}/{vmid}"


def recording(host_id: str, vmid) -> bool:
    return recorder.get(key_of(host_id, vmid)) is not None


def with_sound(host_id: str, vmid) -> bool:
    rec = recorder.get(key_of(host_id, vmid))
    return rec is not None and rec.sound


def toggle(parent: QWidget, host, make_client: Callable, runner, g: dict, notify: Callable[[str], None]) -> None:
    """Start recording the guest's console with the user's own token, or stop the recording that runs."""
    key = key_of(host.id, g["vmid"])
    if recorder.get(key) is not None:
        stop(parent, key, runner)
        return
    title = f"{g.get('name', '')} ({g['vmid']})"
    node, kind, vmid = g["node"], g["type"], g["vmid"]

    def job():
        pve = make_client(host)
        sound, note = None, ""
        if kind != "qemu":
            note = "a container has no sound: the picture only"
        elif spice.viewer_open(key):
            note = "remote-viewer (SPICE) is open on this VM, and SPICE takes one viewer: recording without sound"
        elif pve.has_spice(node, vmid):
            sound = lambda: pve.spice_config(node, vmid)  # noqa: E731
        else:
            note = "this VM has no SPICE sound card: the picture only"
        rec = recorder.Recording(key, title, recorder.file_for(g.get("name") or "", vmid),
                                 lambda: make_client(host).open_vnc(node, kind, vmid), sound, sound_note=note)
        return recorder.start(rec)

    def done(rec, err):
        if err is not None:
            error(parent, "Record Console", str(err))
            return
        notify(f"Recording the console of {title}" + ("" if rec.sound else " — the picture only") +
               ". Stop it from the red mark at the bottom of the window.")

    notify(f"Starting to record the console of {title}…")
    runner.run(job, done)


def stop(parent: QWidget | None, key: str, runner) -> None:
    """Finishes the recording (the video is completed in the background; the status bar says when it is saved)."""
    runner.run(lambda: recorder.stop(key),
               lambda _r, err: error(parent, "Record Console", str(err)) if err is not None else None)


class RecordingIndicator(QWidget):
    """The status bar's red mark: which guest is being recorded and for how long, and Stop. After a recording
    ends: where its video is, with Show."""

    def __init__(self, runner, notify: Callable[[str], None], parent: QWidget | None = None):
        super().__init__(parent)
        self.runner, self.notify = runner, notify
        self.saved: tuple[str, float] | None = None  # (file, when)
        self.seen, _ = recorder.news()  # its place in the news: only recordings that end from now on
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 4, 0)
        lay.setSpacing(6)
        self.dot = QLabel("●")
        self.dot.setStyleSheet("color: #e5484d;")
        self.text = QLabel()
        self.stop_btn = QToolButton()
        self.stop_btn.setText("Stop")
        self.stop_btn.setToolTip("Stop the recording: its video is finished and saved")
        self.stop_btn.clicked.connect(self._stop_clicked)
        self.show_btn = QToolButton()
        self.show_btn.setText("Show")
        self.show_btn.setToolTip("Open the folder of the recordings")
        self.show_btn.clicked.connect(self._show_folder)
        for w in (self.dot, self.text, self.stop_btn, self.show_btn):
            lay.addWidget(w)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.refresh()

    def refresh(self) -> None:
        self.seen, ended = recorder.news(self.seen)
        for _key, res in ended:
            self._ended(res)
        recs = recorder.active()
        if recs:
            first = recs[0]
            more = f" and {len(recs) - 1} more" if len(recs) > 1 else ""
            who = "Claude is recording" if first.by == "Claude" else "Recording"
            self.text.setText(f"{who} {first.title} · {first.status()['recording_for']}{more}")
            self.dot.show()
            self.stop_btn.show()
            self.show_btn.hide()
            if len(recs) > 1:
                menu = QMenu(self.stop_btn)
                for rec in recs:
                    menu.addAction(f"Stop {rec.title}").triggered.connect(
                        lambda _=False, k=rec.key: stop(self.window(), k, self.runner))
                self.stop_btn.setMenu(menu)
                self.stop_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            else:
                self.stop_btn.setMenu(None)
            self.show()
            return
        if self.saved is not None and time.monotonic() - self.saved[1] < SAVED_SHOWN_S:
            self.text.setText(f"Saved: {Path(self.saved[0]).name}")
            self.dot.hide()
            self.stop_btn.hide()
            self.show_btn.show()
            self.show()
            return
        self.hide()

    def _stop_clicked(self) -> None:
        recs = recorder.active()
        if len(recs) == 1:
            stop(self.window(), recs[0].key, self.runner)

    def _ended(self, res: dict) -> None:
        guest = res.get("guest", "")
        if res.get("error") or not res.get("bytes"):
            error(self.window(), "Record Console",
                  f"The recording of {guest} did not complete: {res.get('error') or res.get('ended')}")
            return
        self.saved = (res["file"], time.monotonic())
        ended = res.get("ended", "stopped")
        self.notify(f"Recording of {guest} saved ({res['seconds']:.0f} s): {res['file']}" +
                    ("" if ended == "stopped" else f" — it ended by itself: {ended}"))

    def _show_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(recorder.videos_folder())))
