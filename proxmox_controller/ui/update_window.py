"""A newer version, shown and installed (core/updates): the striped tab beside the ☰ button — warning tape, as Claude's
approval window wears, so it is seen (the user's choice, 26/10, from a mockup) — and the window its click opens: what
is new, and Install."""

from __future__ import annotations

import subprocess
import threading

from PySide6.QtCore import QRectF, Qt, QTimer, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QFontMetrics, QPainter, QPainterPath
from PySide6.QtWidgets import (QApplication, QDialog, QHBoxLayout, QProgressBar, QToolButton, QVBoxLayout,
                               QWidget)

from .. import APP_NAME, VERSION
from ..core import updates
from . import hazard
from .widgets import DialogHead, boxed, button, fit_to_width, label


def short_version(v: str) -> str:
    """'1.1.0' → '1.1' (the tab is small); '1.1.2' stays."""
    return v[:-2] if v.endswith(".0") and v.count(".") == 2 else v


class UpdateTab(QToolButton):
    """'Update 1.1' on yellow and black stripes, the words on a black label so they read."""

    def __init__(self):
        super().__init__()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(32)
        self.hide()

    def show_version(self, version: str) -> None:
        self.setText(f"Update {short_version(version)}")
        self.setToolTip(f"{APP_NAME} {version} is out — what's new, and Install")
        f = QFont(self.font())
        f.setBold(True)
        f.setPixelSize(12)
        self.setFixedWidth(QFontMetrics(f).horizontalAdvance(self.text()) + 44)

    def paintEvent(self, ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(r, 7, 7)
        p.setClipPath(path)
        hazard.paint_stripes(p, r, 7)
        p.setClipping(False)
        inner = r.adjusted(9, 6, -9, -6)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(hazard.BLACK if not self.underMouse() else QColor("#333333"))
        p.drawRoundedRect(inner, 5, 5)
        f = QFont(self.font())
        f.setBold(True)
        f.setPixelSize(12)
        p.setFont(f)
        p.setPen(hazard.YELLOW)
        p.drawText(inner, Qt.AlignmentFlag.AlignCenter, self.text())
        p.end()

    def enterEvent(self, ev) -> None:
        self.update()
        super().enterEvent(ev)

    def leaveEvent(self, ev) -> None:
        self.update()
        super().leaveEvent(ev)


class _Job:
    """The download and the hand-over, on a thread of their own; the window looks at it with a timer (no Qt object
    is touched by the thread)."""

    def __init__(self):
        self.done = self.total = 0
        self.stage, self.error, self.ended = "download", "", False
        self.cancel = threading.Event()


class UpdateDialog(QDialog):
    LOOK_MS = 100

    def __init__(self, parent: QWidget | None, feed: dict, how: str):
        super().__init__(parent)
        self.feed, self.how, self.job = feed, how, None
        version = feed["version"]
        self.setWindowTitle("Update")
        self.setModal(True)
        item = feed.get(updates.platform_key()) or {}
        mb = round(int(item.get("size") or 0) / 1_000_000)
        about = f" (about {mb} MB)" if mb else ""
        if not item:
            text = f"You have {VERSION}. The new version has no file for this system yet: see the download page."
        elif how == "setup":
            text = (f"You have {VERSION}. The update downloads{about}, is checked, and its setup starts — it closes "
                    "the app and offers to open it again.")
        elif how == "deb":
            text = (f"You have {VERSION}. The update downloads{about}, is checked, and is installed through the "
                    "system (it asks for your password) — then the app opens again.")
        else:
            text = (f"You have {VERSION}. This copy was not installed from the website's package, so it does not "
                    "update itself: get the new version from the download page.")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(12)
        lay.addWidget(DialogHead("archive", f"{APP_NAME} {version} is out", text))
        if feed.get("notes"):
            notes = QVBoxLayout()
            for line in feed["notes"][:12]:
                notes.addWidget(label(f"• {line}", "", wrap=True))
            lay.addWidget(label("What's new", "dim"))
            lay.addWidget(boxed(notes))
        self.bar = QProgressBar()
        self.bar.hide()
        lay.addWidget(self.bar)
        self.state = label("", "dim", wrap=True)
        self.state.hide()  # (until there is something to say: no gap above the buttons)
        lay.addWidget(self.state)
        row = QHBoxLayout()
        row.addStretch(1)
        self.later_btn = button("Later")
        self.later_btn.clicked.connect(self._later)
        row.addWidget(self.later_btn)
        self.can_install = bool(item) and how in ("setup", "deb")
        self.install_btn = button("Install" if self.can_install else "Download Page", "suggested")
        self.install_btn.clicked.connect(self.install if self.can_install else self.open_page)
        row.addWidget(self.install_btn)
        lay.addLayout(row)
        self.timer = QTimer(self)
        self.timer.setInterval(self.LOOK_MS)
        self.timer.timeout.connect(self._look)
        fit_to_width(self, 520)

    def open_page(self) -> None:
        QDesktopServices.openUrl(QUrl(self.feed.get("page") or updates.PAGE_URL))
        self.accept()

    def install(self) -> None:
        if self.job is not None:
            return
        job = self.job = _Job()
        feed, how = self.feed, self.how

        def run():
            try:
                path = updates.download(feed, lambda done, total: (setattr(job, "done", done),
                                                                   setattr(job, "total", total)), job.cancel)
                job.stage = "install"
                if how == "setup":
                    updates.start_setup(path)
                else:
                    updates.install_deb(path)
                job.stage = "done"
            except (OSError, updates.UpdateError, subprocess.SubprocessError) as e:
                job.error = str(e) or type(e).__name__
            finally:
                job.ended = True

        self.install_btn.setEnabled(False)
        self.later_btn.setText("Cancel")
        self.bar.setRange(0, 0)
        self.bar.show()
        self.state.setText("Downloading…")
        self.state.show()
        fit_to_width(self, 520)
        threading.Thread(target=run, daemon=True, name="update").start()
        self.timer.start()

    def _look(self) -> None:
        job = self.job
        if job is None:
            return
        if job.total:
            self.bar.setRange(0, 1000)
            self.bar.setValue(int(1000 * job.done / job.total))
        if job.stage == "install" and not job.ended:
            self.state.setText("Starting the setup…" if self.how == "setup" else
                               "Installing — the system asks for your password…")
            self.bar.setRange(0, 0)
        if not job.ended:
            return
        self.timer.stop()
        if job.error:
            self.job = None
            self.bar.hide()
            self.state.setText(f"⚠ {job.error}")
            self.install_btn.setEnabled(True)
            self.later_btn.setText("Later")
            return
        self.state.setText("Done — the app closes now and opens again.")
        if self.how == "deb":  # (on Windows the setup starts the new version)
            from PySide6.QtCore import QProcess
            cmd = updates.restart_command()
            QProcess.startDetached(cmd[0], cmd[1:])
        QTimer.singleShot(300, QApplication.quit)

    def _later(self) -> None:
        if self.job is not None and not self.job.ended:
            self.job.cancel.set()  # (between two blocks of the download; an install already handed over goes on)
            return
        self.reject()

    def done(self, result: int) -> None:
        if self.job is not None and not self.job.ended:
            self.job.cancel.set()
        self.timer.stop()
        super().done(result)
