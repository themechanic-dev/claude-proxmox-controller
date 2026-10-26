"""The built-in console: a VM's or container's screen in a window of the app, through Proxmox's VNC websocket and the
app's API token — no browser and no web login. Keys go to the guest as physical keys where QEMU allows it, so the
keyboard layout of this computer does not get in the way.

Paste… (the user's idea, 26/10) types text into the guest key by key, as the app types its own commands — where
nothing else reaches: an installer, a login, a terminal without the guest agent. Ctrl+Shift+V types one copied line
at once; more than one line opens Paste… first."""

from __future__ import annotations

import sys
import threading
from typing import Callable

from PySide6.QtCore import QObject, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (QColor, QCursor, QFontDatabase, QGuiApplication, QImage, QPainter, QPixmap, QTextCharFormat,
                           QTextCursor)
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QHBoxLayout, QPlainTextEdit, QProgressBar, QTextEdit,
                               QVBoxLayout, QWidget)

from ..core import screen
from ..core.rfb import RfbClient, qnum_from_evdev, qnum_from_windows
from .widgets import DialogHead, button, label


def _v(x) -> int:
    return x.value if hasattr(x, "value") else int(x)


K = Qt.Key
KEYSYMS = {_v(k): sym for k, sym in (
    (K.Key_Backspace, 0xFF08), (K.Key_Tab, 0xFF09), (K.Key_Backtab, 0xFF09), (K.Key_Return, 0xFF0D),
    (K.Key_Enter, 0xFF8D), (K.Key_Escape, 0xFF1B), (K.Key_Delete, 0xFFFF), (K.Key_Home, 0xFF50),
    (K.Key_Left, 0xFF51), (K.Key_Up, 0xFF52), (K.Key_Right, 0xFF53), (K.Key_Down, 0xFF54), (K.Key_PageUp, 0xFF55),
    (K.Key_PageDown, 0xFF56), (K.Key_End, 0xFF57), (K.Key_Insert, 0xFF63), (K.Key_Shift, 0xFFE1),
    (K.Key_Control, 0xFFE3), (K.Key_Meta, 0xFFEB), (K.Key_Alt, 0xFFE9), (K.Key_AltGr, 0xFE03),
    (K.Key_CapsLock, 0xFFE5), (K.Key_NumLock, 0xFF7F), (K.Key_ScrollLock, 0xFF14), (K.Key_Print, 0xFF61),
    (K.Key_Pause, 0xFF13), (K.Key_Menu, 0xFF67), (K.Key_Super_L, 0xFFEB), (K.Key_Super_R, 0xFFEC),
    (K.Key_Space, 0x20))}
F1, F35, KEY_A, KEY_Z = _v(K.Key_F1), _v(K.Key_F35), _v(K.Key_A), _v(K.Key_Z)
BUTTONS = {_v(Qt.MouseButton.LeftButton): 1, _v(Qt.MouseButton.MiddleButton): 2, _v(Qt.MouseButton.RightButton): 4}


def keysym_for(ev) -> int:
    """The X key symbol of a key event."""
    native = ev.nativeVirtualKey()
    if sys.platform.startswith("linux") and native:
        return native  # X11 and Wayland report the key symbol itself
    k = _v(ev.key())
    if k in KEYSYMS:
        return KEYSYMS[k]
    if F1 <= k <= F35:
        return 0xFFBE + (k - F1)
    text = ev.text()
    if text and text.isprintable():
        c = ord(text[0])
        return c if c < 0x100 else 0x1000000 | c
    if KEY_A <= k <= KEY_Z:  # with Ctrl held the text is a control character
        return ord("a") + (k - KEY_A)
    return k if 0x20 <= k < 0x7F else 0


def qnum_for(ev) -> int:
    """The physical key (QEMU key number), when the platform tells it."""
    code = ev.nativeScanCode()
    if not code:
        return 0
    if sys.platform.startswith("linux"):
        return qnum_from_evdev(code - 8)  # X11 and Wayland key codes are the Linux input codes + 8
    if sys.platform.startswith("win"):
        return qnum_from_windows(code)
    return 0


class ConsoleView(QWidget):
    """The guest's screen, scaled to fill the window (bigger or smaller, keeping its proportions), with the keyboard
    and mouse sent to it."""

    key_event = Signal(bool, int, int)       # down, keysym, qnum
    pointer_event = Signal(int, int, int)    # buttons, x, y
    paste_requested = Signal()               # Ctrl+Shift+V: the app's, not the guest's

    def __init__(self):
        super().__init__()
        self.fb = QImage()
        self.buttons = 0
        self.held: dict[int, tuple[int, int]] = {}  # Qt key → (keysym, qnum) of keys now down
        self.swallowed: set[int] = set()  # keys the app took for itself: their release is not the guest's either
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.ArrowCursor)  # until the guest sends its own pointer
        self.setMinimumSize(320, 200)

    def set_size(self, w: int, h: int) -> None:
        fb = QImage(max(1, w), max(1, h), QImage.Format.Format_RGB32)
        fb.fill(QColor(0, 0, 0))
        if not self.fb.isNull():
            p = QPainter(fb)
            p.drawImage(0, 0, self.fb)
            p.end()
        self.fb = fb
        self.update()

    def set_pointer(self, hot_x: int, hot_y: int, w: int, h: int, argb: bytes) -> None:
        """The guest's own mouse pointer becomes this window's pointer: one pointer, no lag, no second one drawn
        on top. A guest without a pointer (a text console) leaves the normal arrow."""
        if not w or not h:
            self.setCursor(Qt.CursorShape.ArrowCursor)
            return
        img = QImage(argb, w, h, w * 4, QImage.Format.Format_ARGB32_Premultiplied).copy()
        self.setCursor(QCursor(QPixmap.fromImage(img), min(hot_x, w - 1), min(hot_y, h - 1)))

    def apply(self, ops: list[tuple]) -> None:
        if self.fb.isNull():
            return
        p = QPainter(self.fb)
        for op in ops:
            if op[0] == "raw":
                _, x, y, w, h, data = op
                p.drawImage(x, y, QImage(data, w, h, w * 4, QImage.Format.Format_RGB32))
            elif op[0] == "copy":
                _, sx, sy, x, y, w, h = op
                p.drawImage(x, y, self.fb.copy(sx, sy, w, h))
        p.end()
        self.update()

    # -- geometry ----------------------------------------------------------------------------------

    def target(self) -> QRectF:
        if self.fb.isNull():
            return QRectF()
        scale = min(self.width() / self.fb.width(), self.height() / self.fb.height())
        w, h = self.fb.width() * scale, self.fb.height() * scale
        return QRectF((self.width() - w) / 2, (self.height() - h) / 2, w, h)

    def to_screen(self, pos) -> tuple[int, int]:
        t = self.target()
        if t.isEmpty():
            return 0, 0
        x = (pos.x() - t.x()) * self.fb.width() / t.width()
        y = (pos.y() - t.y()) * self.fb.height() / t.height()
        return int(min(max(x, 0), self.fb.width() - 1)), int(min(max(y, 0), self.fb.height() - 1))

    def paintEvent(self, ev) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(0, 0, 0))
        t = self.target()
        if not t.isEmpty():
            if t.width() != self.fb.width():  # smooth both ways: no jagged text when enlarged
                p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            p.drawImage(t, self.fb)
        p.end()

    # -- input -------------------------------------------------------------------------------------

    def event(self, ev) -> bool:
        # Tab and Shift+Tab belong to the guest, not to Qt's focus chain
        if ev.type() == ev.Type.KeyPress and _v(ev.key()) in (_v(K.Key_Tab), _v(K.Key_Backtab)):
            self.keyPressEvent(ev)
            return True
        return super().event(ev)

    def keyPressEvent(self, ev) -> None:
        mods = ev.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier |
                                 Qt.KeyboardModifier.AltModifier | Qt.KeyboardModifier.MetaModifier)
        if _v(ev.key()) == _v(K.Key_V) and mods == (Qt.KeyboardModifier.ControlModifier |
                                                    Qt.KeyboardModifier.ShiftModifier):
            self.swallowed.add(_v(ev.key()))
            if not ev.isAutoRepeat():
                self.paste_requested.emit()
            ev.accept()
            return
        sym, qnum = keysym_for(ev), qnum_for(ev)
        if sym or qnum:
            self.held[_v(ev.key())] = (sym, qnum)
            self.key_event.emit(True, sym, qnum)
        ev.accept()

    def keyReleaseEvent(self, ev) -> None:
        if ev.isAutoRepeat():  # the guest repeats a held key by itself
            ev.accept()
            return
        if _v(ev.key()) in self.swallowed:
            self.swallowed.discard(_v(ev.key()))
            ev.accept()
            return
        sym, qnum = self.held.pop(_v(ev.key()), (keysym_for(ev), qnum_for(ev)))
        if sym or qnum:
            self.key_event.emit(False, sym, qnum)
        ev.accept()

    def release_all(self) -> None:
        """Let go of every key still down (focus left the window): no stuck Ctrl or Alt in the guest."""
        for sym, qnum in list(self.held.values()):
            self.key_event.emit(False, sym, qnum)
        self.held.clear()

    def focusOutEvent(self, ev) -> None:
        self.release_all()
        super().focusOutEvent(ev)

    def _pointer(self, pos) -> None:
        x, y = self.to_screen(pos)
        self.pointer_event.emit(self.buttons, x, y)

    def mouseMoveEvent(self, ev) -> None:
        self._pointer(ev.position())

    def mousePressEvent(self, ev) -> None:
        self.buttons |= BUTTONS.get(_v(ev.button()), 0)
        self._pointer(ev.position())

    def mouseReleaseEvent(self, ev) -> None:
        self.buttons &= ~BUTTONS.get(_v(ev.button()), 0)
        self._pointer(ev.position())

    def wheelEvent(self, ev) -> None:
        dy = ev.angleDelta().y()
        if not dy:
            return
        x, y = self.to_screen(ev.position())
        wheel = 8 if dy > 0 else 16
        self.pointer_event.emit(self.buttons | wheel, x, y)
        self.pointer_event.emit(self.buttons, x, y)


class _Relay(QObject):
    """Carries what the reading thread receives to the window (signals cross threads safely)."""
    connected = Signal(object)
    updated = Signal(object)
    ended = Signal(str)
    finished = Signal(object)


class _Session:
    """One connection, worked by its own thread. It holds no widget on purpose: if the thread dropped a window's last
    reference, Qt would destroy the window on that thread and crash (it did, in the tests)."""

    def __init__(self, open_console: Callable[[], tuple]):
        self.open_console = open_console
        self.relay = _Relay()
        self.stopping = False
        self.ws = None
        self.client: RfbClient | None = None
        self.thread = threading.Thread(target=self.run, daemon=True, name="console")

    def run(self) -> None:
        relay, ws = self.relay, None
        try:
            ws, password = self.open_console()
            self.ws = ws
            if self.stopping:
                return
            client = RfbClient(ws, password)
            size = client.handshake()
            self.client = client
            self._emit(relay.connected, size)
            while not self.stopping:
                self._emit(relay.updated, client.next_update())
        except Exception as e:  # shown in the window, which offers Reconnect
            if not self.stopping:
                self._emit(relay.ended, str(e) or "The console was closed.")
        finally:
            if ws is not None:  # this connection is over either way (Reconnect opens a new one)
                ws.close()
            self._emit(relay.finished, self)

    def _emit(self, signal, *args) -> None:
        """A message to the window — unless the app is closing and its relay is gone already: then no one is left to
        tell, and the thread ends quietly (it printed "Signal source has been deleted" at every exit)."""
        try:
            signal.emit(*args)
        except RuntimeError:
            self.stopping = True

    def stop(self) -> None:
        self.stopping = True
        if self.ws is not None:
            self.ws.close()


class _Typing:
    """Text being typed into the guest by a thread of its own. Plain Python on purpose — the windows look at it with a
    timer, so the thread touches no Qt object."""

    def __init__(self, total: int):
        self.total, self.typed, self.error, self.ended = total, 0, "", False
        self.stop = threading.Event()

    def count(self, n: int) -> None:
        self.typed = n


def clipboard_text() -> str:
    """What this computer has copied."""
    return QGuiApplication.clipboard().text()


QUICK_MAX = 300  # Ctrl+Shift+V types at once one line up to this long; more opens Paste… (with its Stop)


class PasteDialog(QDialog):
    """Paste…: text typed into the guest key by key, as on a US keyboard. It opens with what this computer has copied,
    to be read and changed first; what a US keyboard has not (Greek, accents…) is marked and left out; Enter at the
    end only when ticked (a terminal would run it); a bar while it types, and Stop."""

    LOOK_MS = 50

    def __init__(self, win: "ConsoleWindow", text: str):
        from .theme import colors
        super().__init__(win)
        self.win, self.job = win, None
        self.setWindowTitle("Paste into the console")
        self.setWindowModality(Qt.WindowModality.WindowModal)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(12)
        lay.addWidget(DialogHead("clipboard", "Paste into the console", "Typed key by key, as on a US keyboard — no "
                                 "guest agent needed: an installer, a login, a terminal."))
        self.edit = QPlainTextEdit()
        self.edit.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.edit.setMinimumHeight(160)
        self.edit.setPlainText(text)
        lay.addWidget(self.edit, 1)
        self.info = label("", "caption", wrap=True)
        lay.addWidget(self.info)
        self.enter = QCheckBox("Press Enter at the end")
        self.enter.toggled.connect(self._look)
        lay.addWidget(self.enter)
        self.bar = QProgressBar()
        self.bar.hide()
        lay.addWidget(self.bar)
        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_btn = button("Cancel")
        self.cancel_btn.clicked.connect(self._cancel)
        self.type_btn = button("Type", "suggested")
        self.type_btn.clicked.connect(self.type_now)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.type_btn)
        lay.addLayout(row)
        self.bad_format = QTextCharFormat()
        bad = QColor(colors().danger)
        bad.setAlphaF(0.35)
        self.bad_format.setBackground(bad)
        self.timer = QTimer(self)
        self.timer.setInterval(self.LOOK_MS)
        self.timer.timeout.connect(self._progress)
        self.edit.textChanged.connect(self._look)
        self._look()
        self.resize(580, 440)

    def to_type(self) -> tuple[str, list[str]]:
        """What will be typed (without what cannot be, the line ends at its end, and Enter there only when ticked),
        and the characters left out."""
        text, bad = screen.typable(self.edit.toPlainText())
        text = "".join(c for c in text if c not in bad).rstrip("\n")
        if not text.strip():
            return "", bad  # (only spaces: nothing worth typing)
        return text + ("\n" if self.enter.isChecked() else ""), bad

    def _look(self) -> None:
        text, bad = self.to_type()
        lines = text.rstrip("\n").count("\n") + 1 if text else 0
        words = [f"{lines} line{'s' if lines != 1 else ''}, {len(text):,} characters — about "
                 f"{max(1, round(len(text) / 70))} s."] if text else ["Nothing to type."]
        if lines > 1:
            words.append("In a terminal each line runs as its Enter is typed.")
        if bad:
            words.append(f"Not on a US keyboard, left out (marked): {' '.join(bad[:16])}" +
                         (" …" if len(bad) > 16 else ""))
        self.info.setText(" ".join(words))
        marks, at = [], 0  # (Qt counts in UTF-16: an emoji is two)
        for c in self.edit.toPlainText():
            width = 2 if ord(c) > 0xFFFF else 1
            if c in bad and len(marks) < 2000:
                sel = QTextEdit.ExtraSelection()
                sel.cursor = QTextCursor(self.edit.document())
                sel.cursor.setPosition(at)
                sel.cursor.setPosition(at + width, QTextCursor.MoveMode.KeepAnchor)
                sel.format = self.bad_format
                marks.append(sel)
            at += width
        self.edit.setExtraSelections(marks)
        self.type_btn.setEnabled(bool(text) and self.job is None)

    def type_now(self) -> None:
        text, _bad = self.to_type()
        if not text or self.job is not None:
            return
        job = self.win.start_typing(text)
        if job is None:
            self.info.setText("⚠ The console is not connected (or is typing already).")
            return
        self.job = job
        self.edit.setReadOnly(True)
        self.enter.setEnabled(False)
        self.type_btn.setEnabled(False)
        self.cancel_btn.setText("Stop")
        self.bar.setRange(0, job.total)
        self.bar.setValue(0)
        self.bar.show()
        self.timer.start()

    def _progress(self) -> None:
        job = self.job
        if job is None:
            return
        self.bar.setValue(job.typed)
        if not job.ended:
            return
        self.timer.stop()
        if job.error or job.typed < job.total:
            self.job = None
            self.edit.setReadOnly(False)
            self.enter.setEnabled(True)
            self.cancel_btn.setText("Close")
            self._look()
            self.info.setText(f"⚠ {job.error}" if job.error else
                              f"Stopped after {job.typed:,} of {job.total:,} characters.")
            return
        self.accept()  # all typed: back to the console
        self.win.view.setFocus()

    def _cancel(self) -> None:
        if self.job is not None and not self.job.ended:
            self.job.stop.set()
        else:
            self.reject()

    def done(self, result: int) -> None:
        if self.job is not None and not self.job.ended:
            self.job.stop.set()  # (closed while typing: it stops)
        self.timer.stop()
        super().done(result)


_RUNNING: set[_Session] = set()  # sessions whose thread may still run; let go of on the GUI thread only


def _reap(session: _Session) -> None:
    """On the GUI thread, once a session's thread has finished: only now may its relay be destroyed."""
    session.thread.join(timeout=2)
    _RUNNING.discard(session)


OPEN: dict[str, "ConsoleWindow"] = {}  # key → open window, so a second click raises it instead of a new one


class ConsoleWindow(QWidget):
    def __init__(self, key: str, title: str, open_console: Callable[[], tuple]):
        super().__init__(None, Qt.WindowType.Window)
        self.key, self.open_console = key, open_console
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(title)
        self.session: _Session | None = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        bar = QWidget()
        bar.setObjectName("consoleBar")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(8, 6, 8, 6)
        bl.setSpacing(6)
        self.cad_btn = button("Ctrl+Alt+Del", tooltip="Send Ctrl+Alt+Delete to the guest")
        self.cad_btn.clicked.connect(self.ctrl_alt_del)
        self.paste_btn = button("Paste…", tooltip="Type text into the guest key by key — Ctrl+Shift+V in the console "
                                                  "types one copied line")
        self.paste_btn.clicked.connect(lambda: self.paste())
        self.full_btn = button("Full Screen")
        self.full_btn.setCheckable(True)
        self.full_btn.toggled.connect(self._full_screen)
        self.status = label("Connecting…", "dim")
        self.reconnect_btn = button("Reconnect", "suggested")
        self.reconnect_btn.clicked.connect(self.connect_now)
        self.reconnect_btn.hide()
        for w in (self.cad_btn, self.paste_btn, self.full_btn):
            bl.addWidget(w)
        bl.addStretch(1)
        bl.addWidget(self.status)
        bl.addWidget(self.reconnect_btn)
        lay.addWidget(bar)
        self.view = ConsoleView()
        lay.addWidget(self.view, 1)
        self.view.key_event.connect(self._key)
        self.view.pointer_event.connect(self._pointer)
        self.view.paste_requested.connect(self.quick_paste)
        self.job: _Typing | None = None  # text being typed into the guest (Paste…)
        self.paste_dialog: PasteDialog | None = None
        self.job_timer = QTimer(self)
        self.job_timer.setInterval(PasteDialog.LOOK_MS)
        self.job_timer.timeout.connect(self._job_look)
        self.resize(820, 520)
        OPEN[key] = self
        self.connect_now()

    @property
    def client(self) -> RfbClient | None:
        return self.session.client if self.session is not None else None

    # -- the connection ----------------------------------------------------------------------------

    def connect_now(self) -> None:
        if self.session is not None:
            self.session.stop()
        self.status.setText("Connecting…")
        self.reconnect_btn.hide()
        session = _Session(self.open_console)  # a fresh relay too: a late message of the old one cannot interfere
        session.relay.connected.connect(self._connected)
        session.relay.updated.connect(self._updated)
        session.relay.ended.connect(self._ended)
        session.relay.finished.connect(_reap)
        _RUNNING.add(session)
        self.session = session
        session.thread.start()

    def _connected(self, info) -> None:
        w, h, _name = info
        self.view.set_size(w, h)
        self.status.setText("Connected")
        self._fit_window(w, h)
        self.view.setFocus()

    def _updated(self, ops: list) -> None:
        for op in ops:
            if op[0] == "size":
                self.view.set_size(op[1], op[2])
                self._fit_window(op[1], op[2])
            elif op[0] == "cursor":
                self.view.set_pointer(*op[1:])
            elif op[0] == "bell":
                QApplication.beep()
        self.view.apply([op for op in ops if op[0] in ("raw", "copy")])

    def _ended(self, reason: str) -> None:
        self.view.held.clear()
        self.status.setText(f"Disconnected — {reason}")
        self.reconnect_btn.show()

    def _fit_window(self, w: int, h: int) -> None:
        """Make the window the size of the guest's screen, within the monitor (only while the user has not
        maximised it or gone full screen)."""
        if self.isMaximized() or self.isFullScreen():
            return
        screen = (self.screen() or QGuiApplication.primaryScreen()).availableGeometry()
        bar = self.layout().itemAt(0).widget().sizeHint().height()
        self.resize(min(w, int(screen.width() * 0.95)), min(h + bar, int(screen.height() * 0.95)))

    # -- input ---------------------------------------------------------------------------------------

    def _key(self, down: bool, keysym: int, qnum: int) -> None:
        if self.typing():
            return  # (the user's keys would mix into the typed text)
        client = self.client
        if client is not None:
            try:
                client.key(down, keysym, qnum)
            except OSError:
                pass

    def _pointer(self, buttons: int, x: int, y: int) -> None:
        client = self.client
        if client is not None:
            try:
                client.pointer(buttons, x, y)
            except OSError:
                pass

    def ctrl_alt_del(self) -> None:
        client = self.client
        if client is not None:
            try:
                client.ctrl_alt_del()
            except OSError:
                pass
        self.view.setFocus()

    # -- Paste… -----------------------------------------------------------------------------------

    def typing(self) -> bool:
        return self.job is not None and not self.job.ended

    def start_typing(self, text: str) -> _Typing | None:
        """`text` typed into the guest by a thread (screen.type_keys); None when not connected or already typing."""
        client = self.client
        if client is None or self.typing() or not text:
            return None
        self.view.release_all()  # (no Ctrl or Shift left down in the guest under the typed keys)
        job = _Typing(len(text))

        def run():
            try:
                screen.type_keys(lambda down, sym: client.key(down, sym), text, job.stop, job.count)
            except OSError as e:
                job.error = f"The console's connection dropped ({e})." if str(e) else "The console's connection dropped."
            finally:
                job.ended = True

        self.job = job
        self.status.setText("Typing…")
        threading.Thread(target=run, daemon=True, name="paste").start()
        self.job_timer.start()
        return job

    def _job_look(self) -> None:
        job = self.job
        if job is None or not job.ended:
            return
        self.job_timer.stop()
        if self.status.text() == "Typing…":
            self.status.setText(f"Typing stopped — {job.error}" if job.error else "Connected")

    def paste(self, text: str | None = None) -> PasteDialog:
        """Paste…, with what this computer has copied (or `text`)."""
        dlg = PasteDialog(self, clipboard_text() if text is None else text)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.show()
        self.paste_dialog = dlg
        return dlg

    def quick_paste(self) -> None:
        """Ctrl+Shift+V: one copied line typed at once (no Enter); more, or what a US keyboard has not, in Paste…"""
        copied = clipboard_text()
        text, bad = screen.typable(copied)
        line = text.rstrip("\n")
        if not line.strip():
            self.status.setText("Nothing copied to paste.")
        elif "\n" in line or bad or len(line) > QUICK_MAX:
            self.paste(copied)
        elif self.start_typing(line) is None:
            self.status.setText("Not connected — nothing typed.")

    def _full_screen(self, on: bool) -> None:
        self.showFullScreen() if on else self.showNormal()
        self.view.setFocus()

    def closeEvent(self, ev) -> None:
        if self.job is not None:
            self.job.stop.set()
        self.view.release_all()
        if OPEN.get(self.key) is self:
            del OPEN[self.key]
        if self.session is not None:
            self.session.stop()
        super().closeEvent(ev)


def show(key: str, title: str, open_console: Callable[[], tuple]) -> ConsoleWindow:
    """Open a console window, or bring back the one already open for this guest."""
    win = OPEN.get(key)
    if win is None:
        win = ConsoleWindow(key, title, open_console)
    win.show()
    win.raise_()
    win.activateWindow()
    return win


def close_all() -> None:
    for win in list(OPEN.values()):
        win.close()


__all__ = ["ConsoleWindow", "show", "close_all", "keysym_for", "qnum_for"]
