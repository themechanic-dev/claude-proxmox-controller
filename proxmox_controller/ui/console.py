"""The built-in console: a VM's or container's screen in a window of the app, through Proxmox's VNC websocket and the
app's API token — no browser and no web login. Keys go to the guest as physical keys where QEMU allows it, so the
keyboard layout of this computer does not get in the way."""

from __future__ import annotations

import sys
import threading
from typing import Callable

from PySide6.QtCore import QObject, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QCursor, QGuiApplication, QImage, QPainter, QPixmap
from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget

from ..core.rfb import RfbClient, qnum_from_evdev, qnum_from_windows
from .widgets import button, label


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

    def __init__(self):
        super().__init__()
        self.fb = QImage()
        self.buttons = 0
        self.held: dict[int, tuple[int, int]] = {}  # Qt key → (keysym, qnum) of keys now down
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
        sym, qnum = keysym_for(ev), qnum_for(ev)
        if sym or qnum:
            self.held[_v(ev.key())] = (sym, qnum)
            self.key_event.emit(True, sym, qnum)
        ev.accept()

    def keyReleaseEvent(self, ev) -> None:
        if ev.isAutoRepeat():  # the guest repeats a held key by itself
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
            relay.connected.emit(size)
            while not self.stopping:
                relay.updated.emit(client.next_update())
        except Exception as e:  # shown in the window, which offers Reconnect
            if not self.stopping:
                relay.ended.emit(str(e) or "The console was closed.")
        finally:
            if ws is not None:  # this connection is over either way (Reconnect opens a new one)
                ws.close()
            relay.finished.emit(self)

    def stop(self) -> None:
        self.stopping = True
        if self.ws is not None:
            self.ws.close()


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
        self.full_btn = button("Full Screen")
        self.full_btn.setCheckable(True)
        self.full_btn.toggled.connect(self._full_screen)
        self.status = label("Connecting…", "dim")
        self.reconnect_btn = button("Reconnect", "suggested")
        self.reconnect_btn.clicked.connect(self.connect_now)
        self.reconnect_btn.hide()
        for w in (self.cad_btn, self.full_btn):
            bl.addWidget(w)
        bl.addStretch(1)
        bl.addWidget(self.status)
        bl.addWidget(self.reconnect_btn)
        lay.addWidget(bar)
        self.view = ConsoleView()
        lay.addWidget(self.view, 1)
        self.view.key_event.connect(self._key)
        self.view.pointer_event.connect(self._pointer)
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

    def _full_screen(self, on: bool) -> None:
        self.showFullScreen() if on else self.showNormal()
        self.view.setFocus()

    def closeEvent(self, ev) -> None:
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
