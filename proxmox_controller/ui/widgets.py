"""Small building blocks shared by the pages and dialogs."""

from __future__ import annotations

from PySide6.QtCore import QPoint, QRect, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel, QLayout, QLayoutItem,
                               QMessageBox, QProgressBar, QPushButton, QVBoxLayout, QWidget)

from .theme import refresh_widget_style


class FlowLayout(QLayout):
    """Its items side by side, as far as the width goes, and on in another row below — as many rows as the window's
    width needs, laid out again as it is resized (height-for-width, which the page's scroll area honours). An item
    is never split: a group of buttons in one widget moves down whole."""

    def __init__(self, parent: QWidget | None = None, spacing: int = 6):
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self._gap = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item: QLayoutItem) -> None:
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self) -> Qt.Orientation:
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._place(QRect(0, 0, width, 0), move=False)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._place(rect, move=True)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        m = self.contentsMargins()
        return size + QSize(m.left() + m.right(), m.top() + m.bottom())

    def rows(self) -> int:
        """How many rows it uses now (for the tests)."""
        tops = {item.geometry().top() for item in self._items if not item.isEmpty()}
        return len(tops)

    def _place(self, rect: QRect, move: bool) -> int:
        m = self.contentsMargins()
        area = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        x, y, line = area.x(), area.y(), 0
        for item in self._items:
            if item.isEmpty():  # hidden
                continue
            hint = item.sizeHint()
            if x + hint.width() > area.right() + 1 and line:  # does not fit after the last one: another row
                x, y, line = area.x(), y + line + self._gap, 0
            if move:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self._gap
            line = max(line, hint.height())
        return y + line - rect.y() + m.bottom()


def label(text: str = "", name: str = "", wrap: bool = False, selectable: bool = False) -> QLabel:
    lbl = QLabel(text)
    if name:
        lbl.setObjectName(name)
    lbl.setWordWrap(wrap)
    if selectable:
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lbl


def dot_icon(color: str) -> QIcon:
    """A small filled circle. The same picture is given for the selected state, so a selected row's dot keeps its
    colour (Qt otherwise tints it, and a running guest's green dot looked grey on the blue selection)."""
    pm = QPixmap(QSize(32, 32))  # a 16-point icon drawn at twice the size: sharp on high-density screens
    pm.setDevicePixelRatio(2.0)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawEllipse(3, 3, 10, 10)  # a 10-point dot in the middle, whatever icon size the list asks for
    p.end()
    icon = QIcon()
    for mode in (QIcon.Mode.Normal, QIcon.Mode.Selected, QIcon.Mode.Active):
        icon.addPixmap(pm, mode)
    return icon


def power_icon(color: str) -> QIcon:
    """The power symbol (a circle open at the top with a stroke through the gap): 'starts at boot'."""
    from PySide6.QtCore import QRectF
    from PySide6.QtGui import QPen
    pm = QPixmap(QSize(32, 32))
    pm.setDevicePixelRatio(2.0)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), 1.7)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.drawArc(QRectF(3, 3.5, 10, 10), 125 * 16, 290 * 16)  # Qt counts sixteenths of a degree, anticlockwise
    p.drawLine(8, 2, 8, 8)
    p.end()
    icon = QIcon()
    for mode in (QIcon.Mode.Normal, QIcon.Mode.Selected, QIcon.Mode.Active):
        icon.addPixmap(pm, mode)
    return icon


def lock_icon(color: str) -> QIcon:
    """A small padlock: 'protected'."""
    from PySide6.QtCore import QRectF
    from PySide6.QtGui import QPen
    pm = QPixmap(QSize(32, 32))
    pm.setDevicePixelRatio(2.0)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), 1.6)
    p.setPen(pen)
    p.drawArc(QRectF(5, 2.5, 6, 7), 0, 180 * 16)  # the shackle
    p.drawLine(5, 6, 5, 7.5)
    p.drawLine(11, 6, 11, 7.5)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawRoundedRect(QRectF(3.5, 7.5, 9, 6.5), 1.5, 1.5)  # the body
    p.end()
    icon = QIcon()
    for mode in (QIcon.Mode.Normal, QIcon.Mode.Selected, QIcon.Mode.Active):
        icon.addPixmap(pm, mode)
    return icon


class ElidedLabel(QLabel):
    """A one-line label that ends in "…" when there is not room for all of it (all of it then in its tooltip). It
    asks for its whole width but gives way first, so a long host name never pushes the buttons beside it off."""

    def __init__(self, text: str = "", name: str = "", minimum: int = 60):
        super().__init__(text)
        self.full = text
        self.minimum = minimum
        if name:
            self.setObjectName(name)

    def setText(self, text: str) -> None:  # noqa: N802 (Qt's name)
        self.full = text
        self._elide()
        self.updateGeometry()

    def sizeHint(self) -> QSize:  # noqa: N802
        hint = super().sizeHint()
        return QSize(self.fontMetrics().horizontalAdvance(self.full) + 6, hint.height())

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return QSize(self.minimum, super().minimumSizeHint().height())

    def resizeEvent(self, ev) -> None:  # noqa: N802
        super().resizeEvent(ev)
        self._elide()

    def _elide(self) -> None:
        shown = self.fontMetrics().elidedText(self.full, Qt.TextElideMode.ElideRight, max(self.width(), 1))
        super().setText(shown)
        self.setToolTip(self.full if shown != self.full else "")


def button(text: str, kind: str = "", tooltip: str = "") -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setProperty("kind", kind)
    if tooltip:
        b.setToolTip(tooltip)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def card(*widgets: QWidget, spacing: int = 8, margins: int = 14) -> QFrame:
    frame = QFrame()
    frame.setObjectName("card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(margins, margins, margins, margins)
    lay.setSpacing(spacing)
    for w in widgets:
        lay.addWidget(w)
    return frame


class Pill(QLabel):
    """A rounded state label: online / offline / unknown / error."""

    def __init__(self, text: str = "", state: str = "unknown"):
        super().__init__(text)
        self.setProperty("pill", True)
        self.set(text, state)

    def set(self, text: str, state: str) -> None:
        self.setText(text)
        self.setProperty("state", state)
        refresh_widget_style(self)


class StatCard(QFrame):
    """A number with a bar under it: CPU, memory, disk."""

    def __init__(self, title: str, elide: bool = False):
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(4)
        self.title = ElidedLabel(title, "dim") if elide else label(title, "dim")  # elide: a long name ends in …
        lay.addWidget(self.title)
        self.value = label("—", "big")
        lay.addWidget(self.value)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1000)
        self.bar.setFixedHeight(8)
        lay.addWidget(self.bar)
        self.caption = label("", "caption", wrap=True)
        lay.addWidget(self.caption)
        lay.addStretch(1)  # cards in a row share a height: keep every title at the top

    def show_fraction(self, value_text: str, fraction: float | None, caption: str = "") -> None:
        self.value.setText(value_text)
        self.caption.setText(caption)
        self.bar.setVisible(fraction is not None)
        if fraction is not None:
            self.bar.setValue(int(max(0.0, min(1.0, fraction)) * 1000))
            level = "critical" if fraction >= 0.9 else "warning" if fraction >= 0.75 else ""
            self.bar.setProperty("level", level)
            refresh_widget_style(self.bar)

    def clear(self) -> None:
        self.show_fraction("—", None, "")


def row(*widgets: QWidget, spacing: int = 8, stretch_after: int | None = None) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setSpacing(spacing)
    for i, w in enumerate(widgets):
        lay.addWidget(w)
        if stretch_after is not None and i == stretch_after:
            lay.addStretch(1)
    return lay


def badge(glyph: str, color: str, size: int = 40) -> QPixmap:
    """A round badge for a window's head: `glyph` drawn in `color` on a pale disc of the same colour — stop, power,
    reboot, trash, host, warning, question; folder, agent, edit, notes, camera, archive, chart."""
    from PySide6.QtCore import QPointF, QRectF
    from PySide6.QtGui import QFont, QPen, QPolygonF
    pm = QPixmap(QSize(size * 2, size * 2))
    pm.setDevicePixelRatio(2.0)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 40, size / 40)  # drawn on a 40-point grid
    col = QColor(color)
    disc = QColor(col)
    disc.setAlphaF(0.18)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(disc)
    p.drawEllipse(QRectF(0, 0, 40, 40))
    pen = QPen(col, 2.2)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    if glyph == "stop":
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(col)
        p.drawRoundedRect(QRectF(14, 14, 12, 12), 2.5, 2.5)
    elif glyph == "power":
        p.drawArc(QRectF(12, 13, 16, 16), 125 * 16, 290 * 16)
        p.drawLine(QPointF(20, 10.5), QPointF(20, 19))
    elif glyph == "reboot":
        p.drawArc(QRectF(12, 12, 16, 16), 70 * 16, 290 * 16)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(col)
        p.drawPolygon(QPolygonF([QPointF(21, 8.5), QPointF(26.5, 12.5), QPointF(20.5, 15.5)]))
    elif glyph == "trash":
        p.drawLine(QPointF(12, 14), QPointF(28, 14))
        p.drawPolyline(QPolygonF([QPointF(17.5, 14), QPointF(17.5, 11.5), QPointF(22.5, 11.5), QPointF(22.5, 14)]))
        p.drawPolygon(QPolygonF([QPointF(14, 16), QPointF(15.5, 28.5), QPointF(24.5, 28.5), QPointF(26, 16)]))
        p.drawLine(QPointF(18.5, 19), QPointF(18.5, 25.5))
        p.drawLine(QPointF(21.5, 19), QPointF(21.5, 25.5))
    elif glyph == "host":
        for top in (12, 21):
            p.drawRoundedRect(QRectF(12, top, 16, 7), 2, 2)
            p.drawPoint(QPointF(16, top + 3.5))
    elif glyph == "folder":
        p.drawPolygon(QPolygonF([QPointF(11, 13), QPointF(17, 13), QPointF(19.5, 15.5), QPointF(29, 15.5),
                                 QPointF(29, 27), QPointF(11, 27)]))
    elif glyph == "agent":  # a chip with its pins
        p.drawRoundedRect(QRectF(14, 14, 12, 12), 2, 2)
        for k in (17, 20, 23):
            p.drawLine(QPointF(k, 10.5), QPointF(k, 14))
            p.drawLine(QPointF(k, 26), QPointF(k, 29.5))
            p.drawLine(QPointF(10.5, k), QPointF(14, k))
            p.drawLine(QPointF(26, k), QPointF(29.5, k))
    elif glyph == "edit":  # three sliders
        for y, knob in ((14, 16), (20, 24), (26, 19)):
            p.drawLine(QPointF(11, y), QPointF(29, y))
            p.setBrush(col)
            p.drawEllipse(QPointF(knob, y), 2.2, 2.2)
            p.setBrush(Qt.BrushStyle.NoBrush)
    elif glyph == "notes":
        p.drawRoundedRect(QRectF(13, 10.5, 14, 19), 2, 2)
        for y in (15.5, 19.5, 23.5):
            p.drawLine(QPointF(16.5, y), QPointF(23.5 if y < 23 else 20.5, y))
    elif glyph == "camera":
        p.drawRoundedRect(QRectF(10.5, 15, 19, 13), 2.5, 2.5)
        p.drawPolyline(QPolygonF([QPointF(15.5, 15), QPointF(17, 12.5), QPointF(23, 12.5), QPointF(24.5, 15)]))
        p.drawEllipse(QPointF(20, 21.5), 3.6, 3.6)
    elif glyph == "archive":
        p.drawRoundedRect(QRectF(11, 12, 18, 5), 1.5, 1.5)
        p.drawPolyline(QPolygonF([QPointF(12.5, 17), QPointF(12.5, 28), QPointF(27.5, 28), QPointF(27.5, 17)]))
        p.drawLine(QPointF(17.5, 21), QPointF(22.5, 21))
    elif glyph == "chart":
        p.drawPolyline(QPolygonF([QPointF(11, 26), QPointF(16, 19.5), QPointF(20.5, 23), QPointF(28.5, 13)]))
        p.drawLine(QPointF(11, 29), QPointF(29, 29))
    elif glyph == "warning":
        p.drawPolygon(QPolygonF([QPointF(20, 10.5), QPointF(29.5, 27.5), QPointF(10.5, 27.5)]))
        p.drawLine(QPointF(20, 16.5), QPointF(20, 21.5))
        p.drawPoint(QPointF(20, 24.5))
    else:  # a question
        font = QFont(p.font())
        font.setPixelSize(20)
        font.setBold(True)
        p.setFont(font)
        p.drawText(QRectF(0, 0, 40, 40), Qt.AlignmentFlag.AlignCenter, "?")
    p.end()
    return pm


def guest_line(g: dict) -> str:
    """"VM 108 · running · pve · 192.168.1.50": a guest in one line, as its card shows it under the name."""
    kind = "VM" if g.get("type") == "qemu" else "Container"
    parts = [f"{kind} {g.get('vmid', '')}", str(g.get("status", "") or ""), str(g.get("node", "") or "")]
    parts += [ip for ip in (g.get("ips") or [])[:1]]
    return " · ".join(x for x in parts if x)


def guest_card(g: dict) -> QFrame:
    """A guest as a question's window shows it: its status dot, its name, and "VM 108 · running · pve ·
    192.168.1.50" (g: a guest of the list, with "ips" where the app knows them)."""
    from .theme import colors
    c = colors()
    frame = QFrame()
    frame.setObjectName("guestCard")
    lay = QHBoxLayout(frame)
    lay.setContentsMargins(12, 10, 12, 10)
    lay.setSpacing(10)
    running = g.get("status") == "running"
    dot = QLabel()
    dot.setPixmap(dot_icon(c.success if running else c.dim).pixmap(16, 16))
    lay.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
    words = QVBoxLayout()
    words.setSpacing(0)
    words.addWidget(label(f"<b>{g.get('name', '') or '—'}</b>"))
    words.addWidget(label(guest_line(g), "dim"))
    lay.addLayout(words, 1)
    return frame


class DialogHead(QWidget):
    """A window's head, the same in every window of a guest and every question: a round badge, the title in bold and
    a line under it (dim). `title` and `text` are the labels, for a window that changes them later."""

    def __init__(self, icon: str, title: str, text: str = "", color: str = ""):
        from .theme import colors
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        self.badge = QLabel()
        self.badge.setPixmap(badge(icon, color or colors().accent))
        lay.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignTop)
        words = QVBoxLayout()
        words.setSpacing(4)
        self.title = label(title, "confirmTitle", wrap=True)
        words.addWidget(self.title)
        self.text = label(text, "dim", wrap=True)
        self.text.setVisible(bool(text))
        words.addWidget(self.text)
        lay.addLayout(words, 1)


def boxed(content: QLayout | QWidget, margins: int = 14) -> QFrame:
    """`content` in a card with rounded corners (QFrame#card), as a window's parts sit."""
    frame = QFrame()
    frame.setObjectName("card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(margins, margins, margins, margins)
    if isinstance(content, QLayout):
        lay.addLayout(content)
    else:
        lay.addWidget(content)
    return frame


class ConfirmDialog(QDialog):
    """A question before a change (the user's wish, 26/10: the old message boxes looked rough): a round badge, the
    question in bold and what follows from it, the guests it is about as cards, an optional note, and the buttons —
    Cancel by default and on Escape; the action blue, or red where it destroys something; and optionally a second,
    gentler way (`instead`, such as "Shut Down Instead" beside Stop). `choice` is then "go", "instead" or ""."""

    CARDS = 4  # guests shown as cards; the rest are counted

    def __init__(self, parent: QWidget | None, title: str, text: str, action: str, destructive: bool = False,
                 icon: str = "", guests=(), note: str = "", instead: str = ""):
        from .theme import colors
        super().__init__(parent)
        c = colors()
        self.choice = ""
        self.setWindowTitle(title.rstrip("?"))
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(14)
        head = DialogHead(icon or ("warning" if destructive else "question"), title, text,
                          c.danger if destructive else c.accent)
        self.badge, self.title, self.text = head.badge, head.title, head.text
        lay.addWidget(head)
        guests = list(guests)
        for g in guests[:self.CARDS]:
            lay.addWidget(guest_card(g))
        if len(guests) > self.CARDS:
            lay.addWidget(label(f"…and {len(guests) - self.CARDS} more", "dim"))
        self.note = label(f"ⓘ  {note}", "dim", wrap=True) if note else None
        if self.note is not None:
            lay.addWidget(self.note)
        buttons = QDialogButtonBox()
        self.instead = None
        if instead:
            self.instead = buttons.addButton(instead, QDialogButtonBox.ButtonRole.ResetRole)
            self.instead.clicked.connect(lambda: self._done("instead"))
        self.cancel = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.go = buttons.addButton(action, QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("kind", "destructive" if destructive else "suggested")
        self.go.clicked.connect(lambda: self._done("go"))
        self.cancel.clicked.connect(self.reject)
        for b in buttons.buttons():
            b.setAutoDefault(False)
        self.cancel.setDefault(True)  # the safe answer, on Enter too
        lay.addWidget(buttons)
        fit_to_width(self, 460)

    def _done(self, choice: str) -> None:
        self.choice = choice
        self.accept()


def confirm(parent: QWidget, title: str, text: str, action: str, destructive: bool = False, *, icon: str = "",
            guests=(), note: str = "", instead: str = "") -> bool | str:
    """Ask before doing something (ConfirmDialog); Cancel is the default. True to go on, False not to — or
    "instead" when the second way `instead` was chosen."""
    dlg = ConfirmDialog(parent, title, text, action, destructive, icon=icon, guests=guests, note=note,
                        instead=instead)
    dlg.exec()
    return {"go": True, "instead": "instead"}.get(dlg.choice, False)


def fit_to_width(dialog: QWidget, width: int) -> None:
    """Size a dialog for `width`. Qt does not size top-level windows by height-for-width, so dialogs with
    wrapped text opened too short and squeezed their form fields over each other (measured: 580 px given,
    648 px needed at 560 px wide)."""
    dialog.setMinimumWidth(width)
    lay = dialog.layout()
    w = max(width, dialog.width() if dialog.isVisible() else width)
    h = lay.heightForWidth(w) if lay is not None and lay.hasHeightForWidth() else dialog.sizeHint().height()
    h = max(h, dialog.sizeHint().height() if lay is None or not lay.hasHeightForWidth() else h)
    dialog.setMinimumHeight(h)
    dialog.resize(w, h)


def error(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.warning(parent, title, text)


def info(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


# -- number formatting -----------------------------------------------------------------------------

def gib(n: float | int | None) -> str:
    if not n:
        return "0 GiB"
    value = n / (1 << 30)
    return f"{value:.1f} GiB" if value < 100 else f"{value:.0f} GiB"


def mem_text(n: float | int | None) -> str:
    if not n:
        return "—"
    if n < (1 << 30):
        return f"{n / (1 << 20):.0f} MiB"
    return gib(n)


def uptime_text(seconds: int | float | None) -> str:
    s = int(seconds or 0)
    if s <= 0:
        return "—"
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} d {h} h"
    if h:
        return f"{h} h {m} min"
    return f"{m} min"
