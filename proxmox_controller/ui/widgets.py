"""Small building blocks shared by the pages and dialogs."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton, QVBoxLayout,
                               QWidget)

from .theme import refresh_widget_style


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

    def __init__(self, title: str):
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(4)
        lay.addWidget(label(title, "dim"))
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


def confirm(parent: QWidget, title: str, text: str, action: str, destructive: bool = False) -> bool:
    """Ask before doing something. The safe answer (Cancel) is the default."""
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setIcon(QMessageBox.Icon.Warning if destructive else QMessageBox.Icon.Question)
    box.setText(f"<b>{title}</b>")
    box.setInformativeText(text)
    go = box.addButton(action, QMessageBox.ButtonRole.AcceptRole)
    go.setProperty("kind", "destructive" if destructive else "suggested")
    cancel = box.addButton(QMessageBox.StandardButton.Cancel)
    box.setDefaultButton(cancel)
    box.setEscapeButton(cancel)
    box.exec()
    return box.clickedButton() is go


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
