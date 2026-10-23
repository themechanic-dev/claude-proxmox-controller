"""Hazard stripes — yellow and black at 45°, as on warning tape — that make Claude's approval window easy to find among
many windows on a big screen: a band along its top, broken by its title, and a frame all round (the user's choice,
23/10). The same colours in light and dark, as real warning tape."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPolygonF
from PySide6.QtWidgets import QWidget

from . import theme

YELLOW, BLACK = QColor("#F5C400"), QColor("#1C1C1C")
FRAME = 10  # the frame's width in pixels


def paint_stripes(p: QPainter, rect: QRectF, width: float) -> None:
    """Black, then yellow stripes leaning right, `width` wide, across `rect`."""
    p.save()
    p.setClipRect(rect)
    p.fillRect(rect, BLACK)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(YELLOW)
    h = rect.height()
    x = rect.left() - h
    while x < rect.right() + h:
        p.drawPolygon(QPolygonF([QPointF(x, rect.bottom()), QPointF(x + width, rect.bottom()),
                                 QPointF(x + width + h, rect.top()), QPointF(x + h, rect.top())]))
        x += 2 * width
    p.restore()


def paint_frame(widget: QWidget) -> None:
    """The striped frame along the edges of `widget` (called from its paintEvent)."""
    p = QPainter(widget)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    r = QRectF(widget.rect())
    for side in (QRectF(r.left(), r.top(), r.width(), FRAME), QRectF(r.left(), r.bottom() - FRAME, r.width(), FRAME),
                 QRectF(r.left(), r.top(), FRAME, r.height()), QRectF(r.right() - FRAME, r.top(), FRAME, r.height())):
        paint_stripes(p, side, 9)
    p.end()


class HazardBand(QWidget):
    """The stripes along the top of a window, the title on a plate of the window's own colour in the middle."""

    def __init__(self, text: str, height: int = 40, stripe: float = 15):
        super().__init__()
        self.text, self.stripe = text, stripe
        self.setFixedHeight(height)
        self.setAccessibleName(text)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = theme.colors()
        r = QRectF(self.rect())
        paint_stripes(p, r, self.stripe)
        font = QFont(self.font())
        font.setPointSizeF(12.5)
        font.setBold(True)
        p.setFont(font)
        tw = p.fontMetrics().horizontalAdvance(self.text)
        plate = QRectF(r.center().x() - tw / 2 - 18, r.top() + 4, tw + 36, r.height() - 8)
        path = QPainterPath()
        path.addRoundedRect(plate, 6, 6)
        p.fillPath(path, QColor(c.window))
        p.setPen(QColor(c.text))
        p.drawText(plate, Qt.AlignmentFlag.AlignCenter, self.text)
        p.end()
