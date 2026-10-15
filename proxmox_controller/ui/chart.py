"""A one-series line chart drawn with QPainter: CPU or memory of a guest over time.

Same rules as the Server Controller charts: one axis, a 2 px line in categorical slot 1 (blue), recessive
grid, labels measured so they are never cut, the latest value at the end of the line, an optional limit
line, and a crosshair with a tooltip at the pointer's time.
"""

from __future__ import annotations

import math
import time
from typing import Callable

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QFontMetricsF, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from . import theme

SERIES = {"dark": "#3987e5", "light": "#2a78d6"}  # validated categorical slot 1
LIMIT = "#d03b3b"


def nice_ticks(lo: float, hi: float, count: int = 4) -> list[float]:
    if hi <= lo:
        hi = lo + 1
    raw = (hi - lo) / count
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    first, last = math.floor(lo / step) * step, math.ceil(hi / step) * step
    ticks, v = [], first
    while v <= last + 1e-9:
        ticks.append(round(v, 6))
        v += step
    return ticks


class LineChart(QWidget):
    def __init__(self, fmt: Callable[[float], str], short: Callable[[float], str] | None = None):
        super().__init__()
        self.fmt, self.short = fmt, short or fmt
        self.points: list[tuple[float, float]] = []  # (unix time, value)
        self.limit: tuple[float, str] | None = None
        self.floor_zero = True
        self.hover_x: float | None = None
        self.min_left = self.min_right = 0.0  # set by align(): charts stacked in a window share their time axis
        self.setMouseTracking(True)
        self.setMinimumHeight(190)

    def set_data(self, points: list[tuple[float, float]], limit: tuple[float, str] | None = None) -> None:
        self.points = sorted(points)
        self.limit = limit
        self.update()

    def mouseMoveEvent(self, ev) -> None:
        self.hover_x = ev.position().x()
        self.update()

    def leaveEvent(self, ev) -> None:
        self.hover_x = None
        self.update()

    def label_font(self) -> QFont:
        font = QFont(self.font())
        font.setPointSizeF(font.pointSizeF() * 0.9)
        return font

    def scale(self) -> tuple[list[float], list[str], str, float, float]:
        """Ticks, their labels, the last value's label, and the room they need left and right."""
        fm = QFontMetricsF(self.label_font())
        values = [v for _t, v in self.points] + ([self.limit[0]] if self.limit else [])
        lo, hi = (0.0 if self.floor_zero else min(values)), max(values)
        ticks = nice_ticks(lo, hi * 1.08 if hi > 0 else 1)
        labels = [self.short(t) for t in ticks]
        end_label = self.fmt(self.points[-1][1])
        return (ticks, labels, end_label, max(fm.horizontalAdvance(t) for t in labels) + 14,
                fm.horizontalAdvance(end_label) + 22)

    def paintEvent(self, ev) -> None:
        c = theme.colors()
        dark = theme.is_dark()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        text = QColor(c.text)
        muted = QColor(c.dim)
        font = self.label_font()
        p.setFont(font)
        fm = QFontMetricsF(font)
        if not self.points:
            p.setPen(muted)
            p.drawText(QRectF(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No data for this time range yet.")
            return
        ticks, tick_labels, end_label, left, right = self.scale()
        vmin, vmax = ticks[0], ticks[-1]
        x0 = max(left, self.min_left)
        x1 = w - max(right, self.min_right)
        y0, y1 = 10.0, h - 26.0
        t0, t1 = self.points[0][0], self.points[-1][0]
        if t1 <= t0:
            t1 = t0 + 60

        def px(t):
            return x0 + (t - t0) / (t1 - t0) * (x1 - x0)

        def py(v):
            return y1 - (v - vmin) / (vmax - vmin) * (y1 - y0)

        grid = QColor(c.text)
        grid.setAlphaF(0.10)
        for v, lbl in zip(ticks, tick_labels):
            y = round(py(v)) + 0.5
            p.setPen(QPen(grid, 1))
            p.drawLine(QPointF(x0, y), QPointF(x1, y))
            p.setPen(muted)
            p.drawText(QRectF(0, y - 9, x0 - 6, 18), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, lbl)
        span = t1 - t0
        fmt = "%H:%M" if span <= 26 * 3600 else "%a %d"
        widest = fm.horizontalAdvance(time.strftime(fmt, time.localtime(t1))) + 8
        count = max(2, min(5, int((x1 - x0) // (widest * 1.6)) + 1))  # as many times as fit without touching
        for i in range(count):
            t = t0 + span * i / (count - 1)
            s = time.strftime(fmt, time.localtime(t))
            tw = fm.horizontalAdvance(s)
            x = px(t) - (0 if i == 0 else tw if i == count - 1 else tw / 2)
            p.drawText(QPointF(x, h - 8), s)
        if self.limit and vmin <= self.limit[0] <= vmax:
            y = round(py(self.limit[0])) + 0.5
            p.setPen(QPen(QColor(LIMIT), 1))
            p.drawLine(QPointF(x0, y), QPointF(x1, y))
            p.setPen(QColor(c.dim))
            p.drawText(QPointF(x0 + 4, y - 5), self.limit[1])
        series = QColor(SERIES["dark" if dark else "light"])
        path = QPainterPath()
        gap = max(180.0, span / max(len(self.points), 1) * 3)
        prev = None
        for t, v in self.points:
            if prev is None or t - prev > gap:
                path.moveTo(px(t), py(v))
            else:
                path.lineTo(px(t), py(v))
            prev = t
        p.setPen(QPen(series, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.drawPath(path)
        lt, lv = self.points[-1]
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(c.card))
        p.drawEllipse(QPointF(px(lt), py(lv)), 6, 6)
        p.setBrush(series)
        p.drawEllipse(QPointF(px(lt), py(lv)), 4, 4)
        p.setPen(text)
        p.drawText(QPointF(x1 + 10, py(lv) + fm.ascent() / 2 - 1), end_label)
        if self.hover_x is not None and x0 <= self.hover_x <= x1:
            th = t0 + (self.hover_x - x0) / (x1 - x0) * (t1 - t0)
            t, v = min(self.points, key=lambda pt: abs(pt[0] - th))
            x = round(px(t)) + 0.5
            p.setPen(QPen(muted, 1))
            p.drawLine(QPointF(x, y0), QPointF(x, y1))
            label = f"{time.strftime('%a %d %H:%M', time.localtime(t))}   {self.fmt(v)}"
            bw = fm.horizontalAdvance(label) + 20
            bx = x + 10 if x + 10 + bw < w else x - 10 - bw
            p.setPen(QPen(grid, 1))
            p.setBrush(QColor(c.card))
            p.drawRoundedRect(QRectF(bx, y0 + 4, bw, 26), 6, 6)
            p.setPen(text)
            p.drawText(QRectF(bx, y0 + 4, bw, 26), Qt.AlignmentFlag.AlignCenter, label)


def align(*charts: "LineChart") -> None:
    """Give charts stacked in one window the same margins, so one moment sits at the same place in all of them."""
    room = [c.scale()[3:] for c in charts if c.points]
    left = max((r[0] for r in room), default=0.0)
    right = max((r[1] for r in room), default=0.0)
    for c in charts:
        c.min_left, c.min_right = left, right
        c.update()
