"""The graph wall: one window per host with a card for every running VM and container — CPU and memory side by side —
made to fill a screen. Cards come and go by themselves as guests start and stop; the charts stay current."""

from __future__ import annotations

import time
from typing import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QFrame, QGridLayout, QHBoxLayout, QPushButton, QScrollArea,
                               QVBoxLayout, QWidget)

from ..core.pve import Pve
from . import geometry, guest_dialogs
from .chart import LineChart, align
from .widgets import label, mem_text
from .worker import Runner

LIST_EVERY_MS = 10_000  # how soon a guest that starts or stops gets or loses its card
TILE_ASPECT = 2.4       # a card is about this much wider than tall (two charts side by side)
CHART_MIN_H = 60        # below this the wall scrolls instead of shrinking the cards further
WALLS: dict[str, "GraphWall"] = {}


def best_columns(n: int, width: float, height: float, aspect: float = TILE_ASPECT) -> int:
    """How many columns give n cards the biggest size in a width × height window: every card always fits, and they
    shrink as more guests start (and grow again as guests stop)."""
    best, best_size = 1, -1.0
    for cols in range(1, max(n, 1) + 1):
        rows = -(-n // cols)
        size = min(width / cols / aspect, height / max(rows, 1))  # the height a card can have in this shape
        if size > best_size + 1e-9:
            best, best_size = cols, size
    return best


class GuestTile(QFrame):
    """One guest: name and current numbers on top, its CPU and memory charts below."""

    def __init__(self, wall: "GraphWall", guest: dict):
        super().__init__()
        self.setObjectName("card")
        self.wall, self.g = wall, guest
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(6)
        head = QHBoxLayout()
        self.title = label("", "heading")
        self.kind = label("", "dim")
        self.numbers = label("", "dim")
        head.addWidget(self.title)
        head.addWidget(self.kind)
        head.addStretch(1)
        head.addWidget(self.numbers)
        lay.addLayout(head)
        charts = QHBoxLayout()
        charts.setSpacing(12)
        self.cpu = LineChart(lambda v: f"{v:.0f} %", lambda v: f"{v:.0f}%")
        self.mem = LineChart(lambda v: f"{v:.1f} GiB", lambda v: f"{v:g} GiB")
        for title, chart in (("CPU", self.cpu), ("Memory", self.mem)):
            chart.setMinimumHeight(CHART_MIN_H)
            box = QVBoxLayout()
            box.setSpacing(2)
            box.addWidget(label(title, "caption"))
            box.addWidget(chart, 1)
            charts.addLayout(box, 1)
        lay.addLayout(charts, 1)
        self.setToolTip("Double-click for the full graphs")
        self.set_guest(guest)

    def set_guest(self, g: dict) -> None:
        self.g = g
        self.title.setText(f"{g['vmid']} · {g.get('name', '')}")
        self.kind.setText("Container" if g["type"] == "lxc" else "VM")
        cpu = f"CPU {g.get('cpu', 0) * 100:.0f} % of {g.get('maxcpu', 0)}"
        mem = f"Memory {mem_text(g.get('mem'))} / {mem_text(g.get('maxmem'))}"
        self.numbers.setText(f"{cpu}   ·   {mem}")

    def mouseDoubleClickEvent(self, ev) -> None:
        self.wall.open_graphs(self.g)


class GraphWall(QWidget):
    def __init__(self, key: str, client: Callable[[], Pve], runner: Runner, host_name: str,
                 prefs: dict | None = None, save_prefs: Callable[[], None] | None = None):
        super().__init__(None, Qt.WindowType.Window)  # its own window: for any screen, never pinned to the app
        self.key, self.client, self.runner, self.host_name = key, client, runner, host_name
        self.prefs, self.save_prefs = prefs, save_prefs
        self.setWindowTitle(f"Graph Wall — {host_name}")
        self.tiles: dict[int, GuestTile] = {}
        self.guests: list[dict] = []
        self.frame = "hour"
        self.listing = False
        self.columns = 0
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(10)
        top = QHBoxLayout()
        group = QButtonGroup(self)
        self.frame_buttons = {}
        for key_, text in guest_dialogs.GraphsDialog.FRAMES:
            b = QPushButton(text)
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key_: self.set_frame(k))
            group.addButton(b)
            top.addWidget(b)
            self.frame_buttons[key_] = b
        self.frame_buttons["hour"].setChecked(True)
        top.addSpacing(12)
        self.containers = QCheckBox("Containers")
        self.containers.setChecked(True)
        self.containers.toggled.connect(lambda *_: self._show_guests(self.guests))
        top.addWidget(self.containers)
        top.addStretch(1)
        self.status = label("Reading which guests are running…", "dim")
        top.addWidget(self.status)
        lay.addLayout(top)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.body = QWidget()
        self.grid = QGridLayout(self.body)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(12)
        self.empty = label("No VM or container is running.", "dim")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll.setWidget(self.body)
        lay.addWidget(self.scroll, 1)
        self.list_timer = QTimer(self)
        self.list_timer.timeout.connect(self.refresh_list)
        self.list_timer.start(LIST_EVERY_MS)
        self.chart_timer = QTimer(self)
        self.chart_timer.timeout.connect(self.refresh_charts)
        self.chart_timer.start(guest_dialogs.GraphsDialog.REFRESH_MS[self.frame])
        self.resize(1280, 820)
        geometry.restore(self, f"wall/{key}", prefs)  # the screen it was left on
        self.refresh_list()

    # -- which guests ------------------------------------------------------------------------------

    def refresh_list(self) -> None:
        if self.listing:
            return
        self.listing = True
        pve = self.client()
        self.runner.run(lambda: pve.guests(), self._got_list)

    def _got_list(self, guests, err) -> None:
        self.listing = False
        if err is not None:
            self.status.setText(f"No answer from the host — {err}")
            return
        self.guests = guests or []
        self._show_guests(self.guests)

    def _show_guests(self, guests: list[dict]) -> None:
        running = sorted((g for g in guests if g.get("status") == "running" and not g.get("template")
                          and (g["type"] == "qemu" or self.containers.isChecked())), key=lambda g: g["vmid"])
        wanted = {g["vmid"]: g for g in running}
        changed = False
        for vmid in [v for v in self.tiles if v not in wanted]:  # stopped (or hidden): the card goes
            tile = self.tiles.pop(vmid)
            self.grid.removeWidget(tile)
            tile.deleteLater()
            changed = True
        for vmid, g in wanted.items():
            if vmid in self.tiles:
                self.tiles[vmid].set_guest(g)
            else:  # started: a new card, with its charts at once
                self.tiles[vmid] = GuestTile(self, g)
                self._load(vmid)
                changed = True
        if changed or not self.columns:
            self._relayout(force=True)
        self.status.setText(f"{len(self.tiles)} running  ·  updated {time.strftime('%H:%M:%S')}")

    # -- the charts --------------------------------------------------------------------------------

    def set_frame(self, frame: str) -> None:
        self.frame = frame
        self.frame_buttons[frame].setChecked(True)
        self.chart_timer.start(guest_dialogs.GraphsDialog.REFRESH_MS[frame])
        self.refresh_charts()

    def refresh_charts(self) -> None:
        for vmid in list(self.tiles):
            self._load(vmid)

    def _load(self, vmid: int) -> None:
        tile = self.tiles[vmid]
        g, frame, pve = tile.g, self.frame, self.client()
        self.runner.run(lambda: pve.rrd(g["node"], g["type"], g["vmid"], frame),
                        lambda rows, err, vmid=vmid, tile=tile, frame=frame: self._got_rrd(vmid, tile, frame, rows, err))

    def _got_rrd(self, vmid: int, tile: GuestTile, frame: str, rows, err) -> None:
        if self.tiles.get(vmid) is not tile or frame != self.frame or err is not None:
            return  # the card went, or another range was chosen meanwhile
        guest_dialogs.show_rrd(rows, tile.cpu, tile.mem)
        align(tile.cpu, tile.mem)

    # -- layout ------------------------------------------------------------------------------------

    def _relayout(self, force: bool = False) -> None:
        view = self.scroll.viewport()
        cols = best_columns(len(self.tiles), view.width(), view.height())
        if not force and cols == self.columns:
            return
        self.columns = cols
        while self.grid.count():
            self.grid.takeAt(0)
        self.empty.setVisible(not self.tiles)
        if not self.tiles:
            self.grid.addWidget(self.empty, 0, 0)
            return
        for i, vmid in enumerate(sorted(self.tiles)):
            self.grid.addWidget(self.tiles[vmid], i // cols, i % cols)
        for c in range(self.grid.columnCount()):
            self.grid.setColumnStretch(c, 1 if c < cols else 0)
        rows = (len(self.tiles) + cols - 1) // cols
        for r in range(self.grid.rowCount()):
            self.grid.setRowStretch(r, 1 if r < rows else 0)  # the cards share the whole window

    def resizeEvent(self, ev) -> None:
        super().resizeEvent(ev)
        self._relayout()

    def open_graphs(self, g: dict) -> None:
        guest_dialogs.show_graphs(f"{self.key}/{g['vmid']}", self.client, self.runner, g, self.host_name,
                                  self.prefs, self.save_prefs)

    def closeEvent(self, ev) -> None:
        geometry.remember(self, f"wall/{self.key}", self.prefs, self.save_prefs)
        self.list_timer.stop()
        self.chart_timer.stop()
        if WALLS.get(self.key) is self:
            del WALLS[self.key]
        super().closeEvent(ev)


def show_wall(key: str, client: Callable[[], Pve], runner: Runner, host_name: str,
              prefs: dict | None = None, save_prefs: Callable[[], None] | None = None) -> GraphWall:
    """Open a host's graph wall, or bring back the one already open."""
    wall = WALLS.get(key)
    if wall is None:
        wall = GraphWall(key, client, runner, host_name, prefs, save_prefs)
        WALLS[key] = wall
    wall.show()
    wall.raise_()
    wall.activateWindow()
    return wall


def close_all() -> None:
    for wall in list(WALLS.values()):
        wall.close()
