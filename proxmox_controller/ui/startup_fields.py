"""The start/shutdown order rows of a form (New VM, New Container, Edit), shown while "Start at boot" is ticked."""

from __future__ import annotations

from typing import Callable

from PySide6.QtWidgets import QCheckBox, QFormLayout, QHBoxLayout, QSpinBox, QWidget

from ..core import startup
from .widgets import label


class StartupFields:
    def __init__(self, form: QFormLayout, onboot: QCheckBox, relayout: Callable[[], None] | None = None):
        self.form, self.onboot, self.relayout = form, onboot, relayout
        self.order = QSpinBox()
        self.order.setRange(0, 9999)
        self.order.setSpecialValueText("Any")
        self.order.setToolTip("Lower numbers start first and shut down last. Any: after those with a number.")
        self.up = QSpinBox()
        self.up.setRange(0, 3600)
        self.up.setSuffix(" s")
        self.up.setToolTip("How long Proxmox waits after starting this one before it starts the next.")
        self.down = QSpinBox()
        self.down.setRange(0, 3600)
        self.down.setSuffix(" s")
        self.down.setSpecialValueText(f"Default ({startup.DEFAULT_DOWN_S} s)")
        self.down.setToolTip("When the host shuts down: how long this one may take to shut down by itself.")
        self.row = QWidget()
        r = QHBoxLayout(self.row)
        r.setContentsMargins(0, 0, 0, 0)
        r.setSpacing(8)
        r.addWidget(self.order, 1)
        r.addWidget(label("then wait"))
        r.addWidget(self.up, 1)
        form.addRow("Boot order", self.row)
        form.addRow("Shutdown timeout", self.down)
        onboot.toggled.connect(self._show)
        self._show(onboot.isChecked())

    def _show(self, on: bool) -> None:
        self.form.setRowVisible(self.row, on)
        self.form.setRowVisible(self.down, on)
        if self.relayout is not None:
            self.relayout()

    def set_visible(self, on: bool) -> None:
        """For forms that hide the whole Start-at-boot part (a template copy)."""
        self._show(on and self.onboot.isChecked())

    def load(self, cfg: dict) -> None:
        s = startup.parse(cfg.get("startup", ""))
        self.order.setValue(s["order"] or 0)
        self.up.setValue(s["up"] or 0)
        self.down.setValue(s["down"] or 0)

    def text(self) -> str:
        return startup.value(self.order.value(), self.up.value(), self.down.value())

    def params(self) -> dict:
        """For something new: only when it starts at boot and an order was given."""
        return {"startup": self.text()} if self.onboot.isChecked() and self.text() else {}

    def changes(self, cfg: dict) -> dict:
        return startup.change(cfg, self.order.value(), self.up.value(), self.down.value())
