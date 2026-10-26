"""A VM's display, pointer, sound card and USB devices as rows of a form — the same rows in New VM and in Edit."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QListWidget, QListWidgetItem,
                               QVBoxLayout, QWidget)

from ..core import vmhw
from .widgets import label

SPICE_DISPLAYS = ("qxl", "qxl2", "qxl3", "qxl4", "virtio", "virtio-gl")


class HardwareFields:
    def __init__(self, form: QFormLayout):
        self.form = form
        self.original_usb: dict[str, str] = {}  # device id → its config value as it was (kept when untouched)
        self.spice_ports = vmhw.SPICE_USB_PORTS
        self.fast: set[str] = set()
        self.shown = True

        self.display = QComboBox()
        for key, text in vmhw.DISPLAYS:
            self.display.addItem(text, key)
        self.tablet = QCheckBox("USB tablet: the pointer lands exactly where you point")
        self.tablet.setToolTip("An absolute pointer, for this app's console and for Claude's clicks. Without it the "
                               "guest has only a relative mouse: Windows then puts a click wherever its pointer "
                               "already is. Proxmox leaves the tablet out with the SPICE display unless it is set "
                               "here.")
        self.sound = QComboBox()
        self.sound.addItem("None", "")
        for key, text in vmhw.SOUND_CARDS:
            self.sound.addItem(text, key)
        self.output = QComboBox()
        for key, text in vmhw.SOUND_OUTPUTS:
            self.output.addItem(text, key)
        self.sound_box = QWidget()
        srow = QHBoxLayout(self.sound_box)
        srow.setContentsMargins(0, 0, 0, 0)
        srow.setSpacing(8)
        srow.addWidget(self.sound, 1)
        srow.addWidget(label("plays through"))
        srow.addWidget(self.output)
        self.usb = QListWidget()
        self.usb.setMinimumHeight(60)
        self.usb.setMaximumHeight(84)
        self.spice_usb = QCheckBox("Also USB devices of this computer, through SPICE")
        self.spice_usb.setToolTip("In remote-viewer: File → USB device selection. Up to "
                                  f"{vmhw.SPICE_USB_PORTS} devices at a time.")
        self.usb_box = QWidget()
        ubox = QVBoxLayout(self.usb_box)
        ubox.setContentsMargins(0, 0, 0, 0)
        ubox.setSpacing(6)
        ubox.addWidget(self.usb)
        ubox.addWidget(self.spice_usb)
        self.hint = label("", "caption", wrap=True)
        form.addRow("Display", self.display)
        form.addRow("Pointer", self.tablet)
        form.addRow("Sound", self.sound_box)
        form.addRow("", self.hint)
        form.addRow("USB devices", self.usb_box)
        for w in (self.display, self.sound, self.output):
            w.currentIndexChanged.connect(lambda *_: self._update())
        self._update()

    # -- what is shown -----------------------------------------------------------------------------

    def set_visible(self, on: bool) -> None:
        self.shown = on
        for field in (self.display, self.tablet, self.sound_box, self.usb_box):
            self.form.setRowVisible(field, on)
        self._update()

    def _update(self) -> None:
        has_sound = bool(self.sound.currentData())
        self.output.setEnabled(has_sound)
        spice = self.display.currentData() in SPICE_DISPLAYS
        if has_sound and self.output.currentData() == "spice" and not spice:  # said only when it will not work
            self.hint.setText("Sound through SPICE is heard only with the SPICE display (and the SPICE console).")
        else:
            self.hint.setText("")
        self.form.setRowVisible(self.hint, self.shown and bool(self.hint.text()))  # no empty gap when silent
        self.spice_usb.setEnabled(spice)

    def summary(self) -> str:
        """What is chosen, in one line — "SPICE display · USB tablet · Intel HD Audio (ich9) · no USB devices" — for a
        window that folds these rows away (New VM)."""
        n = len(self.chosen())
        parts = [f"{self.display.currentText()} display", "USB tablet" if self.tablet.isChecked() else "no USB tablet",
                 self.sound.currentText() if self.sound.currentData() else "no sound",
                 "no USB devices" if not n else f"{n} USB device{'s' if n != 1 else ''}"]
        if self.spice_usb.isChecked() and self.spice_usb.isEnabled():
            parts.append("USB of this computer through SPICE")
        return " · ".join(parts)

    def set_defaults(self) -> None:
        """A new VM: the SPICE display (with the USB tablet: Proxmox would leave it out) and an Intel HD Audio card
        that plays through SPICE."""
        self.display.setCurrentIndex(self.display.findData("qxl"))
        self.tablet.setChecked(True)
        self.sound.setCurrentIndex(self.sound.findData("ich9-intel-hda"))
        self.output.setCurrentIndex(self.output.findData("spice"))

    def set_devices(self, devices: list[dict], chosen: list[str] = ()) -> None:
        self.usb.clear()
        self.fast = {vmhw.usb_id(d) for d in devices if vmhw.is_fast(d)}
        seen = set()
        for d in devices:
            dev = vmhw.usb_id(d)
            if dev in seen:
                continue
            seen.add(dev)
            self._add(vmhw.usb_label(d), dev, dev in chosen)
        for dev in chosen:  # set up for the VM but not plugged in now
            if dev not in seen:
                self._add(f"{dev}  (not plugged in now)" if ":" in dev else f"USB port {dev}", dev, True)
        if self.usb.count() == 0:
            item = QListWidgetItem("No USB devices are plugged into the host.")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.usb.addItem(item)

    def _add(self, text: str, dev: str, checked: bool) -> None:
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, dev)
        item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        self.usb.addItem(item)

    def load(self, cfg: dict, devices: list[dict]) -> None:
        """An existing VM's settings."""
        display = vmhw.display_of(cfg)
        if self.display.findData(display) < 0:  # something this app does not offer, such as cirrus
            self.display.addItem(f"{display} (as set now)", display)
        self.display.setCurrentIndex(self.display.findData(display))
        self.tablet.setChecked(vmhw.tablet_of(cfg))  # as the VM has it now — Proxmox's default where it is not set
        sound = vmhw.sound_of(cfg)
        self.sound.setCurrentIndex(max(0, self.sound.findData(sound[0])) if sound else 0)
        if sound:
            self.output.setCurrentIndex(max(0, self.output.findData(sound[1])))
        slots = vmhw.usb_slots(cfg)
        self.original_usb = {vmhw.usb_host(v): v for v in slots.values() if vmhw.usb_host(v) != "spice"}
        spice = sum(1 for v in slots.values() if vmhw.usb_host(v) == "spice")
        self.spice_ports = spice or vmhw.SPICE_USB_PORTS
        self.spice_usb.setChecked(spice > 0)
        self.set_devices(devices, list(self.original_usb))
        self._update()

    # -- what is asked for -------------------------------------------------------------------------

    def chosen(self) -> list[str]:
        return [self.usb.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.usb.count())
                if self.usb.item(i).checkState() == Qt.CheckState.Checked]

    def _wanted_usb(self) -> list[str]:
        values = [self.original_usb.get(dev) or vmhw.usb_value(dev, dev in self.fast) for dev in self.chosen()]
        spice = self.spice_ports if self.spice_usb.isChecked() and self.spice_usb.isEnabled() else 0
        return values + ["spice"] * spice

    def params(self) -> dict:
        """For a new VM."""
        out: dict = {}
        if self.display.currentData() != "std":
            out["vga"] = self.display.currentData()
        out["tablet"] = 1 if self.tablet.isChecked() else 0  # said outright: it then outlives a change of display
        if self.sound.currentData():
            out["audio0"] = vmhw.sound_value(self.sound.currentData(), self.output.currentData())
        for n, value in enumerate(self._wanted_usb()):
            out[f"usb{n}"] = value
        return out

    def changes(self, cfg: dict, limit: int = vmhw.USB_SLOTS) -> dict:
        """For an existing VM: only what differs from its config."""
        parts = []
        display = self.display.currentData()
        if display != vmhw.display_of(cfg):
            parts.append({"vga": display} if display != "std" else {"delete": "vga"})
        if self.tablet.isChecked() != vmhw.tablet_of(cfg, display):  # with the display it will have: SPICE drops it
            parts.append({"tablet": 1 if self.tablet.isChecked() else 0})
        sound = (self.sound.currentData(), self.output.currentData()) if self.sound.currentData() else None
        if sound != vmhw.sound_of(cfg):
            parts.append({"audio0": vmhw.sound_value(*sound)} if sound else {"delete": "audio0"})
        parts.append(vmhw.usb_changes(cfg, self._wanted_usb(), limit))
        return vmhw.merge(*parts)
