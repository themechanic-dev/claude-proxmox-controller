"""The new-VM form — install from an ISO image (Windows 11's UEFI and TPM included) or copy a template — and getting
ISO images onto the host: downloaded by the host itself from a web address, or uploaded from this computer."""

from __future__ import annotations

import os
import re
import threading
from typing import Callable

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                               QHBoxLayout, QLineEdit, QProgressDialog, QRadioButton, QSpinBox, QVBoxLayout, QWidget)

from ..core.pve import Pve, PveError, upload_name
from ..core.vmspec import PROFILES, VMNAME, WINDOWS, iso_name_from_url, vm_params  # noqa: F401 (used here and by tests)
from .startup_fields import StartupFields
from .vm_hardware import HardwareFields
from .widgets import button, confirm, error, fit_to_width, gib, label
from .worker import Runner

ISO_NAME = re.compile(r"^[A-Za-z0-9._-]+\.iso$", re.IGNORECASE)
URL = re.compile(r"^https?://\S+$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
VIRTIO_URL = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
DOWNLOAD_TIMEOUT_S = 4 * 3600

class _Relay(QObject):
    """Carries upload progress from the worker thread to the window (object: sizes pass 2 GB)."""
    progressed = Signal(object, object)


class _Busy:
    def busy(self, text: str) -> None:
        self.status.setText(text)
        self.setEnabled(False)

    def idle(self, text: str = "") -> None:
        self.status.setText(text)
        self.setEnabled(True)


# -- downloading an ISO onto the host --------------------------------------------------------------

class DownloadIsoDialog(_Busy, QDialog):
    """The host downloads an ISO image from a web address straight into one of its storages."""

    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, node: str, storages: list[str],
                 url: str = "", filename: str = ""):
        super().__init__(parent)
        self.client, self.runner, self.node = client, runner, node
        self.volid = ""
        self.setWindowTitle("Download an ISO Image")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.addWidget(label("The Proxmox host downloads the image itself, straight into its storage — nothing passes "
                            "through this computer. Paste the image's direct download address.", "dim", wrap=True))
        form = QFormLayout()
        form.setVerticalSpacing(8)
        self.url = QLineEdit(url)
        self.url.setPlaceholderText("https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso")
        self.filename = QLineEdit(filename or iso_name_from_url(url))
        self.filename.setPlaceholderText("name.iso")
        self._auto_name = not filename
        self.url.textChanged.connect(self._url_changed)
        self.filename.textEdited.connect(lambda *_: setattr(self, "_auto_name", False))
        self.storage = QComboBox()
        self.storage.addItems(storages)
        self.checksum = QLineEdit()
        self.checksum.setPlaceholderText("SHA-256 (optional) — the host checks the file against it")
        form.addRow("Address", self.url)
        form.addRow("File name", self.filename)
        form.addRow("Save to storage", self.storage)
        form.addRow("Checksum", self.checksum)
        lay.addLayout(form)
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.go = buttons.addButton("Download", QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("kind", "suggested")
        buttons.accepted.connect(self.download)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        fit_to_width(self, 560)

    def _url_changed(self, text: str) -> None:
        if self._auto_name:
            self.filename.setText(iso_name_from_url(text))

    def check(self) -> str:
        if not URL.match(self.url.text().strip()):
            return "Paste a web address that starts with https:// (or http://)."
        if not ISO_NAME.match(self.filename.text().strip()):
            return "The file name must end in .iso and use letters, digits, '.', '-' and '_' only."
        if not self.storage.currentText():
            return "No storage on this host accepts ISO images."
        if self.checksum.text().strip() and not SHA256.match(self.checksum.text().strip()):
            return "A SHA-256 checksum is 64 hexadecimal characters (or leave it empty)."
        return ""

    def download(self) -> None:
        problem = self.check()
        if problem:
            error(self, "Download", problem)
            return
        pve, node = self.client(), self.node
        url, name, storage = self.url.text().strip(), self.filename.text().strip(), self.storage.currentText()
        checksum = self.checksum.text().strip().lower()

        def job():
            upid = pve.download_url(node, storage, url, name, checksum=checksum)
            pve.wait_task(node, upid, timeout=DOWNLOAD_TIMEOUT_S, poll=2.0)
            return f"{storage}:iso/{name}"

        def finished(volid, err):
            if err is not None:
                self.idle()
                error(self, "Download", str(err))
                return
            self.volid = volid
            self.accept()

        self.busy(f"The host is downloading {name}. Large images take a while.")
        self.runner.run(job, finished)


# -- the new VM ------------------------------------------------------------------------------------

class CreateVmDialog(_Busy, QDialog):
    def __init__(self, parent: QWidget, client: Callable[[], Pve], runner: Runner, nodes: list[str]):
        super().__init__(parent)
        self.client, self.runner, self.nodes = client, runner, nodes
        self.created: tuple[int, str] | None = None
        self.iso_storages: list[str] = []
        self.template_cfg: dict = {}
        self.setWindowTitle("New VM")
        self.setModal(True)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)

        source = QHBoxLayout()
        source.setSpacing(16)
        self.from_iso = QRadioButton("Install from an ISO image")
        self.from_template = QRadioButton("Copy a template")
        self.from_iso.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.from_iso)
        group.addButton(self.from_template)
        source.addWidget(self.from_iso)
        source.addWidget(self.from_template)
        source.addStretch(1)
        lay.addLayout(source)

        self.form = form = QFormLayout()
        form.setVerticalSpacing(8)
        self.node = QComboBox()
        self.node.addItems(nodes)
        self.vmid = QSpinBox()
        self.vmid.setRange(100, 999999999)
        self.name = QLineEdit()
        self.name.setPlaceholderText("my-vm")
        self.profile = QComboBox()
        for key, prof in PROFILES.items():
            self.profile.addItem(prof["label"], key)
        self.iso = QComboBox()
        self.iso.currentIndexChanged.connect(lambda *_: self.iso.setToolTip(self.iso.currentText()))
        self.download_btn = button("Download…", tooltip="The host downloads an ISO image from a web address")
        self.download_btn.clicked.connect(self.download_iso)
        self.upload_btn = button("Upload…", tooltip="Send an ISO image from this computer to the host")
        self.upload_btn.clicked.connect(self.upload_iso)
        iso_row = QHBoxLayout()
        iso_row.setSpacing(8)
        iso_row.addWidget(self.iso, 1)
        iso_row.addWidget(self.download_btn)
        iso_row.addWidget(self.upload_btn)
        self.virtio = QComboBox()
        self.virtio.currentIndexChanged.connect(lambda *_: self.virtio.setToolTip(self.virtio.currentText()))
        self.virtio_btn = button("Get VirtIO ISO", tooltip="The host downloads Red Hat's VirtIO drivers disc "
                                                           "(virtio-win.iso, about 700 MB) from fedorapeople.org")
        self.virtio_btn.clicked.connect(self.get_virtio)
        virtio_row = QHBoxLayout()
        virtio_row.setSpacing(8)
        virtio_row.addWidget(self.virtio, 1)
        virtio_row.addWidget(self.virtio_btn)
        self.template = QComboBox()
        self.full = QCheckBox("Full copy (stands on its own; a linked copy shares the template's disk)")
        self.full.setChecked(True)
        self.cores = QSpinBox()
        self.cores.setRange(1, 512)
        self.host_cpu = QCheckBox("Host's CPU type (fastest)")
        self.memory = QSpinBox()
        self.memory.setRange(64, 4 * 1024 * 1024)
        self.memory.setSingleStep(512)
        self.memory.setSuffix(" MiB")
        self.disk = QSpinBox()
        self.disk.setRange(1, 65536)
        self.disk.setSuffix(" GiB")
        self.storage = QComboBox()
        self.disk_label = label("on")
        disk_row = QHBoxLayout()
        disk_row.setSpacing(8)
        disk_row.addWidget(self.disk)
        disk_row.addWidget(self.disk_label)
        disk_row.addWidget(self.storage, 1)
        self.bridge = QComboBox()
        self.bridge.setEditable(True)
        self.agent = QCheckBox("QEMU guest agent (lets the app show its address)")
        self.agent.setToolTip("Also install qemu-guest-agent inside the VM (Windows: from the VirtIO drivers disc).")
        self.agent.setChecked(True)
        self.onboot = QCheckBox("Start at boot")
        self.start = QCheckBox("Start it when it is created")
        self.start.setChecked(True)
        if len(nodes) > 1:
            form.addRow("Node", self.node)
        form.addRow("ID", self.vmid)
        form.addRow("Name", self.name)
        form.addRow("Template", self.template)
        form.addRow("", self.full)
        form.addRow("Operating system", self.profile)
        form.addRow("ISO image", iso_row)
        form.addRow("VirtIO drivers", virtio_row)
        cores_row = QHBoxLayout()
        cores_row.setSpacing(12)
        cores_row.addWidget(self.cores, 1)
        cores_row.addWidget(self.host_cpu)
        form.addRow("CPU cores", cores_row)
        form.addRow("Memory", self.memory)
        form.addRow("Disk", disk_row)
        form.addRow("Network bridge", self.bridge)
        self.hw = HardwareFields(form)
        self.hw.set_defaults()
        form.addRow("", self.agent)
        start_row = QHBoxLayout()
        start_row.setSpacing(16)
        start_row.addWidget(self.onboot)
        start_row.addWidget(self.start)
        start_row.addStretch(1)
        form.addRow("", start_row)
        self.startup = StartupFields(form, self.onboot, lambda: fit_to_width(self, 600))
        lay.addLayout(form)
        self.hint = label("", "caption", wrap=True)
        lay.addWidget(self.hint)
        self.status = label("", "dim", wrap=True)
        lay.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.create_btn = buttons.addButton("Create", QDialogButtonBox.ButtonRole.AcceptRole)
        self.create_btn.setProperty("kind", "suggested")
        buttons.accepted.connect(self.create)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

        self.profile.currentIndexChanged.connect(lambda *_: self._profile_changed())
        self.from_iso.toggled.connect(lambda *_: self._source_changed())
        self.template.currentIndexChanged.connect(lambda *_: self._template_changed())
        self.full.toggled.connect(lambda *_: self._mode_changed())
        self.node.currentTextChanged.connect(lambda *_: self.load())
        self._profile_changed()
        fit_to_width(self, 600)
        self.load()

    # -- loading -----------------------------------------------------------------------------------

    def current_node(self) -> str:
        return self.node.currentText()

    def load(self, select_iso: str = "") -> None:
        pve, node = self.client(), self.current_node()
        self.busy("Reading ISO images, storage, networks, USB devices and templates…")

        def usb():
            try:
                return pve.usb_devices(node)
            except PveError:
                return None  # the list says so; creating the VM still works

        self.runner.run(lambda: {"id": pve.next_id(), "isos": pve.isos(node),
                                 "iso_storages": [s["storage"] for s in pve.storages(node, content="iso")],
                                 "storage": pve.storages(node, content="images"), "bridges": pve.bridges(node),
                                 "templates": [g for g in pve.guests() if g.get("template") and g["type"] == "qemu"
                                               and g.get("node") == node], "usb": usb()},
                        lambda data, err: self._loaded(data, err, select_iso))

    def _loaded(self, data, err, select_iso: str = "") -> None:
        if err is not None:
            self.idle()
            error(self, "New VM", str(err))
            return
        self.vmid.setValue(int(data["id"]))
        self.iso_storages = data["iso_storages"]
        chosen = self.hw.chosen()
        self.hw.set_devices(data["usb"] or [], chosen)
        if data["usb"] is None:
            self.hw.usb.addItem("Could not read the host's USB devices.")
        several = len({i["storage"] for i in data["isos"]}) > 1
        for combo, keep, first in ((self.iso, select_iso or self.iso.currentData(), None),
                                   (self.virtio, self.virtio.currentData(), "None")):
            combo.blockSignals(True)
            combo.clear()
            if first:
                combo.addItem(first, "")
            for i in data["isos"]:
                file = i["volid"].split("/")[-1]
                combo.addItem(f"{file}  ({i['storage']})" if several else file, i["volid"])
            index = combo.findData(keep) if keep else -1
            if combo is self.virtio and index < 0:  # a VirtIO disc already on the host is the obvious choice
                index = next((n for n in range(combo.count()) if "virtio" in (combo.itemData(n) or "").lower()), 0)
            combo.setCurrentIndex(max(index, 0))
            combo.blockSignals(False)
        keep = self.storage.currentData()
        self.storage.clear()
        for st in data["storage"]:
            free = (st.get("total", 0) - st.get("used", 0))
            self.storage.addItem(f"{st['storage']}  ({gib(free)} free)", st["storage"])
        if keep and self.storage.findData(keep) >= 0:
            self.storage.setCurrentIndex(self.storage.findData(keep))
        current = self.bridge.currentText()
        self.bridge.clear()
        self.bridge.addItems(data["bridges"] or ["vmbr0"])
        if current:
            self.bridge.setCurrentText(current)
        keep = self.template.currentData()
        self.template.blockSignals(True)
        self.template.clear()
        for t in sorted(data["templates"], key=lambda t: t["vmid"]):
            self.template.addItem(f"{t.get('name', '')} ({t['vmid']})", t["vmid"])
        if keep is not None and self.template.findData(keep) >= 0:
            self.template.setCurrentIndex(self.template.findData(keep))
        self.template.blockSignals(False)
        has_templates = self.template.count() > 0
        self.from_template.setEnabled(has_templates)
        self.from_template.setToolTip("" if has_templates else "There are no VM templates on this host. Turn a VM "
                                                                 "into one in Proxmox: right-click → Convert to template.")
        if not has_templates and self.from_template.isChecked():
            self.from_iso.setChecked(True)
        self.idle("" if data["isos"] or not self.from_iso.isChecked()
                  else "There are no ISO images on this host yet: use Download… or Upload… first.")
        self._mode_changed()
        if self.from_template.isChecked():
            self._template_changed()

    # -- what the form shows -----------------------------------------------------------------------

    def _profile_changed(self) -> None:
        prof = PROFILES[self.profile.currentData()]
        self.cores.setValue(prof["cores"])
        self.memory.setValue(prof["memory"])
        self.disk.setValue(prof["disk"])
        self._mode_changed()

    def _mode_changed(self) -> None:
        iso = self.from_iso.isChecked()
        windows = self.profile.currentData() in WINDOWS
        form = self.form
        for field, visible in ((self.template, not iso), (self.full, not iso), (self.profile, iso), (self.iso, iso)):
            form.setRowVisible(self._row_of(field), visible)
        form.setRowVisible(self._row_of(self.virtio), iso and windows)
        self.host_cpu.setVisible(iso)
        form.setRowVisible(self._row_of(self.agent), iso)
        self.hw.set_visible(iso)  # a copy keeps the template's display, sound and USB
        self.disk.setVisible(iso)  # a copy keeps the template's disk size
        self.disk_label.setText("on" if iso else "Copy to")
        self.storage.setEnabled(iso or self.full.isChecked())  # a linked copy lives next to its template
        if not iso:
            self.hint.setText("The copy keeps the template's disks and settings; CPU and memory are changed after "
                              "copying if you set different values here.")
        elif self.profile.currentData() == "win11":
            self.hint.setText("Windows 11 gets UEFI with Secure Boot and a TPM 2.0. Without the VirtIO drivers disc "
                              "the disk and network use slower drivers Windows already has (SATA, Intel e1000e).")
        elif windows:
            self.hint.setText("Without the VirtIO drivers disc the disk and network use slower drivers Windows "
                              "already has (SATA, Intel e1000e). With it, load the drivers from that disc during setup.")
        else:
            self.hint.setText("After it starts, open its Console to install the operating system.")
        fit_to_width(self, 600)

    def _source_changed(self) -> None:
        self._mode_changed()
        if self.from_template.isChecked():  # start from the chosen template's CPU and memory
            self._template_changed()

    def _row_of(self, field: QWidget) -> int:
        """The form row whose field contains `field` (rows with a layout as their field, such as the ISO row)."""
        for row in range(self.form.rowCount()):
            item = self.form.itemAt(row, QFormLayout.ItemRole.FieldRole)
            if item is None:
                continue
            if item.widget() is field:
                return row
            lay = item.layout()
            if lay is not None and any(lay.itemAt(i).widget() is field for i in range(lay.count())):
                return row
        return -1

    def _template_changed(self) -> None:
        vmid = self.template.currentData()
        if vmid is None:
            return
        pve, node = self.client(), self.current_node()

        def done(cfg, err):
            self.template_cfg = cfg or {}
            if cfg:
                self.cores.setValue(int(cfg.get("cores", self.cores.value())))
                self.memory.setValue(int(cfg.get("memory", self.memory.value())))
                if not self.name.text().strip():
                    self.name.setPlaceholderText(f"{cfg.get('name', 'vm')}-copy")

        self.runner.run(lambda: pve.guest_config(node, "qemu", vmid), done)

    # -- ISO images --------------------------------------------------------------------------------

    def download_iso(self, url: str = "", filename: str = "") -> None:
        if not self.iso_storages:
            error(self, "Download", "No storage on this host accepts ISO images.")
            return
        dlg = DownloadIsoDialog(self, self.client, self.runner, self.current_node(), self.iso_storages, url, filename)
        dlg.finished.connect(lambda result: self._after_download(dlg, result))
        dlg.open()
        self.download_dialog = dlg

    def _after_download(self, dlg: DownloadIsoDialog, result: int) -> None:
        if result == QDialog.DialogCode.Accepted and dlg.volid:
            self.load(select_iso=dlg.volid if "virtio" not in dlg.volid.lower() else "")

    def get_virtio(self) -> None:
        if not self.iso_storages:
            error(self, "VirtIO drivers", "No storage on this host accepts ISO images.")
            return
        if any("virtio-win.iso" in (self.virtio.itemData(i) or "") for i in range(self.virtio.count())):
            error(self, "VirtIO drivers", "virtio-win.iso is already on the host — choose it in the list.")
            return
        if not confirm(self, "Download the VirtIO drivers disc?",
                       f"The host downloads virtio-win.iso (about 700 MB) from fedorapeople.org into "
                       f"“{self.iso_storages[0]}”.", "Download"):
            return
        pve, node, storage = self.client(), self.current_node(), self.iso_storages[0]

        def job():
            pve.wait_task(node, pve.download_url(node, storage, VIRTIO_URL, "virtio-win.iso"),
                          timeout=DOWNLOAD_TIMEOUT_S, poll=2.0)

        def finished(_r, err):
            if err is not None:
                self.idle()
                error(self, "VirtIO drivers", str(err))
                return
            self.load(select_iso=self.iso.currentData() or "")

        self.busy("The host is downloading virtio-win.iso…")
        self.runner.run(job, finished)

    def upload_iso(self) -> None:
        if not self.iso_storages:
            error(self, "Upload", "No storage on this host accepts ISO images.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Upload an ISO Image", os.path.expanduser("~"),
                                              "ISO images (*.iso *.ISO)")
        if not path:
            return
        try:
            name = upload_name(path)
        except ValueError as e:
            error(self, "Upload", str(e))
            return
        storage = self.iso_storages[0]
        volid = f"{storage}:iso/{name}"
        if self.iso.findData(volid) >= 0:
            error(self, "Upload", f"{name} is already on the host — choose it in the list.")
            return
        size = os.path.getsize(path)
        pve, node = self.client(), self.current_node()
        stop = threading.Event()
        relay = _Relay(self)
        progress = QProgressDialog(f"Uploading {name} to {storage}…", "Cancel", 0, 1000, self)
        progress.setWindowTitle("Upload")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.canceled.connect(stop.set)
        relay.progressed.connect(lambda sent, total: (
            progress.setValue(int(1000 * sent / total) if total else 1000),
            progress.setLabelText(f"Uploading {name} to {storage}…\n{gib(sent)} of {gib(total)}")))
        progress.show()
        self.upload_progress = progress

        def job():
            upid = pve.upload(node, storage, path, progress=relay.progressed.emit, cancelled=stop.is_set)
            pve.wait_task(node, upid, timeout=1800, poll=1.0)  # the host moves the file into place

        def finished(_r, err):
            progress.close()
            if err is not None:
                if not stop.is_set():
                    error(self, "Upload", str(err))
                self.idle()
                return
            self.load(select_iso=volid)

        self.busy(f"Uploading {name} ({gib(size)})…")
        self.runner.run(job, finished)

    # -- creating ----------------------------------------------------------------------------------

    def check(self) -> str:
        name = self.name.text().strip()
        if not VMNAME.match(name):
            return "Choose a name: letters, digits, '-' and '.' (it becomes the VM's name in Proxmox)."
        if not self.storage.currentData():
            return "No storage on this host accepts VM disks."
        if self.from_iso.isChecked() and not self.iso.currentData():
            return "Choose an ISO image (or get one with Download… or Upload…)."
        if self.from_template.isChecked() and self.template.currentData() is None:
            return "Choose a template."
        return ""

    def params(self) -> dict:
        return vm_params(vmid=self.vmid.value(), name=self.name.text().strip(), profile=self.profile.currentData(),
                         iso=self.iso.currentData(), virtio_iso=self.virtio.currentData() or "",
                         cores=self.cores.value(), host_cpu=self.host_cpu.isChecked(), memory=self.memory.value(),
                         disk_gb=self.disk.value(), storage=self.storage.currentData(),
                         bridge=self.bridge.currentText().strip() or "vmbr0", agent=self.agent.isChecked(),
                         onboot=self.onboot.isChecked(), start=self.start.isChecked())

    def create(self) -> None:
        problem = self.check()
        if problem:
            error(self, "New VM", problem)
            return
        pve, node = self.client(), self.current_node()
        vmid, name = self.vmid.value(), self.name.text().strip()
        if self.from_iso.isChecked():
            params = {**self.params(), **self.hw.params(), **self.startup.params()}

            def job():
                pve.wait_task(node, pve.create_vm(node, params), timeout=900)
        else:
            source, full, storage = self.template.currentData(), self.full.isChecked(), self.storage.currentData()
            changes = {k: w.value() for k, w in (("cores", self.cores), ("memory", self.memory))
                       if w.value() != int(self.template_cfg.get(k, -1))}
            if self.onboot.isChecked():
                changes["onboot"] = 1
                changes.update(self.startup.params())
            start = self.start.isChecked()

            def job():
                pve.wait_task(node, pve.clone_vm(node, source, vmid, name, full=full, storage=storage), timeout=3600)
                if changes:
                    pve.update_config(node, "qemu", vmid, changes)
                if start:
                    pve.wait_task(node, pve.guest_action(node, "qemu", vmid, "start"), timeout=300)

        def finished(_r, err):
            if err is not None:
                self.idle()
                error(self, "New VM", str(err))
                return
            self.created = (vmid, name)
            self.accept()

        self.busy(f"Creating VM {vmid} ({name})…")
        self.runner.run(job, finished)
