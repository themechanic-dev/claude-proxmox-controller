"""Renders the app's windows to PNG from demo mode, with no display (Qt "offscreen").

    QT_QPA_PLATFORM=offscreen .venv/bin/python tools/screenshots.py [out-dir] [--light]
"""

import ctypes
import faulthandler
import os
import sys
import tempfile

if sys.platform.startswith("linux"):
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # a crash prints a traceback here, not Ubuntu's error window
faulthandler.enable(all_threads=True)

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
args = [a for a in sys.argv[1:] if not a.startswith("--")]
OUT = os.path.abspath(args[0] if args else os.path.join(ROOT, "docs", "images"))
LIGHT = "--light" in sys.argv
TMP = tempfile.mkdtemp(prefix="pvc-shots-")
os.environ["XDG_CONFIG_HOME"] = TMP
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, ROOT)

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QToolButton  # noqa: E402

from proxmox_controller.core.demo import DEMO_HOSTS, DemoPve  # noqa: E402
from proxmox_controller.ui import guest_dialogs, theme  # noqa: E402
from proxmox_controller.ui.host_dialog import HostDialog  # noqa: E402
from proxmox_controller.ui.main_window import MainWindow  # noqa: E402
from proxmox_controller.ui.settings import SettingsDialog  # noqa: E402
from proxmox_controller.ui.vm_dialog import CreateVmDialog  # noqa: E402

app = QApplication([])
theme.apply(app, dark=not LIGHT)
os.makedirs(OUT, exist_ok=True)
win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)
win.resize(1060, 760)
win.show()
suffix = "-light" if LIGHT else ""


def shot(widget, name):
    path = os.path.join(OUT, f"{name}{suffix}.png")
    widget.grab().save(path)
    print("wrote", path, widget.width(), "x", widget.height(), flush=True)


def wait(ms):
    end = QTimer()
    end.setSingleShot(True)
    end.start(ms)
    while end.isActive():
        app.processEvents()


wait(1500)
view = win.current_view()
view.table.selectRow(1)
wait(300)
shot(win, "main")
from proxmox_controller.ui import bulk  # noqa: E402
dlg = bulk.BulkDialog(win, view.client, win.runner, view.guests, view.details, "shutdown")
dlg.show()
wait(300)
shot(dlg, "bulk-shutdown")
dlg.close()
cluster = DemoPve._clusters[DEMO_HOSTS[0].id]
cluster.long_task("vzdump", 101, ["INFO: starting new backup job: vzdump 101 --storage local --mode snapshot",
                                  "INFO: Starting Backup of VM 101 (lxc)", "INFO:  37% (11.8 GiB of 32.0 GiB) in 1m 2s"])
view.refresh()
wait(800)
view.open_task_log(view.tasks_panel.tasks[0])
wait(1200)
log = view.task_logs[view.tasks_panel.tasks[0]["upid"]]
shot(log, "task-log")
log.close()
win.resize(1060, 980)  # tall enough for the Tasks list under the guests
wait(400)
shot(win, "main-tasks")
win.resize(1060, 760)
wait(200)
g = view.selected()
for cls, name in ((guest_dialogs.EditGuestDialog, "edit"), (guest_dialogs.SnapshotsDialog, "snapshots"),
                  (guest_dialogs.GraphsDialog, "graphs")):
    dlg = cls(win, view.client, win.runner, g)
    dlg.show()
    wait(800)
    shot(dlg, name)
    dlg.close()
vm = next(x for x in view.guests if x["vmid"] == 201)
dlg = guest_dialogs.EditGuestDialog(win, view.client, win.runner, vm)
dlg.show()
wait(800)
shot(dlg, "edit-vm")
dlg.close()
dlg = guest_dialogs.NotesDialog(win, view.client, win.runner, g)
dlg.show()
wait(600)
dlg.editor.setPlainText("# Nextcloud\n\nFamily files and calendars.\n\n- **Address:** https://cloud.home.lan\n"
                        "- Data on `local-lvm`, nightly backup\n- Update **before** the 1st of the month\n\n"
                        "## Accounts\n\n1. admin — in the password manager\n2. family")
wait(400)
shot(dlg, "notes")
dlg.editor.setPlainText(dlg.original)
dlg.close()
dlg = guest_dialogs.CreateContainerDialog(win, view.client, win.runner, view.nodes)
dlg.show()
wait(800)
shot(dlg, "new-container")
dlg.close()
dlg = CreateVmDialog(win, view.client, win.runner, view.nodes)
dlg.show()
wait(800)
dlg.name.setText("web-server")
shot(dlg, "new-vm")
dlg.profile.setCurrentIndex(dlg.profile.findData("win11"))
dlg.name.setText("windows-11")
wait(300)
shot(dlg, "new-vm-windows")
dlg.close()
dlg = HostDialog(win, win.runner, DemoPve, DEMO_HOSTS[0])
dlg.show()
wait(300)
shot(dlg, "host")
dlg.close()
from proxmox_controller.ui import console  # noqa: E402
view.table.selectRow(view._row_of(201))
wait(200)
view.open_builtin_console(view.selected())
cwin = console.OPEN[f"{DEMO_HOSTS[0].id}/201"]
wait(800)
from PySide6.QtTest import QTest  # noqa: E402
for ch in "root":
    QTest.keyClick(cwin.view, ch)
QTest.keyClick(cwin.view, "\r")
for ch in "uptime":
    QTest.keyClick(cwin.view, ch)
wait(500)
shot(cwin, "console")
cwin.close()
view.table.selectRow(view._row_of(101))
wait(200)
dlg = SettingsDialog(win)
dlg.show()
wait(300)
shot(dlg, "settings")
dlg.close()
win.show_help()
wait(300)
shot(win.help_dialog, "help")
win.help_dialog.close()
button = win.current_view().findChild(QToolButton, "menuButton")
win.menu.popup(button.mapToGlobal(button.rect().bottomRight()))
wait(300)
shot(win.menu, "menu")
win.menu.close()
win.show_host("demo-pc")
wait(1200)
shot(win, "second-host")
win.close()
