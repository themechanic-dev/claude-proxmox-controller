"""The windows and dialogs, driven without a screen (Qt's offscreen platform) against the demo cluster.
Questions and warnings that would wait for a click are replaced by recorders. Needs PySide6 (.venv)."""

import json
import os
import sys
import shutil
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QPoint, Qt
    from PySide6.QtGui import QColor, QIcon
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QDialog, QFrame, QLabel, QStyleOptionViewItem, QToolButton
except ImportError:  # pragma: no cover - the core tests still run with plain python3
    QApplication = None

if QApplication is not None:
    from proxmox_controller.core import store
    from proxmox_controller.core import ubuntu_releases
    from proxmox_controller.core import updates as updates_core
    from proxmox_controller.ui import update_window
    from proxmox_controller.core.demo import DEMO_HOSTS, DemoPve
    from proxmox_controller.core.pve import Host, PveError
    from proxmox_controller import app as app_module
    import threading
    from proxmox_controller.core import (autoinstall, claude_access, claude_policy, cloudseed, connector_link,
                                         connector_log, setupdisc, sounds, screen as screen_core, ssh as ssh_core,
                                         vault)
    from proxmox_controller.ui import (backup_jobs, backups, bulk, claude_window, connector, console, geometry,
                                       agent_setup, files_window, graph_wall, guest_dialogs, hazard, host_dialog,
                                       host_shell, host_view, main_window, tasks_panel, theme, vault_dialogs,
                                       vm_dialog, widgets)
    from proxmox_controller.ui.chart import nice_ticks
    from proxmox_controller.ui.host_dialog import HostDialog
    from proxmox_controller.ui.host_view import HostView
    from proxmox_controller.ui.main_window import MainWindow
    from proxmox_controller.ui.worker import Runner

    APP = QApplication.instance() or QApplication([])
    theme.apply(APP, dark=True)


SHORT_TMP = "/tmp" if os.name == "posix" else None  # a Unix socket's path must be short; Windows: its own temp folder


def wait_until(cond, timeout=5.0):
    """Let the event loop run (the API answers arrive through it) until cond() is true. The short sleep lets the
    workers' threads have the GIL: QTest.qWait keeps it while it waits — on Windows a worker then took 5.6 s instead of
    0.05 (measured), and the test gave up. (The app itself waits in exec(), which lets it go.)"""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        time.sleep(0.01)
        QTest.qWait(10)  # (last before the check: what a thread just signalled is delivered first)
        if cond():
            return True
    return bool(cond())


@unittest.skipIf(QApplication is None, "needs PySide6")
class UiCase(unittest.TestCase):
    def setUp(self):
        DemoPve._clusters.clear()  # a fresh pretend cluster for every test
        self.private = tempfile.mkdtemp(dir=SHORT_TMP, prefix="pvc-")  # never the real log, socket or runtime folder
        self.addCleanup(lambda: __import__("shutil").rmtree(self.private, True))
        config, data = os.path.join(self.private, "config"), os.path.join(self.private, "data")
        env = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.private,  # (Windows: APPDATA, LOCALAPPDATA)
                                           "XDG_CONFIG_HOME": config, "APPDATA": config,
                                           "XDG_DATA_HOME": data, "LOCALAPPDATA": data})
        env.start()
        self.addCleanup(env.stop)
        self.errors, self.asked = [], []
        self.answer = True

        def confirm(_parent, title, _text, _action, destructive=False, **_shown):
            self.asked.append(title)
            return self.answer

        def error(_parent, title, text):
            self.errors.append((title, text))

        self.patches = [mock.patch.object(m, "confirm", confirm) for m in (host_view, guest_dialogs, main_window)]
        self.arp = []  # this computer's ARP table, as the tests want it (never the real one)
        self.patches.append(mock.patch.object(host_view.netinfo, "neighbour_lines", lambda: list(self.arp)))
        self.patches += [mock.patch.object(m, "error", error) for m in (host_view, guest_dialogs, host_dialog,
                                                                         vm_dialog, backups)]
        self.patches.append(mock.patch.object(backups, "confirm", confirm))
        self.patches.append(mock.patch.object(backup_jobs, "confirm", confirm))
        self.patches.append(mock.patch.object(backup_jobs, "error", error))
        self.patches.append(mock.patch.object(vm_dialog, "confirm", confirm))
        self.patches.append(mock.patch.object(tasks_panel, "confirm", confirm))
        self.patches.append(mock.patch.object(vault_dialogs, "confirm", confirm))
        self.patches.append(mock.patch.object(claude_window, "confirm", confirm))
        self.patches += [mock.patch.object(files_window, "confirm", confirm), mock.patch.object(files_window, "error", error),
                         mock.patch.object(agent_setup, "error", error)]
        self.patches.append(mock.patch.object(claude_window, "error", error))
        self.patches += [mock.patch.object(m, "error", error) for m in (bulk, tasks_panel)]
        self.infos = []
        self.patches.append(mock.patch.object(guest_dialogs, "info", lambda _p, title, text: self.infos.append(text)))
        self.played = []  # no test ever plays a sound on the desktop: what would play is kept here
        self.patches.append(mock.patch.object(sounds, "play", lambda name: self.played.append(name) or True))
        self.terminals = []  # no test ever opens a real terminal window on the desktop: what would open is kept here
        self.titles = []
        self.patches.append(mock.patch.object(ssh_core, "open_terminal", lambda inner, title="": (
            self.terminals.append(inner), self.titles.append(title))))
        self.patches.append(mock.patch.object(host_shell, "error", error))
        self.patches.append(mock.patch.object(host_shell, "confirm", confirm))
        # nor moves anything into the desktop's Trash, opens a file in its apps or writes its clipboard
        self.trashed, self.trash_works, self.opened, self.clipboard = [], True, [], []
        self.real_to_trash = files_window.to_trash

        def to_trash(path):
            if not self.trash_works:
                return False
            self.trashed.append(path.name)
            shutil.rmtree(path) if path.is_dir() else path.unlink()
            return True
        self.patches.append(mock.patch.object(files_window, "to_trash", to_trash))
        self.patches.append(mock.patch.object(files_window, "QDesktopServices", types.SimpleNamespace(
            openUrl=lambda url: self.opened.append(url.toLocalFile()) or True)))
        self.patches.append(mock.patch.object(files_window, "QGuiApplication", types.SimpleNamespace(
            clipboard=lambda: types.SimpleNamespace(setText=self.clipboard.append))))
        self.copied = ""  # what "this computer has copied", for the console's Paste… (never the real clipboard)
        self.ubuntu_index = None  # Ubuntu's image index as the tests want it (never the network)

        def ubuntu_index():
            if self.ubuntu_index is None:
                raise OSError("no network in tests")
            return self.ubuntu_index
        self.patches.append(mock.patch.object(ubuntu_releases, "fetch_index", ubuntu_index))
        self.patches.append(mock.patch.object(ubuntu_releases, "fetch_size_mb", lambda url: 905))
        self.update_feed = None  # the app's update feed as the tests want it (never the network)

        def update_feed():
            if self.update_feed is None:
                raise OSError("no network in tests")
            return json.dumps(self.update_feed)
        self.patches.append(mock.patch.object(updates_core, "fetch_feed", update_feed))
        self.patches.append(mock.patch.object(updates_core, "how_installed", lambda: "deb"))
        self.patches.append(mock.patch.object(console, "clipboard_text", lambda: self.copied))
        for p in self.patches:
            p.start()
        self.runner = Runner()
        self.notes = []

    def tearDown(self):
        guest_dialogs.close_all_graphs()
        graph_wall.close_all()
        self.runner.close()
        for p in self.patches:
            p.stop()

    def usb_items(self, hw):
        return {hw.usb.item(i).data(Qt.ItemDataRole.UserRole): hw.usb.item(i) for i in range(hw.usb.count())}

    def guest_cfg(self, vmid):
        g = self.cluster().guests[vmid]
        return DemoPve(DEMO_HOSTS[0]).guest_config("pve", g["type"], vmid)

    def cluster(self, host_id="demo-pve"):
        return DemoPve._clusters[host_id]

    def loaded_view(self, make_client=None, prefs=None) -> "HostView":
        self.states, self.saved_prefs = [], 0
        view = HostView(DEMO_HOSTS[0], make_client or DemoPve, self.runner, self.notes.append, lambda h: None,
                        lambda hid, state: self.states.append((hid, state)), prefs=prefs,
                        on_prefs_changed=lambda: setattr(self, "saved_prefs", self.saved_prefs + 1))
        view.resize(1100, 760)
        view.refresh()
        self.assertTrue(wait_until(lambda: view.online is not None))
        return view

    def select(self, view, vmid):
        row = view._row_of(vmid)
        self.assertIsNotNone(row, f"guest {vmid} not in the table")
        view.table.selectRow(row)
        return view.selected()

    def column(self, view, col):
        return [view.table.item(r, col).text() for r in range(view.table.rowCount())]

    def visible_ids(self, view):
        return [int(view.table.item(r, 1).text()) for r in range(view.table.rowCount()) if not view.table.isRowHidden(r)]


class HostViewTest(UiCase):
    def test_storage_cards_like_the_cards_above(self):
        """Each storage a card with a bar, as CPU and Memory (15/10, the user's local, local-lvm and nas): the same
        width each, side by side — and the same cards on the next refresh (no flicker)."""
        DemoPve(DEMO_HOSTS[0]).cluster.network_share = True
        view = self.loaded_view()
        view.show()
        sc = view.storage_cards
        self.assertEqual(list(sc.cards), ["pve/local", "pve/local-lvm", "nas"])  # by name; the NAS is shared
        nas = sc.cards["nas"]
        self.assertEqual((nas.title.text(), nas.value.text(), nas.caption.text()),
                         ("nas (cifs)", "415 GiB", "of 7233 GiB · 6 % used"))
        self.assertTrue(nas.bar.isVisibleTo(nas))
        self.assertIn("holds ISO images", nas.toolTip())
        self.assertIn("6818 GiB free", nas.toolTip())
        QApplication.processEvents()
        self.assertEqual(sc.columns, 3)
        widths = [c.width() for c in sc.cards.values()]
        self.assertLessEqual(max(widths) - min(widths), 1, widths)  # (a pixel left over goes to one of them)
        self.assertGreater(nas.width(), 250)  # a third of the page each
        view.refresh()
        self.assertTrue(wait_until(lambda: not view.inflight))
        self.assertIs(sc.cards["nas"], nas)
        view.close()

    def test_many_storages_four_a_row_all_the_same_width(self):
        """Someone else's host with more storages (the user's question, 15/10): every one shows, four a row."""
        found = [{"storage": f"disk{i}", "type": "zfspool", "used": i << 30, "total": 100 << 30, "shared": 0}
                 for i in range(1, 8)]
        found[6]["storage"] = "disk7-backup-nas-in-the-garage-for-the-old-photos"  # a long name takes no more room
        sc = host_view.StorageCards()
        sc.resize(1000, 400)
        sc.show_entries(host_view.storage_entries({"pve": found}))
        sc.show()
        QApplication.processEvents()
        where = [sc.grid.getItemPosition(sc.grid.indexOf(c))[:2] for c in sc.cards.values()]
        self.assertEqual(where, [(0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (1, 1), (1, 2)])
        widths = [c.width() for c in sc.cards.values()]
        self.assertLessEqual(max(widths) - min(widths), 1, widths)  # (a pixel left over goes to one of them)
        long = sc.cards["pve/disk7-backup-nas-in-the-garage-for-the-old-photos"]
        self.assertTrue(long.title.text().endswith("…"))  # (all of it in the tooltip)
        sc.show_entries(host_view.storage_entries({"pve": found[:2]}))  # storages gone: the cards follow
        QApplication.processEvents()
        self.assertEqual((list(sc.cards), sc.columns), (["pve/disk1", "pve/disk2"], 2))
        self.assertGreater(sc.cards["pve/disk1"].width(), 400)  # two halves now
        sc.show_entries([])
        self.assertTrue(sc.empty.isVisibleTo(sc))
        sc.close()

    def test_storage_entries_for_a_cluster(self):
        """A cluster's shared storage (Ceph, a NAS) once, each node's own with its name; a storage that does not
        answer or is disabled still shows, saying so."""
        e = host_view.storage_entries({
            "pve1": [{"storage": "local", "type": "dir", "used": 1 << 30, "total": 4 << 30, "shared": 0},
                     {"storage": "ceph", "type": "rbd", "used": 2 << 30, "total": 8 << 30, "shared": 1,
                      "content": "images,rootdir"}],
            "pve2": [{"storage": "local", "type": "dir", "used": 3 << 30, "total": 4 << 30, "shared": 0},
                     {"storage": "ceph", "type": "rbd", "used": 2 << 30, "total": 8 << 30, "shared": 1},
                     {"storage": "nas", "type": "nfs", "shared": 1, "active": 0, "total": 0},
                     {"storage": "old", "type": "dir", "enabled": 0, "total": 0}]})
        self.assertEqual([(x["title"], x["caption"]) for x in e], [
            ("ceph (rbd)", "of 8.0 GiB · 25 % used"), ("pve1 · local (dir)", "of 4.0 GiB · 25 % used"),
            ("pve2 · local (dir)", "of 4.0 GiB · 75 % used"), ("nas (nfs)", "Not available"),
            ("pve2 · old (dir)", "Disabled")])
        self.assertIsNone(e[3]["fraction"])  # no bar for what does not answer
        self.assertIn("VM disks, container disks", e[0]["tip"])

    def test_overview_and_table(self):
        view = self.loaded_view()
        self.assertTrue(view.online)
        self.assertEqual(view.pill.text(), "Online")
        self.assertEqual(view.stack.currentIndex(), 1)
        self.assertEqual(view.table.rowCount(), 5)
        self.assertEqual([view.table.item(r, 1).text() for r in range(5)], ["100", "101", "102", "200", "201"])
        self.assertIn("threads", view.cpu_card.caption.text())
        self.assertIn("pve/local-lvm", view.storage_cards.cards)
        self.assertFalse(view.wake_btn.isVisibleTo(view))  # online: no Wake button
        # the guests' addresses arrive a moment later
        self.assertTrue(wait_until(lambda: view.table.item(0, host_view.COL_IP).text() == "192.0.2.10"))

    def test_actions_follow_the_state(self):
        view = self.loaded_view()
        enabled = lambda: {k for k, b in view.act.items() if b.isEnabled()}  # noqa: E731
        self.assertEqual(enabled(), set())  # nothing selected
        self.select(view, 100)  # running container
        self.assertEqual(enabled(), {"shutdown", "stop", "reboot", "console", "files", "edit", "notes", "snapshots",
                                     "backups", "graphs"})
        self.select(view, 102)  # stopped container
        self.assertEqual(enabled(), {"start", "edit", "notes", "snapshots", "backups", "graphs", "delete"})
        self.select(view, 200)  # stopped VM: deleted the same way as a container
        self.assertEqual(enabled(), {"start", "edit", "notes", "snapshots", "backups", "graphs", "delete"})

    def test_boot_column(self):
        view = self.loaded_view()
        boot = lambda vmid: view.table.item(view._row_of(vmid), host_view.COL_BOOT)  # noqa: E731
        self.assertTrue(wait_until(lambda: not boot(100).icon().isNull()))  # pihole starts at boot
        self.assertTrue(boot(102).icon().isNull())  # test-box does not
        self.assertEqual(boot(100).toolTip(), host_view.BOOT_TIP)
        view.table.sortByColumn(host_view.COL_BOOT, Qt.SortOrder.AscendingOrder)
        self.assertEqual(self.column(view, host_view.COL_ID)[:2], ["100", "101"])  # those that start at boot first
        self.select(view, 102)
        view.client().update_config("pve", "lxc", 102, {"onboot": 1, "startup": "order=1,up=15"})  # as Edit would
        view._refresh_details(force=True)
        self.assertTrue(wait_until(lambda: not boot(102).icon().isNull()))
        self.assertEqual(boot(102).text(), "1")
        self.assertIn("order 1, then waits 15 s", boot(102).toolTip())
        view.table.sortByColumn(host_view.COL_BOOT, Qt.SortOrder.AscendingOrder)
        self.assertEqual(self.column(view, host_view.COL_ID)[0], "102")  # order 1 starts first

    def test_columns_spread_with_the_window(self):
        view = self.loaded_view()
        view.show()  # resizes reach a hidden widget's table late
        self.addCleanup(view.close)
        QTest.qWait(30)
        hdr = view.table.horizontalHeader()
        view.resize(1700, 760)
        QTest.qWait(30)
        natural = hdr.sectionSize(host_view.COL_NAME)  # (wide: as much as it wants)
        for width in (850, 1700, 1250):
            view.resize(width, 760)
            QTest.qWait(30)
            used = sum(hdr.sectionSize(c) for c in range(len(host_view.COLUMNS) - 1))
            self.assertLessEqual(abs(view.table.viewport().width() - used), 1, width)  # no gap on the right
            self.assertEqual(view.table.horizontalScrollBar().maximum(), 0, width)  # and nothing cut off
            if width == 850:
                self.assertLess(hdr.sectionSize(host_view.COL_NAME), natural)  # narrow: Name gave way
        self.assertEqual(hdr.sectionSize(host_view.COL_DOT), view.table.iconSize().width() + 14)  # icons stay narrow

    def test_selected_dot_keeps_its_colour(self):
        view = self.loaded_view()
        self.select(view, 100)  # running
        icon = view.table.item(view._row_of(100), 0).icon()
        normal = icon.pixmap(12, 12, QIcon.Mode.Normal).toImage()
        selected = icon.pixmap(12, 12, QIcon.Mode.Selected).toImage()
        self.assertEqual(normal, selected)  # it was tinted white-grey before: a running guest looked stopped
        centre = normal.pixelColor(normal.width() // 2, normal.height() // 2)
        self.assertEqual(centre.name(), theme.colors().success)

    def test_sorting_uses_numbers(self):
        view = self.loaded_view()
        view.table.sortByColumn(host_view.COL_DISK, Qt.SortOrder.DescendingOrder)  # Disk: 64, 40, 32, 8, 4 GiB
        self.assertEqual(self.column(view, 1), ["200", "201", "101", "102", "100"])
        view.table.sortByColumn(host_view.COL_MEM, Qt.SortOrder.DescendingOrder)  # Memory: stopped guests last
        self.assertEqual(self.column(view, 4)[-2:], ["Stopped", "Stopped"])
        view.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)  # the dot: running first
        self.assertEqual(self.column(view, 4)[:3], ["Running"] * 3)
        view.table.sortByColumn(2, Qt.SortOrder.AscendingOrder)
        view.table.sortByColumn(host_view.COL_FILL, Qt.SortOrder.AscendingOrder)  # the empty column keeps the previous order
        self.assertEqual(view.sort, (2, Qt.SortOrder.AscendingOrder))
        self.assertEqual(self.column(view, 2)[0], "nextcloud")
        view.refresh()  # a refresh keeps the order the user chose
        self.assertTrue(wait_until(lambda: not view.inflight))
        self.assertEqual(self.column(view, 2), ["nextcloud", "pihole", "test-box", "ubuntu-desktop", "windows-11"])

    def test_hide_stopped(self):
        prefs = {"hide_stopped": False}
        view = self.loaded_view(prefs=prefs)
        self.assertEqual(view.count.text(), "3 of 5 running")
        self.select(view, 102)
        view.hide_stopped.setChecked(True)
        self.assertEqual(self.visible_ids(view), [100, 101, 201])
        self.assertIsNone(view.selected())  # the hidden row does not stay selected
        self.assertEqual((prefs["hide_stopped"], self.saved_prefs), (True, 1))
        view.table.sortByColumn(2, Qt.SortOrder.DescendingOrder)
        self.assertEqual(self.visible_ids(view), [201, 100, 101])  # still hidden after sorting
        self.select(view, 100)
        view.guest_action("stop")
        self.assertTrue(wait_until(lambda: self.visible_ids(view) == [201, 101]))  # stopped: it disappears

    def test_addresses_tags_and_notes(self):
        view = self.loaded_view()
        view.table.sortByColumn(2, Qt.SortOrder.DescendingOrder)  # rows move: addresses must follow their guest
        ip = lambda vmid: view.table.item(view._row_of(vmid), host_view.COL_IP)  # noqa: E731
        self.assertTrue(wait_until(lambda: ip(201).text() != "—"))
        self.assertEqual(ip(100).text(), "192.0.2.10")  # container: from Proxmox
        self.assertEqual(ip(201).text(), "192.0.2.21")  # VM: from its guest agent, Docker's bridge left out
        self.assertEqual(ip(102).text(), "—")  # stopped
        name = lambda vmid: view.table.item(view._row_of(vmid), 2)  # noqa: E731
        self.assertEqual(name(101).data(host_view.TAGS_ROLE), ["cloud", "prod"])
        self.assertIn("Tags: cloud, prod", name(101).toolTip())
        self.assertIn("DNS for the house", name(100).toolTip())
        self.assertEqual(name(102).toolTip(), "<b>test-box</b>")  # just the name (whole, if the column cuts it)
        delegate = view.table.itemDelegateForColumn(2)
        opt = QStyleOptionViewItem()
        opt.initFrom(view.table)
        tagged = delegate.sizeHint(opt, view.table.model().index(view._row_of(101), 2)).width()
        plain = delegate.sizeHint(opt, view.table.model().index(view._row_of(100), 2)).width()
        self.assertGreater(tagged - plain, 40)  # the tags get their room in the column

    def test_vm_without_agent_found_in_arp_table(self):
        DemoPve(DEMO_HOSTS[0])  # creates the cluster
        self.cluster().guests[201]["agent"] = 0
        self.cluster().guests[200].update(status="running", agent=0)
        mac = self.cluster().mac(201).lower()
        self.arp = [f"192.168.1.106 dev enp5s0 lladdr {mac} REACHABLE",
                    "192.168.1.1 dev enp5s0 lladdr aa:bb:cc:dd:ee:ff STALE"]
        view = self.loaded_view()
        ip = lambda vmid: view.table.item(view._row_of(vmid), host_view.COL_IP)  # noqa: E731
        self.assertTrue(wait_until(lambda: ip(201).text() == "192.168.1.106"))
        self.assertEqual(ip(201).toolTip(), host_view.ARP_TIP)
        self.assertEqual(ip(200).text(), "—")  # not in the table either
        self.assertEqual(ip(200).toolTip(), host_view.NO_AGENT_TIP)

    def test_start_and_stop(self):
        view = self.loaded_view()
        self.select(view, 102)
        view.guest_action("start")
        self.assertEqual(self.asked, [])  # starting needs no question
        self.assertTrue(wait_until(lambda: self.cluster().guests[102]["status"] == "running"))
        self.assertTrue(wait_until(lambda: view.selected() and view.selected()["status"] == "running"))
        self.assertTrue(view.act["stop"].isEnabled())

        self.answer = False  # "Cancel" on the question: nothing is sent
        view.guest_action("stop")
        self.assertEqual(self.asked, ["Stop container 102 now?"])
        QTest.qWait(200)
        self.assertEqual(self.cluster().guests[102]["status"], "running")
        self.answer = "instead"  # "Shut Down Instead": a clean shutdown, not the plug pulled
        view.guest_action("stop")
        self.assertTrue(wait_until(lambda: any("Shutdown sent to container 102" in n for n in self.notes)))
        self.assertTrue(wait_until(lambda: self.cluster().guests[102]["status"] == "stopped"))

        self.answer = True
        view.guest_action("stop")
        self.assertTrue(wait_until(lambda: self.cluster().guests[102]["status"] == "stopped"))

    def test_start_done_with_warnings_is_not_a_failure(self):
        """The user's Windows VM started, yet the app said "The task failed: WARNINGS: 2" (17/10): Proxmox ends a
        task that did its job with warnings that way. No error window; in Tasks it is yellow, not counted as failed."""
        view = self.loaded_view()
        self.cluster().warn_next = ["EFI disk without 'ms-cert=2023k' option, suggesting that not all UEFI 2023",
                                    "ide0: version 0.1.285 of the VirtIO drivers for Windows is known to cause issues"]
        self.select(view, 200)
        view.guest_action("start")
        self.assertTrue(wait_until(lambda: self.cluster().guests[200]["status"] == "running"))
        self.assertTrue(wait_until(lambda: view.tasks_panel.tasks and
                                   view.tasks_panel.tasks[0].get("status") == "WARNINGS: 2"))
        QTest.qWait(100)
        self.assertEqual(self.errors, [])  # no "The task failed" window
        panel = view.tasks_panel
        self.assertEqual(panel.table.item(0, tasks_panel.COL_STATUS).text(), "WARNINGS: 2")
        self.assertEqual(panel.table.item(0, tasks_panel.COL_STATUS).foreground().color().name(),
                         theme.colors().warning)
        self.assertEqual(tasks_panel.status_color(panel.tasks[0]), theme.colors().warning)
        self.assertEqual(panel.summary.text(), "last: VM 200 (windows-11) — Start — OK, with warnings")
        self.assertNotIn("failed", panel.summary.text())

    def test_refused_action_is_shown(self):
        view = self.loaded_view()
        self.cluster().forbidden.add(r"POST /nodes/pve/lxc/\d+/status/.*")
        self.select(view, 102)
        view.guest_action("start")
        self.assertTrue(wait_until(lambda: self.errors))
        self.assertIn("not allowed", self.errors[0][1])

    def test_offline_host_offers_wake(self):
        def dead(host):
            pve = DemoPve(host)
            pve.request = mock.Mock(side_effect=PveError("Could not reach 192.0.2.80:8006: timed out"))
            return pve

        view = self.loaded_view(make_client=dead)
        self.assertIs(view.online, False)
        self.assertEqual(view.pill.text(), "Offline")
        self.assertEqual(self.states, [("demo-pve", "offline")])
        self.assertEqual(view.stack.currentIndex(), 0)
        self.assertIn("Could not reach", view.state_text.text())
        self.assertTrue(view.state_wake.isVisibleTo(view))
        self.assertFalse(view.shutdown_btn.isEnabled())

        with mock.patch.object(host_view.wol, "send", return_value=6) as send:
            view.wake()
            self.assertTrue(wait_until(lambda: view.pill.text() == "Waking…"))
        send.assert_called_once_with("02:00:00:00:00:80", "255.255.255.255")
        self.assertEqual(view.state_title.text(), "Waking up…")

    def test_host_shutdown_asks_first(self):
        view = self.loaded_view()
        self.answer = False
        view.node_command("shutdown")
        self.assertEqual(self.asked, ["Shut down Home server (demo)?"])
        QTest.qWait(200)
        self.assertEqual(self.notes, [])


class FakeGuestSide:
    """The guest's side of Files (core/guestfiles), in memory: what it was asked, and a gate to hold a copy."""

    os_name = "linux"

    def __init__(self):
        from proxmox_controller.core.guestfiles import Entry
        self.Entry = Entry
        self.entries = [Entry("old.txt", False, 5, 0), Entry("docs", True, 0, 0)]
        self.calls, self.gate, self.fail = [], threading.Event(), None
        self.gate.set()

    def home(self):
        return "/home/user"

    def list(self, folder):
        if self.fail:
            raise self.fail
        return folder, list(self.entries)

    def send(self, paths, dest, progress, cancel):
        from proxmox_controller.core.guestfiles import Cancelled
        self.calls.append(("send", [p.name for p in paths], dest))
        for i in range(5):
            while not self.gate.is_set():
                if cancel.is_set():
                    raise Cancelled()
                time.sleep(0.01)
            progress((i + 1) * 100, 500, "network")
        self.entries.append(self.Entry(paths[0].name, False, 1, 0))
        return "network"

    def receive(self, folder, names, dest, progress, cancel, total=None):
        self.calls.append(("receive", folder, list(names), str(dest)))
        (dest / names[0]).write_text("from the guest")
        progress(14, total, "proxmox")
        return "proxmox"

    def rename(self, folder, old, new):
        self.calls.append(("rename", folder, old, new))
        self.entries = [self.Entry(new, e.is_dir, e.size, e.mtime) if e.name == old else e for e in self.entries]

    def delete(self, folder, names):
        self.calls.append(("delete", folder, list(names)))
        self.entries = [e for e in self.entries if e.name not in names]

    def mkdir(self, folder, name):
        self.calls.append(("mkdir", folder, name))
        self.entries.append(self.Entry(name, True, 0, 0))

    def accounts(self):
        return [("root", 0), ("user", 1000)], [("root", 0), ("user", 1000), ("www-data", 33)]

    def put_back(self, path, folder, progress, cancel):
        self.calls.append(("put_back", path.name, folder, path.read_text()))
        progress(path.stat().st_size, path.stat().st_size, "network")
        return "network"

    def set_permissions(self, folder, names, mode, owner, scope="self"):
        self.calls.append(("permissions", folder, list(names), mode, owner, scope))

    def properties(self, folder, names):
        from proxmox_controller.core.guestfiles import Props
        self.calls.append(("properties", folder, list(names)))
        if self.fail:
            raise self.fail
        return [Props(n, "file", 5, mtime=1700000000, uid=1000, gid=1000, mode=0o644, owner="user", group="user")
                if n.endswith(".txt") else
                Props(n, "folder", 3_500_000, 12, 3, mtime=1700000000, uid=0, gid=0, mode=0o755, owner="root",
                      group="root") for n in names]


class FilesWindowTest(UiCase):
    def setUp(self):
        super().setUp()
        self.local = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.local, True)
        (self.local / "new.txt").write_text("new")
        (self.local / "old.txt").write_text("old")
        self.side = FakeGuestSide()
        self.dlg = files_window.FilesWindow(None, "VM 201 (ubuntu)", "", lambda: self.side, self.runner,
                                            local_start=self.local)
        self.assertTrue(wait_until(lambda: self.dlg.remote.folder == "/home/user"))

    def tearDown(self):
        self.side.gate.set()
        self.dlg.close()  # (before the patches stop: a copy still going asks first)
        super().tearDown()

    def choose(self, pane, *names):
        pane.tree.clearSelection()
        for i in range(pane.tree.topLevelItemCount()):
            item = pane.tree.topLevelItem(i)
            if item.data(0, Qt.ItemDataRole.UserRole) in names:
                item.setSelected(True)

    def item(self, pane, name):
        return next(pane.tree.topLevelItem(i) for i in range(pane.tree.topLevelItemCount())
                    if pane.tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole) == name)

    def actions(self, pane):
        return [(a.text(), a.isEnabled()) for a in self.dlg.menu_for(pane).actions() if not a.isSeparator()]

    def settled(self):
        return wait_until(lambda: not self.dlg.busy and self.dlg.cancel is None)

    def test_right_click_menu(self):
        dlg = self.dlg
        dlg.show()
        dlg.local.tree.clearSelection()  # the empty space: the folder itself
        self.assertEqual(self.actions(dlg.local), [("New Folder…", True), ("Refresh", True), ("Copy Path", True),
                                                   ("Properties…", True)])
        self.choose(dlg.local, "new.txt")
        self.assertEqual([t for t, _ in self.actions(dlg.local)],
                         ["Open", "Send  →", "Rename…", "Delete…", "New Folder…", "Refresh", "Copy Path", "Properties…"])
        self.choose(dlg.remote, "old.txt")  # the guest's file: Edit; a Linux guest: Permissions…
        self.assertEqual([t for t, _ in self.actions(dlg.remote)],
                         ["Edit", "←  Receive", "Rename…", "Delete…", "New Folder…", "Refresh", "Copy Path", "Properties…",
                          "Permissions…"])
        self.choose(dlg.remote, "old.txt", "docs")  # two: one name cannot go on both
        self.assertIn(("Rename…", False), self.actions(dlg.remote))
        self.choose(dlg.remote, "docs")
        self.assertEqual(self.actions(dlg.remote)[0], ("Open", True))
        dlg._busy(True)  # the guest's side being read: nothing changes there meanwhile (what reads only, still)
        self.assertEqual([t for t, on in self.actions(dlg.remote) if on], ["Copy Path", "Properties…"])  # (not Permissions…)
        self.assertTrue(all(on for _t, on in self.actions(dlg.local)))
        dlg._busy(False)
        shown = []  # the right click itself: the item under the pointer chosen first, the empty space the folder
        with mock.patch.object(dlg, "menu_for", lambda pane: types.SimpleNamespace(exec=shown.append)):
            QApplication.processEvents()
            dlg._menu(dlg.remote, dlg.remote.tree.visualItemRect(self.item(dlg.remote, "old.txt")).center())
            self.assertEqual([e.name for e in dlg.remote.chosen()], ["old.txt"])
            dlg._menu(dlg.remote, QPoint(5, dlg.remote.tree.viewport().height() - 5))
            self.assertEqual(dlg.remote.chosen(), [])
        self.assertEqual(len(shown), 2)
        keys = {sc.key().toString(): sc for sc in dlg.remote.tree.findChildren(files_window.QShortcut)}
        self.assertEqual(set(keys), {"Del", "F2", "F5", "Alt+Return"})  # FileZilla's keys, on each side's list
        self.choose(dlg.remote, "old.txt")
        self.answer = False
        keys["Del"].activated.emit()
        self.assertEqual(self.asked[-1], "Delete old.txt for good?")
        with mock.patch.object(files_window, "ask_name", return_value="") as ask:
            keys["F2"].activated.emit()
        self.assertEqual(ask.call_args.args[1:], ("Rename", "A new name for old.txt.", "old.txt", "linux"))
        self.assertEqual(self.side.calls, [])  # nothing done: asked, and cancelled
        self.choose(dlg.local, "new.txt")
        dlg.open_item(dlg.local)  # this computer's file: in its own app
        self.assertEqual(self.opened, [str(self.local / "new.txt")])
        self.choose(dlg.remote, "old.txt", "docs")
        dlg.copy_path(dlg.remote)
        self.assertEqual(self.clipboard, ["/home/user/old.txt\n/home/user/docs"])
        self.assertEqual(dlg.result.text(), "Copied: /home/user/old.txt and 1 more")

    def test_rename_delete_and_new_folder_in_the_guest(self):
        dlg = self.dlg
        with mock.patch.object(files_window, "ask_name", side_effect=["notes.txt", "docs", "Νέος φάκελος"]):
            self.choose(dlg.remote, "old.txt")
            dlg.rename_item(dlg.remote)
            self.assertTrue(wait_until(lambda: "notes.txt" in [e.name for e in dlg.remote.entries]))
            self.assertEqual(self.side.calls[-1], ("rename", "/home/user", "old.txt", "notes.txt"))
            self.assertTrue(self.settled())
            self.assertEqual(dlg.result.text(), "Renamed old.txt to notes.txt.")
            self.choose(dlg.remote, "notes.txt")
            dlg.rename_item(dlg.remote)  # a name already there: said, not sent
            self.assertEqual(self.errors[-1], ("Rename", "docs is already in this folder."))
            self.assertEqual(len(self.side.calls), 1)
            dlg.new_folder(dlg.remote)
            self.assertTrue(wait_until(lambda: "Νέος φάκελος" in [e.name for e in dlg.remote.entries]))
            self.assertEqual(self.side.calls[-1], ("mkdir", "/home/user", "Νέος φάκελος"))
        self.assertTrue(self.settled())
        self.answer = False
        self.choose(dlg.remote, "notes.txt", "docs")
        dlg.delete_items(dlg.remote)
        self.assertEqual(self.asked[-1], "Delete 2 items for good?")
        self.assertEqual(self.side.calls[-1][0], "mkdir")  # not deleted
        self.answer = True
        dlg.delete_items(dlg.remote)
        self.assertTrue(wait_until(lambda: [e.name for e in dlg.remote.entries] == ["Νέος φάκελος"]))
        self.assertEqual(self.side.calls[-1], ("delete", "/home/user", ["notes.txt", "docs"]))
        self.assertTrue(self.settled())
        self.assertEqual(dlg.result.text(), "Deleted notes.txt, docs.")
        with mock.patch.object(self.side, "mkdir", side_effect=files_window.GuestError("Making the folder failed: "
                                                                                       "Permission denied")), \
                mock.patch.object(files_window, "ask_name", return_value="x"):
            dlg.new_folder(dlg.remote)
            self.assertTrue(wait_until(lambda: self.errors))
        self.assertEqual(self.errors[-1], ("Files", "Making the folder failed: Permission denied"))
        self.assertTrue(self.settled())

    def test_rename_delete_and_new_folder_on_this_computer(self):
        dlg = self.dlg
        with mock.patch.object(files_window, "ask_name", side_effect=["σημείωση.txt", "Φάκελος", "old.txt"]):
            self.choose(dlg.local, "new.txt")
            dlg.rename_item(dlg.local)
            dlg.new_folder(dlg.local)
            self.choose(dlg.local, "σημείωση.txt")
            dlg.rename_item(dlg.local)
        self.assertEqual(self.errors, [("Rename", "old.txt is already in this folder.")])
        self.assertEqual([e.name for e in dlg.local.entries], ["Φάκελος", "old.txt", "σημείωση.txt"])
        self.assertTrue((self.local / "Φάκελος").is_dir())
        self.answer = False
        self.choose(dlg.local, "old.txt")
        dlg.delete_items(dlg.local)
        self.assertEqual(self.asked[-1], "Move old.txt to the Trash?")
        self.assertTrue((self.local / "old.txt").exists())
        self.answer = True
        dlg.delete_items(dlg.local)
        self.assertEqual(self.trashed, ["old.txt"])
        self.assertFalse((self.local / "old.txt").exists())
        self.assertEqual([e.name for e in dlg.local.entries], ["Φάκελος", "σημείωση.txt"])
        self.trash_works = False  # a place with no Trash: asked again, then deleted for good
        self.choose(dlg.local, "Φάκελος", "σημείωση.txt")
        (self.local / "Φάκελος" / "μέσα.txt").write_text("x")
        dlg.delete_items(dlg.local)
        self.assertEqual(self.asked[-2:], ["Move 2 items to the Trash?", "Delete for good?"])
        self.assertEqual(os.listdir(self.local), [])
        self.assertEqual(dlg.local.entries, [])

    def test_an_older_listing_never_comes_over_a_newer(self):
        """A folder opened while the last one is still read: the older answer, coming after, is not shown."""
        dlg, held, came, real = self.dlg, threading.Event(), threading.Event(), self.side.list

        def listing(folder):
            if folder != "/home/user":
                return real(folder)
            held.wait(5)
            try:
                return real(folder)
            finally:
                came.set()
        self.side.list = listing
        dlg.go_remote("/home/user")
        dlg.go_remote("/home/user/docs")
        self.assertTrue(wait_until(lambda: dlg.remote.folder == "/home/user/docs"))
        self.assertFalse(dlg.busy)  # (what was asked for last has come)
        held.set()  # the older answer comes now
        self.assertTrue(wait_until(came.is_set))
        wait_until(lambda: False, 0.3)  # (and is delivered — wait_until lets the worker run, unlike QTest.qWait)
        self.assertEqual(dlg.remote.folder, "/home/user/docs")
        self.assertFalse(dlg.busy)

    def test_properties(self):
        dlg = self.dlg
        self.assertIn(("Properties…", True), self.actions(dlg.remote))
        self.choose(dlg.remote, "old.txt")
        dlg.properties(dlg.remote)
        win = dlg.props_windows[-1]
        self.assertTrue(wait_until(lambda: "Kind" in win.values))
        self.assertEqual(self.side.calls[-1], ("properties", "/home/user", ["old.txt"]))
        self.assertEqual((win.head.title.text(), win.head.text.text()), ("old.txt", "In /home/user · VM 201"))
        when = files_window.datetime.fromtimestamp(1700000000).strftime("%d/%m/%Y %H:%M:%S")
        self.assertEqual(win.values, {"Kind": "File", "Size": "5 B", "Modified": when, "Owner": "user (1000)",
                                      "Group": "user (1000)", "Permissions": "rw-r--r-- (644)"})
        win.close()
        self.assertEqual(dlg.props_windows, [])
        dlg.remote.tree.clearSelection()  # nothing chosen: the folder itself
        dlg.properties(dlg.remote)
        win = dlg.props_windows[-1]
        self.assertTrue(wait_until(lambda: "Kind" in win.values))
        self.assertEqual(self.side.calls[-1], ("properties", "/home/user", ["."]))
        self.assertEqual((win.head.title.text(), win.head.text.text()), ("user", "/home/user · VM 201"))
        self.assertEqual((win.values["Size"], win.values["Holds"], win.values["Owner"], win.values["Permissions"]),
                         ("3.3 MiB (3,500,000 bytes)", "12 files, 3 folders", "root (0)", "rwxr-xr-x (755)"))
        self.choose(dlg.remote, "old.txt", "docs")  # two: what they make together
        keys = {sc.key().toString(): sc for sc in dlg.remote.tree.findChildren(files_window.QShortcut)}
        keys["Alt+Return"].activated.emit()
        win = dlg.props_windows[-1]
        self.assertTrue(wait_until(lambda: "Chosen" in win.values))
        self.assertEqual(win.head.title.text(), "2 items")
        self.assertEqual(win.values, {"Chosen": "1 file, 1 folder", "Size": "3.3 MiB (3,500,005 bytes)",
                                      "Holds": "13 files, 4 folders"})
        self.side.fail = files_window.GuestError("Reading the properties failed: No such folder")
        dlg.properties(dlg.remote)
        win = dlg.props_windows[-1]
        self.assertTrue(wait_until(lambda: "Error" in win.values))
        self.assertEqual(win.state.text(), "⚠ Reading the properties failed: No such folder")
        self.side.fail = None
        os.chmod(self.local / "new.txt", 0o600)
        self.choose(dlg.local, "new.txt")  # this computer's own
        dlg.properties(dlg.local)
        win = dlg.props_windows[-1]
        self.assertTrue(wait_until(lambda: "Kind" in win.values))
        self.assertEqual((win.values["Size"], win.head.text.text()), ("3 B", f"In {self.local} · this computer"))
        if os.name == "posix":
            self.assertEqual(win.values["Permissions"], "rw------- (600)")

    def test_permissions(self):
        dlg = self.dlg
        self.assertEqual(self.actions(dlg.remote)[-1], ("Permissions…", False))  # (nothing chosen)
        self.assertNotIn("Permissions…", [t for t, _ in self.actions(dlg.local)])  # the guest's side only
        self.choose(dlg.remote, "old.txt", "docs")
        self.assertEqual(self.actions(dlg.remote)[-1], ("Permissions…", True))
        asked = []

        def ask(_parent, title, where, props, users, groups):
            asked.append((title, where, [(p.name, p.mode) for p in props], users[1], groups[2]))
            return ("u+rw,g-w", "", "all")
        with mock.patch.object(files_window, "ask_permissions", ask):
            dlg.permissions(dlg.remote)
            self.assertTrue(wait_until(lambda: self.side.calls and self.side.calls[-1][0] == "permissions"))
        self.assertEqual(asked, [("2 items", "In /home/user · VM 201", [("old.txt", 0o644), ("docs", 0o755)],
                                  ("user", 1000), ("www-data", 33))])
        self.assertEqual(self.side.calls[-1], ("permissions", "/home/user", ["old.txt", "docs"], "u+rw,g-w", "", "all"))
        self.assertTrue(self.settled())
        self.assertEqual(dlg.result.text(), "Permissions set: old.txt, docs.")
        self.assertEqual(dlg.remote.state.text(), "2 items")
        self.assertEqual([e.name for e in dlg.remote.chosen()], ["old.txt", "docs"])  # still chosen, read again
        with mock.patch.object(files_window, "ask_permissions", return_value=None):  # cancelled: nothing set
            dlg.permissions(dlg.remote)
            self.assertTrue(self.settled())
        self.assertEqual(self.side.calls[-1][0], "properties")
        self.side.os_name = "windows"  # a Windows guest: not offered
        self.assertNotIn("Permissions…", [t for t, _ in self.actions(dlg.remote)])

    def saved(self, path, text):
        """As an editor saves: new contents, a new time."""
        path.write_text(text)
        t = time.time_ns() + 2_000_000_000 * (1 + len(self.asked))
        os.utime(path, ns=(t, t))

    def test_edit_as_filezilla(self):
        dlg = self.dlg
        self.choose(dlg.remote, "docs")
        self.assertEqual(self.actions(dlg.remote)[0], ("Open", True))  # a folder: opened, not edited
        self.choose(dlg.remote, "old.txt")
        self.assertEqual(self.actions(dlg.remote)[0], ("Edit", True))
        dlg.edit_item(dlg.remote)
        self.assertTrue(wait_until(lambda: dlg.edits and self.opened))
        ed = dlg.edits[0]
        self.assertEqual(self.opened, [str(ed.path)])  # in this computer's own app
        self.assertEqual((ed.path.name, ed.path.read_text()), ("old.txt", "from the guest"))
        self.assertTrue(ed.path.parent.name.startswith("pvc-edit-"))
        self.assertTrue(dlg.edit_timer.isActive())
        self.assertTrue(self.settled())
        dlg.check_edits()  # not saved yet: nothing asked
        self.assertEqual(self.asked, [])
        self.answer = False
        self.saved(ed.path, "edited")
        dlg.check_edits()
        self.assertEqual(self.asked, ["Send old.txt back?"])
        dlg.check_edits()  # "not now": asked again only when saved again
        self.assertEqual(self.asked, ["Send old.txt back?"])
        self.answer = True
        self.saved(ed.path, "edited again")
        dlg.check_edits()
        self.assertTrue(wait_until(lambda: self.side.calls[-1][0] == "put_back"))
        self.assertEqual(self.side.calls[-1], ("put_back", "old.txt", "/home/user", "edited again"))
        self.assertTrue(self.settled())
        self.assertFalse(ed.changed())
        asked = len(self.asked)
        t = time.time_ns() + 60_000_000_000
        os.utime(ed.path, ns=(t, t))  # saved without a change: nothing asked
        dlg.check_edits()
        self.assertEqual(len(self.asked), asked)
        calls = len(self.side.calls)
        dlg.edit_item(dlg.remote)  # the same file again: its copy opened again, not received again
        self.assertEqual((self.opened[-1], len(self.opened), len(self.side.calls)), (str(ed.path), 2, calls))
        self.saved(ed.path, "not sent")
        self.answer = False
        dlg.close()  # a change not sent back: asked, and kept open
        self.assertEqual(self.asked[-1], "Close without sending back?")
        self.assertTrue(ed.path.exists())
        self.answer = True
        dlg.close()
        self.assertFalse(ed.path.parent.exists())  # the copies go with the window
        self.assertEqual(dlg.edits, [])

    def test_edit_that_cannot_be_received(self):
        dlg, made, real = self.dlg, [], tempfile.mkdtemp

        def mkdtemp(**kw):
            made.append(Path(real(**kw)))
            return str(made[-1])
        self.choose(dlg.remote, "old.txt")
        with mock.patch.object(files_window.tempfile, "mkdtemp", mkdtemp), \
                mock.patch.object(self.side, "receive", side_effect=files_window.GuestError("No such file")):
            dlg.edit_item(dlg.remote)
            self.assertTrue(wait_until(lambda: self.errors))
        self.assertEqual(self.errors[-1], ("Files", "No such file"))
        self.assertEqual((dlg.edits, self.opened), ([], []))
        self.assertFalse(made[0].exists())  # nothing left on this computer

    def test_permissions_window(self):
        Props = files_window.Props
        users, groups = [("root", 0), ("user", 1000)], [("root", 0), ("user", 1000)]
        one = files_window.PermissionsDialog(None, "old.txt", "In /home/user · VM 201",
                                             [Props("old.txt", "file", mode=0o644, owner="user", group="user")],
                                             users, groups)
        self.addCleanup(one.close)
        self.assertEqual(one.number.text(), "644")
        self.assertFalse(one.has_scope)  # a file: nothing inside
        self.assertEqual(one.changes(), ("", "", "self"))  # nothing touched, nothing changes
        one.boxes["ux"].click()
        self.assertEqual(one.number.text(), "744")
        self.assertEqual(one.changes(), ("u+rwx,g+r,g-wx,o+r,o-wx", "", "self"))  # the rights as a whole
        one.number.setText("60")
        one.number.textEdited.emit("60")
        self.assertFalse(one.apply.isEnabled())
        one.number.setText("600")
        one.number.textEdited.emit("600")
        self.assertTrue(one.apply.isEnabled())
        self.assertEqual([k for k, b in one.boxes.items() if b.isChecked()], ["ur", "uw"])
        one.group.setCurrentText("www data")
        self.assertFalse(one.apply.isEnabled())
        one.group.setCurrentText("root")
        one.group.lineEdit().textEdited.emit("root")
        self.assertEqual(one.changes()[1], "user:root")
        many = files_window.PermissionsDialog(None, "2 items", "In /home/user · VM 201",
                                              [Props("a", "folder", mode=0o755, owner="user", group="user"),
                                               Props("b", "file", mode=0o4640, owner="root", group="user")],
                                              users, groups)
        self.addCleanup(many.close)
        self.assertEqual(many.number.text(), "")  # mixed
        self.assertEqual(many.boxes["gx"].checkState(), Qt.CheckState.PartiallyChecked)
        self.assertEqual((many.user.currentText(), many.group.currentText()), ("", "user"))  # owners differ
        self.assertTrue(many.has_scope)
        many.scope.setCurrentIndex(2)
        many.boxes["ow"].click()
        self.assertEqual(many.changes(), ("u+rw,g+r,g-w,o+w", "", "files"))  # the mixed bits left as each is
        texts = [lbl.text() for lbl in many.findChildren(QLabel)]
        self.assertIn("Setuid, setgid and the sticky bit stay as they are.", texts)

    @unittest.skipUnless(sys.platform.startswith("linux"), "elsewhere it would be the real Trash")
    def test_this_computers_trash(self):
        home = Path(self.private) / "home"  # (a Trash of the test's own: never the user's)
        data = home / ".local" / "share"
        data.mkdir(parents=True)
        f = home / "Σημείωση.txt"
        f.write_text("x")
        with mock.patch.dict(os.environ, {"HOME": str(home), "XDG_DATA_HOME": str(data)}):
            self.assertTrue(self.real_to_trash(f))
        self.assertFalse(f.exists())
        self.assertEqual((data / "Trash" / "files" / "Σημείωση.txt").read_text(), "x")

    def test_name_dialog(self):
        dlg = files_window.NameDialog(None, "Rename", "A new name for report.txt.", "report.txt", "windows")
        self.addCleanup(dlg.close)
        self.assertEqual(dlg.name.selectedText(), "report")  # without its extension, as file managers do
        self.assertTrue(dlg.ok.isEnabled())
        dlg.name.setText("a:b?")
        self.assertFalse(dlg.ok.isEnabled())
        self.assertEqual(dlg.problem.text(), "A name cannot hold ':' '?'.")
        dlg.name.setText("name. ")
        self.assertFalse(dlg.ok.isEnabled())
        dlg = files_window.NameDialog(None, "New Folder", "A folder in /home/user.", "New folder", "linux")
        self.addCleanup(dlg.close)
        self.assertEqual(dlg.name.selectedText(), "New folder")
        dlg.name.setText("a:b?")
        self.assertTrue(dlg.ok.isEnabled())  # Linux takes it

    def test_send_and_receive(self):
        dlg = self.dlg
        self.assertEqual(dlg.remote.subtitle.text(), "Linux · as root")
        self.assertEqual([e.name for e in dlg.local.entries], ["new.txt", "old.txt"])
        self.assertEqual([e.name for e in dlg.remote.entries], ["old.txt", "docs"])
        self.choose(dlg.local, "new.txt")
        dlg.send_btn.click()
        self.assertTrue(wait_until(lambda: dlg.result.text().startswith("Done")))
        self.assertEqual(self.side.calls[-1], ("send", ["new.txt"], "/home/user"))
        self.assertIn("over the network", dlg.result.text())
        self.assertTrue(wait_until(lambda: "new.txt" in [e.name for e in dlg.remote.entries]))  # read again
        self.assertFalse(dlg.progress_card.isVisibleTo(dlg))
        self.choose(dlg.local, "old.txt")
        self.answer = False
        dlg.send_btn.click()  # already there: asked first, and not sent
        self.assertEqual(self.asked[-1], "Replace?")
        self.assertEqual(len(self.side.calls), 1)
        self.answer = True
        self.choose(dlg.remote, "old.txt")
        dlg.receive_btn.click()  # here too: replaced once asked
        self.assertTrue(wait_until(lambda: dlg.result.text().startswith("Done")))
        self.assertEqual(self.side.calls[-1], ("receive", "/home/user", ["old.txt"], str(self.local)))
        self.assertEqual((self.local / "old.txt").read_text(), "from the guest")
        self.assertIn("through Proxmox (slow)", dlg.result.text())
        self.assertTrue(wait_until(lambda: dlg.cancel is None))
        dlg.remote.tree.clearSelection()
        dlg.receive_btn.click()
        self.assertEqual(self.errors[-1], ("Receive", "Choose what to receive on the right first."))

    def test_drag_from_one_side_to_the_other(self):
        dlg = self.dlg
        self.choose(dlg.local, "new.txt")
        dlg.remote.tree.dropped.emit("local", [])  # dropped on the guest's side: Send
        self.assertTrue(wait_until(lambda: self.side.calls and self.side.calls[-1][0] == "send"))
        self.assertTrue(wait_until(lambda: dlg.cancel is None))
        dlg.remote.tree.dropped.emit("desktop", [str(self.local / "old.txt")])  # from the desktop's file manager
        self.assertTrue(wait_until(lambda: len(self.side.calls) == 2))
        self.assertEqual(self.side.calls[-1], ("send", ["old.txt"], "/home/user"))
        self.assertEqual(self.asked[-1], "Replace?")
        self.assertTrue(wait_until(lambda: dlg.cancel is None))
        self.choose(dlg.remote, "old.txt")
        dlg.local.tree.dropped.emit("remote", [])  # dropped on this computer's side: Receive
        self.assertTrue(wait_until(lambda: self.side.calls[-1][0] == "receive"))
        mime = dlg.local.tree.mimeData([])
        self.assertEqual(bytes(mime.data(files_window.MIME)).decode(), "local")

    def test_progress_cancel_and_folders(self):
        dlg = self.dlg
        self.side.gate.clear()
        self.choose(dlg.local, "new.txt")
        dlg.send_btn.click()
        self.assertTrue(wait_until(lambda: dlg.progress_card.isVisibleTo(dlg) and dlg.stop_btn.isEnabled()))
        self.assertFalse(dlg.send_btn.isEnabled())  # one copy at a time
        dlg.stop_btn.click()
        self.assertTrue(wait_until(lambda: dlg.result.text() == "Cancelled."))
        self.side.gate.set()
        self.side.calls.clear()
        dlg.remote.tree.itemDoubleClicked.emit(dlg.remote.tree.topLevelItem(1), 0)  # docs: opened
        self.assertTrue(wait_until(lambda: dlg.remote.folder == "/home/user/docs"))
        dlg.remote.up.click()
        self.assertTrue(wait_until(lambda: dlg.remote.folder == "/home/user"))
        self.side.fail = files_window.GuestError("No such folder")
        dlg.go_remote("/nope")
        self.assertTrue(wait_until(lambda: self.errors))
        self.assertEqual(self.errors[-1], ("Files", "No such folder"))
        self.assertEqual(files_window.file_size(1536), "1.5 KiB")
        self.assertEqual(files_window.file_size(500), "500 B")


class AgentSetupTest(UiCase):
    """Install Guest Agent, on the pretend cluster: what is turned on, what is typed into the console, the password
    and Windows' Yes passed from the window, the restart, and the wait for the agent."""

    def client(self):
        return DemoPve(DEMO_HOSTS[0])

    def guest(self, vmid):
        return next(g for g in self.client().guests() if g["vmid"] == vmid)

    def setUp(self):
        super().setUp()
        self.client()
        for patch in (mock.patch.object(agent_setup, "POLL_S", 0.05), mock.patch.object(screen_core, "KEY_GAP_S", 0.0)):
            patch.start()  # (typing a whole command key by key takes seconds on a real console)
            self.addCleanup(patch.stop)

    def cluster(self):
        return DemoPve._clusters["demo-pve"]

    def typed(self):
        """Everything typed into any of the VM's consoles, as text (keys pressed down)."""
        out = []
        for server in self.cluster().consoles:
            for k in server.keys:
                if k[1]:
                    out.append(chr(k[2]) if k[2] < 0x10000 and k[2] < 0xFF00 else f"<{k[2]:x}>")
        return "".join(out)

    def test_linux_with_the_agent_on_but_silent(self):
        self.cluster().guests[201]["agent_down"] = True
        dlg = agent_setup.AgentSetupDialog(None, self.client, self.runner, self.guest(201))
        self.addCleanup(dlg.close)
        self.assertTrue(wait_until(lambda: dlg.install_btn.isEnabled()))
        self.assertTrue(dlg.steps[0].text().startswith("—"))  # already on
        dlg.install_btn.click()
        self.assertTrue(wait_until(lambda: dlg.password.isVisibleTo(dlg)))
        self.assertIn("apt-get install -y qemu-guest-agent", self.typed())
        self.assertFalse(dlg.restart_btn.isVisibleTo(dlg))  # it was on: no restart needed
        dlg.password.setText("pw1")
        dlg.type_password.click()
        self.assertTrue(wait_until(lambda: self.typed().endswith("pw1<ff0d>")))
        self.assertEqual(dlg.password.text(), "")  # not kept
        self.cluster().guests[201]["agent_down"] = False
        self.assertTrue(wait_until(lambda: dlg.status.text().startswith("✓"), 10))
        self.assertTrue(all(s.text()[0] in "✓—" for s in dlg.steps))
        self.assertFalse(dlg.need.isVisibleTo(dlg))  # what the console must show is past

    def test_nothing_squeezed_over_the_picture(self):
        """26/10, the live test on Windows: the steps came after the window opened, it stayed as tall as before, and
        the note under the console's picture lay over it."""
        g = self.cluster().guests[200]
        g.update(status="running", agent=1, agent_down=True)
        g.setdefault("extra", {}).update(ostype="win11")
        dlg = agent_setup.AgentSetupDialog(None, self.client, self.runner, self.guest(200))
        self.addCleanup(dlg.close)
        dlg.show()
        self.assertTrue(wait_until(lambda: dlg.install_btn.isEnabled() and not dlg.shot.isNull()))
        QApplication.processEvents()
        lay = dlg.layout()
        self.assertGreaterEqual(dlg.height(), lay.totalHeightForWidth(dlg.width()) if lay.hasHeightForWidth()
                                else lay.minimumSize().height())
        self.assertLessEqual(dlg.picture.geometry().bottom(), dlg.need.geometry().top())  # one under the other
        pm = dlg.picture.pixmap()
        self.assertLessEqual((pm.width(), pm.height()), (dlg.picture.width(), dlg.picture.height()))
        self.assertTrue(dlg.need.isVisibleTo(dlg))  # (before the install: it says what the console must show)

    def test_linux_with_the_agent_off_restarts_once(self):
        self.cluster().guests[201]["agent"] = 0
        dlg = agent_setup.AgentSetupDialog(None, self.client, self.runner, self.guest(201))
        self.addCleanup(dlg.close)
        self.assertTrue(wait_until(lambda: dlg.install_btn.isEnabled()))
        dlg.install_btn.click()
        self.assertTrue(wait_until(lambda: dlg.restart_btn.isVisibleTo(dlg)))
        self.assertIn("at the next start", dlg.steps[0].text())
        self.assertEqual(self.cluster().guests[201].get("agent_next"), 1)  # turned on, waiting for the restart
        dlg.restart_btn.click()
        self.assertTrue(wait_until(lambda: dlg.status.text().startswith("✓"), 10))
        self.assertEqual(self.cluster().guests[201]["agent"], 1)

    def test_windows_puts_the_drivers_disc_in_and_presses_yes(self):
        g = self.cluster().guests[200]
        g.update(status="running", agent=1, agent_down=True)
        g.setdefault("extra", {}).update(ostype="win11", ide2="local:iso/ubuntu-24.04.1-live-server-amd64.iso,media=cdrom")
        dlg = agent_setup.AgentSetupDialog(None, self.client, self.runner, self.guest(200))
        self.addCleanup(dlg.close)
        self.assertTrue(wait_until(lambda: dlg.install_btn.isEnabled()))
        self.assertIn("Windows", dlg.who.text())
        dlg.install_btn.click()
        self.assertTrue(wait_until(lambda: dlg.yes_btn.isVisibleTo(dlg), 15))
        self.assertIn("local:iso/virtio-win.iso", self.cluster().isos)  # downloaded onto the host
        self.assertEqual(g["extra"]["ide2"], "local:iso/virtio-win.iso,media=cdrom")  # in the existing drive, at once
        self.assertIn("virtio-win-guest-tools.exe", self.typed())
        before = len(self.typed())
        dlg.yes_btn.click()
        self.assertTrue(wait_until(lambda: len(self.typed()) > before))
        self.assertIn("y", self.typed()[before:])  # Alt+Y
        g["agent_down"] = False
        self.assertTrue(wait_until(lambda: dlg.status.text().startswith("✓"), 10))

    def test_nothing_to_do_when_it_answers(self):
        dlg = agent_setup.AgentSetupDialog(None, self.client, self.runner, self.guest(201))
        self.addCleanup(dlg.close)
        self.assertTrue(wait_until(lambda: dlg.status.text().startswith("✓")))
        self.assertFalse(dlg.install_btn.isEnabled())

    def test_files_offers_the_agent_when_it_is_silent(self):
        self.cluster().guests[201]["agent_down"] = True
        view = self.loaded_view()
        self.addCleanup(view.close)
        self.assertTrue(wait_until(lambda: 201 in view.details))
        self.assertTrue(view._agent_missing(self.guest(201)))
        self.assertFalse(view._agent_missing(self.guest(100)))  # a container: no agent to miss
        opened = []
        with mock.patch.object(agent_setup, "AgentSetupDialog", lambda *a: opened.append(a[3]["vmid"]) or mock.Mock()):
            self.answer = True
            view.open_files(self.guest(201))
        self.assertEqual((self.asked[-1], opened), ("Install the guest agent?", [201]))

    def test_files_opens_its_window(self):
        """The Files button opens the window — for a VM, and for a container over the host's SSH (26/10: it opened
        nothing after the new head went in, an error before the window was made)."""
        view = self.loaded_view()
        self.addCleanup(view.close)
        self.assertTrue(wait_until(lambda: 201 in view.details))
        made = []

        def window(*a, **kw):
            made.append((a[1], kw.get("guest", {}).get("vmid")))
            return mock.Mock()
        with mock.patch.object(files_window, "FilesWindow", window):
            self.select(view, 201)
            view.act["files"].click()
            self.assertEqual(made, [("VM 201 (ubuntu-desktop)", 201)])  # with its card
            with mock.patch.object(view, "_with_ssh", lambda then: then()), \
                    mock.patch.object(host_shell, "settings_of", lambda host: {"key": True}):
                view.open_files(self.guest(100))
            self.assertEqual(made[-1][1], 100)

    def test_install_guest_agent_in_the_row(self):
        """The user's choice, 24/10: in the row of buttons — which takes a second row where the window is too narrow."""
        self.cluster().guests[201]["agent_down"] = True
        view = self.loaded_view()
        self.addCleanup(view.close)
        self.assertTrue(wait_until(lambda: 201 in view.details))
        self.select(view, 201)
        self.assertTrue(view.act["agent"].isEnabled())  # a running VM whose agent is silent
        self.select(view, 100)
        self.assertFalse(view.act["agent"].isEnabled())  # a container has no agent
        self.select(view, 201)
        opened = []
        with mock.patch.object(agent_setup, "AgentSetupDialog", lambda *a: opened.append(a[3]["vmid"]) or mock.Mock()):
            view.act["agent"].click()
        self.assertEqual(opened, [201])
        self.cluster().guests[201]["agent_down"] = False
        view._refresh_details(force=True)
        self.assertTrue(wait_until(lambda: not view.act["agent"].isEnabled()))  # it answers now: nothing to install

    def test_the_buttons_take_a_second_row_when_narrow(self):
        view = self.loaded_view()
        view.show()
        self.addCleanup(view.close)
        rows = []
        for width in (1700, 1060, 1700):
            view.resize(width, 760)
            QTest.qWait(40)
            bottom = max(b.mapTo(view, b.rect().bottomLeft()).y() for b in view.act.values())
            self.assertLess(bottom, view.table.mapTo(view, QPoint(0, 0)).y(), width)  # never over the list
            rows.append(view.actions.rows())
            groups = {k: view.act[k].parentWidget() for k in ("shutdown", "stop", "files", "agent", "edit", "graphs")}
            self.assertIs(groups["shutdown"], groups["stop"])  # a group moves down whole
            self.assertIs(groups["files"], groups["agent"])
            self.assertIs(groups["edit"], groups["graphs"])
        self.assertEqual(rows, [1, 2, 1])  # and back to one when it is wide again


class GuestDialogsTest(UiCase):
    def client(self):
        return DemoPve(DEMO_HOSTS[0])

    def guest(self, vmid):
        pve = self.client()
        return next(g for g in pve.guests() if g["vmid"] == vmid)

    def test_edit_container(self):
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(102))
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.original))
        self.assertEqual((dlg.name.text(), dlg.cores.value(), dlg.memory.value()), ("test-box", 1, 1024))
        self.assertTrue(dlg.dhcp.isChecked())
        self.assertEqual(dlg.changes(), {})
        dlg.cores.setValue(3)
        dlg.grow.setValue(2)
        dlg.static.setChecked(True)
        dlg.ip.setText("192.168.1.50")  # no prefix
        dlg.save()
        self.assertIn("prefix", self.errors[-1][1])
        dlg.ip.setText("192.168.1.50/24")
        dlg.gw.setText("192.168.1.1")
        self.assertEqual(dlg.changes(), {"cores": 3, "net0": "name=eth0,bridge=vmbr0,ip=192.168.1.50/24,gw=192.168.1.1"})
        dlg.save()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        g = self.cluster().guests[102]
        self.assertEqual((g["cores"], g["disk_gb"]), (3, 10))
        self.assertIn("ip=192.168.1.50/24", g["net0"])

    def test_edit_vm_sound_and_usb(self):
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(201))  # running, SPICE
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.original))
        hw = dlg.hw
        self.assertEqual((hw.display.currentData(), hw.sound.currentData()), ("qxl", ""))  # no sound card yet
        hw.sound.setCurrentIndex(hw.sound.findData("ich9-intel-hda"))
        self.usb_items(hw)["046d:c52b"].setCheckState(Qt.CheckState.Checked)
        self.assertEqual(dlg.changes(), {"audio0": "device=ich9-intel-hda,driver=spice", "usb0": "host=046d:c52b"})
        dlg.save()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertEqual(len(self.infos), 1)
        self.assertIn("Sound", self.infos[0])  # the running VM hears it after a restart: said so
        self.assertNotIn("USB", self.infos[0])  # USB is plugged in at once

        again = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(201))
        self.assertTrue(wait_until(lambda: again.isEnabled() and again.original))
        self.assertEqual(again.hw.sound.currentData(), "ich9-intel-hda")
        self.assertEqual(again.hw.chosen(), ["046d:c52b"])
        again.hw.sound.setCurrentIndex(0)
        self.usb_items(again.hw)["046d:c52b"].setCheckState(Qt.CheckState.Unchecked)
        self.assertEqual(again.changes(), {"delete": "audio0,usb0"})

    def test_edit_vm_usb_tablet(self):
        """The Pointer row: the tablet as the VM has it (Proxmox's default where it is not set — off with SPICE), and
        set outright when the display changes to SPICE, which would drop it."""
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(201))  # running, SPICE, unset
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.original))
        self.assertTrue(dlg.hw.form.isRowVisible(dlg.hw.tablet))
        self.assertFalse(dlg.hw.tablet.isChecked())
        self.assertEqual(dlg.changes(), {})
        dlg.hw.tablet.setChecked(True)
        self.assertEqual(dlg.changes(), {"tablet": 1})
        dlg.save()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertEqual(self.cluster().guests[201]["extra"]["tablet"], "1")
        self.assertEqual(self.infos, [])  # plugged in at once (USB hotplug): nothing waits for a restart
        self.assertEqual(self.client().monitor("pve", 201, "info mice").splitlines()[-1],
                         "* Mouse #3: QEMU HID Tablet (absolute)")

        self.cluster().guests[200]["spice"] = False  # the default display: Proxmox's tablet is on
        sw = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(200))
        self.assertTrue(wait_until(lambda: sw.isEnabled() and sw.original))
        self.assertTrue(sw.hw.tablet.isChecked())
        sw.hw.display.setCurrentIndex(sw.hw.display.findData("qxl"))
        self.assertEqual(sw.changes(), {"vga": "qxl", "tablet": 1})  # kept through the change to SPICE
        sw.hw.tablet.setChecked(False)
        self.assertEqual(sw.changes(), {"vga": "qxl"})  # (SPICE leaves it out anyway)
        sw.reject()

        self.cluster().guests[201]["extra"]["tablet"] = "0"  # set off outright: left as it is
        off = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(201))
        self.assertTrue(wait_until(lambda: off.isEnabled() and off.original))
        self.assertFalse(off.hw.tablet.isChecked())
        off.hw.display.setCurrentIndex(off.hw.display.findData("std"))
        self.assertEqual(off.changes(), {"delete": "vga"})
        off.reject()

    def test_edit_vm_unplugged_device_and_limit(self):
        self.client()
        self.cluster().guests[200]["extra"] = {"usb0": "host=1234:abcd"}  # set up, but not plugged in now
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(200))
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.original))
        items = self.usb_items(dlg.hw)
        self.assertIn("not plugged in", items["1234:abcd"].text())
        self.assertEqual(items["1234:abcd"].checkState(), Qt.CheckState.Checked)
        self.assertEqual(dlg.changes(), {})  # nothing touched, nothing sent
        dlg.usb_limit = 2
        dlg.hw.spice_usb.setChecked(True)  # 1 device + 2 SPICE ports > 2
        dlg.save()
        self.assertIn("at most 2", self.errors[-1][1])

    def test_start_order_in_edit(self):
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(100))  # starts at boot
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.original))
        self.assertTrue(dlg.startup.form.isRowVisible(dlg.startup.row))
        dlg.startup.order.setValue(1)
        dlg.startup.up.setValue(30)
        self.assertEqual(dlg.changes(), {"startup": "order=1,up=30"})
        dlg.save()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertEqual(self.guest_cfg(100)["startup"], "order=1,up=30")
        again = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(100))
        self.assertTrue(wait_until(lambda: again.isEnabled() and again.original))
        self.assertEqual((again.startup.order.value(), again.startup.up.value()), (1, 30))
        again.startup.order.setValue(0)
        again.startup.up.setValue(0)
        self.assertEqual(again.changes(), {"delete": "startup"})  # nothing left: the setting goes

    def test_start_order_shows_only_with_start_at_boot(self):
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(102))  # does not
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.original))
        form = dlg.startup.form
        self.assertFalse(form.isRowVisible(dlg.startup.row))
        dlg.onboot.setChecked(True)
        self.assertTrue(form.isRowVisible(dlg.startup.row))
        self.assertTrue(form.isRowVisible(dlg.startup.down))

    def test_start_order_for_new_guests(self):
        dlg = guest_dialogs.CreateContainerDialog(None, self.client, self.runner, ["pve"])
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.template.count()))
        dlg.hostname.setText("web-2")
        dlg.password.setText("abcdef")
        dlg.password2.setText("abcdef")
        dlg.startup.order.setValue(2)
        self.assertIsInstance(dlg.params(), dict)  # a complete form
        self.assertNotIn("startup", dlg.params())  # not started at boot: no order sent
        dlg.onboot.setChecked(True)
        self.assertEqual(dlg.params()["startup"], "order=2")
        vm = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"])
        self.assertTrue(wait_until(lambda: vm.isEnabled() and vm.iso.count()))
        vm.unattended.setChecked(False)  # (installed by hand)
        vm.onboot.setChecked(True)
        vm.startup.order.setValue(3)
        vm.startup.up.setValue(20)
        vm.name.setText("vm-3")
        vm.create()
        self.assertTrue(wait_until(lambda: vm.result() == vm.DialogCode.Accepted))
        self.assertEqual(self.cluster().guests[103]["cfg"]["startup"], "order=3,up=20")

    def test_new_guests_default_to_the_hosts_own_disk(self):
        """A NAS share that takes disks too, listed first by Proxmox: the windows still offer local-lvm first
        (the user's New VM showed local-lvm once and nas the next time, 15/10) — and the NAS stays there to pick."""
        DemoPve(DEMO_HOSTS[0]).cluster.network_share = True
        for _ in range(2):  # the same each time it opens
            vm = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"])
            self.assertTrue(wait_until(lambda: vm.isEnabled() and vm.storage.count()))
            self.assertEqual([vm.storage.itemData(i) for i in range(vm.storage.count())], ["local-lvm", "nas"])
            self.assertEqual(vm.storage.currentData(), "local-lvm")
            vm.close()
        ct = guest_dialogs.CreateContainerDialog(None, self.client, self.runner, ["pve"])
        self.assertTrue(wait_until(lambda: ct.isEnabled() and ct.storage.count()))
        self.assertEqual(ct.storage.currentData(), "local-lvm")
        ct.close()

    def test_container_edit_has_no_vm_hardware(self):
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(100))
        self.assertIsNone(dlg.hw)

    def test_edit_keeps_the_mac_address(self):
        self.client()  # creates the cluster
        self.cluster().guests[102]["net0"] = "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=dhcp"
        dlg = guest_dialogs.EditGuestDialog(None, self.client, self.runner, self.guest(102))
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.original))
        dlg.static.setChecked(True)
        dlg.ip.setText("10.0.0.5/24")
        self.assertIn("hwaddr=BC:24:11:00:00:02", dlg.changes()["net0"])

    def test_notes_window(self):
        dlg = guest_dialogs.NotesDialog(None, self.client, self.runner, self.guest(201))
        self.assertTrue(wait_until(lambda: dlg.loaded))
        self.assertEqual(dlg.editor.toPlainText(), "build machine")
        self.assertFalse(dlg.dirty())
        text = "# Build box\n\n- **Ubuntu** 24.04\n- [docs](https://example.org)"
        dlg.editor.setPlainText(text)
        self.assertTrue(dlg.windowTitle().startswith("• "))  # unsaved
        self.assertTrue(wait_until(lambda: "Build box" in dlg.preview.toPlainText()))
        self.assertNotIn("#", dlg.preview.toPlainText())  # shown as Proxmox shows it, not as typed
        self.assertNotIn("**", dlg.preview.toPlainText())
        dlg.save(close=False)  # what Ctrl+S does
        self.assertTrue(wait_until(lambda: not dlg.dirty() and dlg.isEnabled()))
        self.assertEqual(dlg.status.text(), "Saved.")
        self.assertEqual(self.cluster().guests[201]["description"], text)
        self.assertFalse(dlg.windowTitle().startswith("• "))
        dlg.editor.setPlainText("  \n")  # emptied: removed in Proxmox, not saved as blank
        dlg.save(close=True)
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertEqual(self.cluster().guests[201]["description"], "")

    def test_notes_ask_before_losing_changes(self):
        dlg = guest_dialogs.NotesDialog(None, self.client, self.runner, self.guest(100))
        self.assertTrue(wait_until(lambda: dlg.loaded))
        closed = []
        dlg.rejected.connect(lambda: closed.append(True))
        dlg.editor.setPlainText("changed")
        self.answer = False
        dlg.reject()
        self.assertEqual((self.asked, closed), (["Discard the changes?"], []))
        self.answer = True
        dlg.reject()
        self.assertEqual(closed, [True])
        self.assertEqual(self.cluster().guests[100]["description"], "DNS for the house")  # nothing was saved

    def test_notes_change(self):
        self.assertEqual(guest_dialogs.notes_change("x"), {"description": "x"})
        self.assertEqual(guest_dialogs.notes_change(" \n"), {"delete": "description"})

    def test_snapshots(self):
        dlg = guest_dialogs.SnapshotsDialog(None, self.client, self.runner, self.guest(101))
        self.assertTrue(wait_until(lambda: dlg.list.count() == 1))
        self.assertFalse(dlg.rollback_btn.isEnabled())
        dlg.snap_name.setText("1bad name")
        dlg.take()
        self.assertEqual(self.errors[-1][0], "Snapshot")
        dlg.snap_name.setText("before-change")
        dlg.take()
        self.assertTrue(wait_until(lambda: dlg.list.count() == 2))
        dlg.list.setCurrentRow(0)
        self.assertTrue(dlg.rollback_btn.isEnabled())
        self.answer = False
        dlg.delete()
        QTest.qWait(150)
        self.assertEqual(len(self.cluster().snaps[101]), 2)
        self.answer = True
        dlg.list.setCurrentRow(0)
        dlg.delete()
        self.assertTrue(wait_until(lambda: dlg.list.count() == 1))

    def test_graphs_pick_a_unit(self):
        dlg = guest_dialogs.GraphsDialog(None, self.client, self.runner, self.guest(100))  # 512 MiB guest
        self.assertTrue(wait_until(lambda: dlg.mem.points))
        self.assertTrue(dlg.frame_buttons["hour"].isChecked())
        self.assertIn("MiB", dlg.mem.short(256))
        self.assertTrue(dlg.cpu.points)
        dlg.load("week")
        self.assertTrue(dlg.frame_buttons["week"].isChecked() and not dlg.frame_buttons["hour"].isChecked())

    def test_graphs_window_is_free_and_live(self):
        dlg = guest_dialogs.show_graphs("h/100", self.client, self.runner, self.guest(100), "Home")
        self.assertTrue(wait_until(lambda: dlg.mem.points))
        self.assertIsNone(dlg.parentWidget())  # its own window: GNOME does not pin it to the main one
        self.assertFalse(dlg.isModal())
        self.assertTrue(dlg.windowTitle().endswith("— Home"))
        self.assertIs(guest_dialogs.show_graphs("h/100", self.client, self.runner, self.guest(100), "Home"), dlg)
        other = guest_dialogs.show_graphs("h/101", self.client, self.runner, self.guest(101), "Home")
        self.assertIsNot(other, dlg)  # one per guest, several at once
        small = dlg.cpu.height()
        dlg.resize(1600, 1100)  # a whole screen
        QTest.qWait(50)
        self.assertGreater(dlg.cpu.height(), small * 2)  # the charts take the room
        self.assertEqual(dlg.cpu.min_left, dlg.mem.min_left)  # one time axis for both charts
        self.assertGreaterEqual(dlg.cpu.min_left, dlg.cpu.scale()[3])
        self.assertEqual(dlg.timer.interval(), 60_000)  # Hour: every minute
        dlg.load("week")
        self.assertEqual(dlg.timer.interval(), 1_800_000)
        calls = []
        with mock.patch.object(DemoPve, "rrd", side_effect=lambda *a: calls.append(a) or []):
            dlg.timer.timeout.emit()  # what the timer does by itself
            self.assertTrue(wait_until(lambda: calls and not dlg.loading))
        self.assertEqual(calls[0][3], "week")
        self.assertIn("Updated", dlg.status.text())
        dlg.close()
        self.assertFalse(dlg.timer.isActive())
        self.assertNotIn("h/100", guest_dialogs.GRAPHS)
        self.assertIn("h/101", guest_dialogs.GRAPHS)

    def delete_dialog(self, vmid):
        dlg = guest_dialogs.DeleteDialog(None, self.client, self.runner, self.guest(vmid))
        self.assertTrue(wait_until(lambda: dlg.backups is not None))  # its backups listed
        return dlg

    def add_backups(self, vmid, *protected):
        self.client()  # (the pretend cluster comes with the first connection)
        c = self.cluster()
        for hours, p in enumerate(protected, 1):
            c.backups.append(c._backup_entry(c.guests[vmid], "local", time.time() - hours * 3600, "before & after", p))

    def test_delete_needs_the_name(self):
        dlg = guest_dialogs.DeleteDialog(None, self.client, self.runner, self.guest(102))
        dlg.typed.setText("test-box")
        self.assertFalse(dlg.go.isEnabled())  # not before its backups are known
        self.assertTrue(wait_until(lambda: dlg.backups is not None))
        dlg.typed.setText("test-bo")
        self.assertFalse(dlg.go.isEnabled())
        dlg.typed.setText("test-box")
        self.assertTrue(dlg.go.isEnabled())
        dlg.delete()
        self.assertTrue(wait_until(lambda: 102 not in self.cluster().guests))

    def test_delete_a_stopped_vm(self):
        dlg = self.delete_dialog(200)
        self.assertTrue(dlg.with_backups.isHidden())
        self.assertEqual(dlg.found.text(), "It has no backups.")
        dlg.typed.setText("windows-11")
        self.assertTrue(dlg.go.isEnabled())
        dlg.delete()
        self.assertTrue(wait_until(lambda: 200 not in self.cluster().guests))

    def test_delete_takes_its_backups_but_not_the_protected(self):
        self.add_backups(102, False, True, False)
        self.add_backups(200, False)  # another guest's
        dlg = self.delete_dialog(102)
        self.assertFalse(dlg.with_backups.isHidden())
        self.assertTrue(dlg.with_backups.isChecked())
        self.assertIn("Also delete its 2 backups", dlg.with_backups.text())
        self.assertEqual(dlg.found.text().count(" · local · "), 3)  # all three listed
        self.assertIn("Backups of Deleted Guests", dlg.found.text())  # where the kept one is found later
        self.assertIn("protected, kept", dlg.found.text())
        self.assertIn("before &amp; after", dlg.found.text())  # notes are text, not markup
        dlg.typed.setText("test-box")
        dlg.delete()
        self.assertTrue(wait_until(lambda: dlg.result() == QDialog.DialogCode.Accepted))
        self.assertNotIn(102, self.cluster().guests)
        self.assertEqual([b["protected"] for b in self.cluster().backups if b["vmid"] == 102], [1])
        self.assertEqual(len([b for b in self.cluster().backups if b["vmid"] == 200]), 1)

    def test_delete_can_keep_the_backups(self):
        self.add_backups(102, False)
        dlg = self.delete_dialog(102)
        dlg.with_backups.setChecked(False)
        dlg.typed.setText("test-box")
        dlg.delete()
        self.assertTrue(wait_until(lambda: dlg.result() == QDialog.DialogCode.Accepted))
        self.assertNotIn(102, self.cluster().guests)
        self.assertEqual(len([b for b in self.cluster().backups if b["vmid"] == 102]), 1)

    def test_delete_with_only_protected_backups_and_snapshots(self):
        self.add_backups(102, True)
        dlg = self.delete_dialog(102)
        self.assertTrue(dlg.with_backups.isHidden())
        self.assertIn("Its 1 backup is protected and stays", dlg.found.text())
        snaps = self.delete_dialog(101)
        self.assertIn("its 1 snapshot and", snaps.gone.text())
        self.assertIn("Also delete its 1 backup (", snaps.with_backups.text())

    def test_delete_refuses_a_running_guest(self):
        dlg = guest_dialogs.DeleteDialog(None, self.client, self.runner, self.guest(100))
        dlg.typed.setText("pihole")
        dlg.delete()
        QTest.qWait(150)
        self.assertIn(100, self.cluster().guests)

    def test_new_container(self):
        dlg = guest_dialogs.CreateContainerDialog(None, self.client, self.runner, ["pve"])
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.template.count()))
        self.assertEqual(dlg.vmid.value(), 103)
        self.assertEqual(dlg.bridge.itemText(0), "vmbr0")
        self.assertIn("hostname", dlg.params())
        dlg.hostname.setText("web-1")
        dlg.password.setText("abcdef")
        dlg.password2.setText("abcdeX")
        self.assertIn("not the same", dlg.params())
        dlg.password2.setText("abcdef")
        dlg.nesting.setChecked(True)
        p = dlg.params()
        self.assertEqual((p["hostname"], p["net0"], p["features"]), ("web-1", "name=eth0,bridge=vmbr0,ip=dhcp",
                                                                      "nesting=1"))
        self.assertNotIn("ssh-public-keys", p)
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        new = self.cluster().guests[103]
        self.assertEqual((new["name"], new["status"]), ("web-1", "running"))


ISO = "local:iso/ubuntu-24.04.1-live-server-amd64.iso"


@unittest.skipIf(QApplication is None, "needs PySide6")
class VmParamsTest(unittest.TestCase):
    base = dict(vmid=113, name="web", iso=ISO, cores=2, host_cpu=False, memory=2048, disk_gb=32,
                storage="local-lvm", bridge="vmbr0", agent=True, onboot=False, start=True)

    def test_linux(self):
        p = vm_dialog.vm_params(profile="linux", virtio_iso="", **self.base)
        self.assertEqual((p["ostype"], p["scsi0"], p["net0"], p["boot"], p["ide2"], p["agent"]),
                         ("l26", "local-lvm:32,iothread=1,discard=on", "virtio,bridge=vmbr0,firewall=1",
                          "order=scsi0;ide2;net0", f"{ISO},media=cdrom", "1"))
        for key in ("bios", "efidisk0", "tpmstate0", "ide0", "sata0"):
            self.assertNotIn(key, p)
        self.assertEqual(p["cpu"], "x86-64-v2-AES")  # not the API's kvm64 (no SSE4.2 or AVX)

    def test_windows_11_without_and_with_virtio(self):
        p = vm_dialog.vm_params(profile="win11", virtio_iso="", **{**self.base, "host_cpu": True})
        self.assertEqual((p["ostype"], p["bios"], p["machine"], p["cpu"]), ("win11", "ovmf", "q35", "host"))
        self.assertEqual(p["efidisk0"], "local-lvm:1,efitype=4m,pre-enrolled-keys=1")
        self.assertEqual(p["tpmstate0"], "local-lvm:1,version=v2.0")
        self.assertEqual((p["sata0"], p["net0"], p["boot"]), ("local-lvm:32,discard=on",
                                                              "e1000e,bridge=vmbr0,firewall=1", "order=sata0;ide2;net0"))
        self.assertNotIn("scsi0", p)
        p = vm_dialog.vm_params(profile="win11", virtio_iso="local:iso/virtio-win.iso", **self.base)
        self.assertEqual((p["scsi0"].split(",")[0], p["net0"].split(",")[0], p["ide0"]),
                         ("local-lvm:32", "virtio", "local:iso/virtio-win.iso,media=cdrom"))

    def test_iso_name_from_url(self):
        self.assertEqual(vm_dialog.iso_name_from_url("https://x.org/a/ubuntu%2024.04.iso?dl=1"), "ubuntu_24.04.iso")


def test_core_read_iso(image: bytes) -> dict:
    from tests.test_core import read_iso
    return read_iso(image, joliet=True)[1]


class ConfirmDialogTest(UiCase):
    """The question before a change (26/10: the old message boxes looked rough)."""

    def test_the_window(self):
        g = {"vmid": 108, "name": "UbuntuServer", "type": "qemu", "status": "running", "node": "pve",
             "ips": ["192.168.1.50", "fe80::1"]}
        dlg = widgets.ConfirmDialog(None, "Stop VM 108 now?", "Cuts it off at once.", "Stop Now", True, icon="stop",
                                    guests=[g], note="Shut Down closes it cleanly — try that first.",
                                    instead="Shut Down Instead")
        self.assertEqual(dlg.windowTitle(), "Stop VM 108 now")
        self.assertEqual((dlg.go.text(), dlg.go.property("kind")), ("Stop Now", "destructive"))  # red
        self.assertTrue(dlg.cancel.isDefault())  # the safe answer on Enter
        card = dlg.findChild(QFrame, "guestCard")
        self.assertIn("VM 108 · running · pve · 192.168.1.50", " ".join(l.text() for l in card.findChildren(QLabel)))
        self.assertFalse(dlg.badge.pixmap().isNull())
        dlg.instead.click()
        self.assertEqual((dlg.choice, dlg.result()), ("instead", QDialog.DialogCode.Accepted))
        many = [{**g, "vmid": n, "name": f"g{n}"} for n in range(6)]
        dlg = widgets.ConfirmDialog(None, "Reboot 6 guests?", "Restarts them cleanly.", "Reboot", icon="reboot",
                                    guests=many)
        self.assertEqual(len(dlg.findChildren(QFrame, "guestCard")), widgets.ConfirmDialog.CARDS)
        self.assertEqual(dlg.go.property("kind"), "suggested")  # blue: nothing is destroyed
        self.assertIsNone(dlg.instead)
        dlg.go.click()
        self.assertEqual(dlg.choice, "go")
        for glyph in ("stop", "power", "reboot", "trash", "host", "warning", "question"):
            self.assertFalse(widgets.badge(glyph, "#e5484d").isNull(), glyph)

    def test_confirm_answers(self):
        for clicked, answer in (("go", True), ("instead", "instead"), ("", False)):
            def run(dlg, clicked=clicked):
                dlg.choice = clicked
                return 1
            with mock.patch.object(widgets.ConfirmDialog, "exec", run):
                self.assertEqual(widgets.confirm(None, "Q?", "T", "Go", instead="Other"), answer)


class SetupDiscViewTest(UiCase):
    def test_discs_go_once_the_vm_is_set_up(self):
        pve = DemoPve(DEMO_HOSTS[0])
        volid = setupdisc.upload(pve, "pve", "local", 160, {"autounattend.xml": b"<x/>"}, "autounattend")
        pve.create_vm("pve", {"vmid": 160, "name": "win", "scsi0": "local-lvm:8", "ide3": f"{volid},media=cdrom",
                              "agent": "1"})
        self.cluster().guests[160]["agent_down"] = True  # Windows is still installing
        other = {**setupdisc.entry("other-host", "pve", 160, "local:iso/pvc-setup-160-aaaaaa.iso", "ide3", True)}
        prefs = {"setup_discs": [setupdisc.entry("demo-pve", "pve", 160, volid, "ide3", True), other]}
        view = self.loaded_view(prefs=prefs)

        def status() -> str:
            t = view.table
            row = next(r for r in range(t.rowCount()) if t.item(r, host_view.COL_ID).text() == "160")
            return t.item(row, host_view.COL_STATUS).text()

        self.assertTrue(wait_until(lambda: not view.discs_inflight))
        self.assertIn(volid, self.cluster().isos)  # stopped: kept
        self.assertEqual(status(), "Stopped")  # not setting itself up while it does not run
        self.cluster().guests[160]["status"] = "running"
        view.discs_at = 0.0
        view.refresh()
        self.assertTrue(wait_until(lambda: view.discs_at and not view.discs_inflight))
        self.assertIn(volid, self.cluster().isos)  # running, the agent silent: kept
        self.assertEqual(status(), "Setting up…")  # it looks finished from outside: the list says it is not
        row = next(r for r in range(view.table.rowCount()) if view.table.item(r, host_view.COL_ID).text() == "160")
        self.assertIn("in the background", view.table.item(row, host_view.COL_STATUS).toolTip())
        self.cluster().guests[160]["agent_down"] = False  # the guest tools are in: Windows is ready
        view.discs_at = 0.0
        view.refresh()
        self.assertTrue(wait_until(lambda: volid not in self.cluster().isos))
        self.assertTrue(wait_until(lambda: prefs["setup_discs"] == [other]))  # another host's disc is not this page's
        self.assertTrue(self.saved_prefs)
        self.assertTrue(any("setup finished" in n for n in self.notes))
        self.assertEqual(self.guest_cfg(160)["ide3"], "none,media=cdrom")
        view.refresh()
        self.assertTrue(wait_until(lambda: status() == "Running"))

    def test_enter_after_windows_starts(self):
        view = self.loaded_view(prefs={})
        done = types.SimpleNamespace(created=(201, "win"), done_text="Created VM 201 (win)", boot_keys=("pve", 201),
                                     boot_kind="windows")
        watched = []
        with mock.patch.object(setupdisc, "answer_boot_prompt", lambda pve, node, vmid: watched.append(vmid) or True):
            view._after_new_vm(done)
            self.assertTrue(wait_until(lambda: any("Enter pressed" in n for n in self.notes)))
        self.assertIn("Created VM 201 (win)", self.notes)
        self.assertEqual(watched, [201])
        with mock.patch.object(setupdisc, "answer_boot_prompt", lambda pve, node, vmid: False):
            view._after_new_vm(done)
            self.assertTrue(wait_until(lambda: any("was not seen" in n for n in self.notes)))
        view.remember_setup_disc({"node": "pve", "vmid": 201, "volid": "local:iso/x.iso"})
        self.assertEqual(view.prefs["setup_discs"][0]["host"], "demo-pve")

    def test_yes_after_ubuntu_starts(self):
        view = self.loaded_view(prefs={})
        done = types.SimpleNamespace(created=(202, "srv"), done_text="Created VM 202 (srv)", boot_keys=("pve", 202),
                                     boot_kind="ubuntu")
        watched = []
        with mock.patch.object(autoinstall, "answer_question", lambda pve, node, vmid: watched.append(vmid) or True), \
                mock.patch.object(setupdisc, "answer_boot_prompt", lambda *a: self.fail("not Windows' question")):
            view._after_new_vm(done)
            self.assertTrue(wait_until(lambda: any("yes typed" in n for n in self.notes)))
        self.assertEqual(watched, [202])
        self.assertTrue(any("Continue with autoinstall?" in n for n in self.notes))


class VmDialogTest(UiCase):
    def client(self):
        return DemoPve(DEMO_HOSTS[0])

    def dialog(self):
        dlg = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"])
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.iso.count()))
        return dlg

    def visible(self, dlg, field):
        return dlg.form.isRowVisible(dlg._row_of(field))

    def test_ubuntu_releases_from_ubuntus_index(self):
        """The ready-made Ubuntu's releases: the list kept (here the one built in) at once, then Ubuntu's index read
        in the background — a new LTS shows, what was chosen stays chosen."""
        self.ubuntu_index = {"index": {ubuntu_releases.IMAGES: {"products": [
            f"com.ubuntu.cloud:server:{v}:amd64" for v in ("22.04", "24.04", "26.04", "26.10", "28.04")]}}}
        with mock.patch.object(ubuntu_releases, "supported", lambda v, today=None: True):  # (whatever today is)
            dlg = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"])
            self.addCleanup(dlg.close)
            first = [dlg.release.itemData(i) for i in range(dlg.release.count())]
            dlg.release.setCurrentIndex(dlg.release.findData("26.04"))
            self.assertTrue(wait_until(lambda: dlg.release.count() == 3))
        self.assertEqual(first, ["24.04", "26.04"])
        self.assertEqual([dlg.release.itemText(i) for i in range(3)], ["24.04 LTS", "26.04 LTS", "28.04 LTS"])
        self.assertEqual(dlg.release.currentData(), "26.04")
        self.assertEqual(vm_dialog.size_words("28.04"), " (about 905 MB)")  # (asked of the image's server)
        self.assertEqual(vm_dialog.size_words("24.04"), " (about 626 MB)")

    def test_linux_vm_from_iso(self):
        dlg = self.dialog()
        self.assertEqual((dlg.vmid.value(), dlg.iso.currentData(), dlg.bridge.currentText()), (103, ISO, "vmbr0"))
        self.assertEqual((dlg.cores.value(), dlg.memory.value(), dlg.disk.value()), (2, 2048, 32))
        self.assertFalse(dlg.from_template.isEnabled())  # no templates on this host
        self.assertFalse(self.visible(dlg, dlg.virtio))  # VirtIO drivers are a Windows matter
        self.assertTrue(dlg.linux_setup())  # an Ubuntu Server ISO installs itself unless told not to
        dlg.unattended.setChecked(False)
        self.assertFalse(self.visible(dlg, dlg.user) or self.visible(dlg, dlg.static))  # by hand: nothing of it
        dlg.name.setText("bad name")
        dlg.create()
        self.assertIn("name", self.errors[-1][1])
        dlg.name.setText("web-1")
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertEqual(dlg.created, (103, "web-1"))
        vm = self.cluster().guests[103]
        self.assertEqual((vm["type"], vm["status"], vm["agent"]), ("qemu", "running", 1))
        self.assertEqual(vm["cfg"]["ide2"], f"{ISO},media=cdrom")

    def test_windows_profile(self):
        dlg = self.dialog()
        dlg.profile.setCurrentIndex(dlg.profile.findData("win11"))
        self.assertEqual((dlg.cores.value(), dlg.memory.value(), dlg.disk.value()), (4, 8192, 64))
        self.assertTrue(self.visible(dlg, dlg.virtio))
        self.assertIn("TPM", dlg.hint.text())
        self.assertEqual(dlg.virtio.currentData(), "")  # none on the host yet
        dlg.get_virtio()
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.virtio.findData("local:iso/virtio-win.iso") >= 0))
        self.assertEqual(dlg.virtio.currentData(), "local:iso/virtio-win.iso")  # picked by itself
        self.assertEqual(dlg.iso.currentData(), ISO)  # the install image stays chosen
        dlg.name.setText("win11")
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        cfg = self.cluster().guests[103]["cfg"]
        self.assertEqual((cfg["bios"], cfg["ide0"]), ("ovmf", "local:iso/virtio-win.iso,media=cdrom"))
        self.assertIn("tpmstate0", cfg)

    def test_ubuntu_server_iso_installs_itself_with_a_static_ip(self):
        kept = []
        dlg = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"], remember=kept.append,
                                       known_ips=frozenset({"192.168.1.26"}))
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.iso.count()))
        self.assertTrue(dlg.linux_setup())  # the host's Ubuntu Server ISO, the Linux profile: it installs itself
        for field in (dlg.unattended, dlg.user, dlg.ssh_key, dlg.static):
            self.assertTrue(self.visible(dlg, field))
        self.assertFalse(self.visible(dlg, dlg.agent))  # that setup installs the agent anyway
        self.assertIn("Continue with autoinstall?", dlg.hint.text())
        self.assertFalse(dlg.static_ip.isVisibleTo(dlg))  # the field opens with the tick
        dlg.static.setChecked(True)
        self.assertTrue(dlg.static_ip.isVisibleTo(dlg))
        self.assertEqual(dlg.static_note.text(), "/24 · gateway 192.168.1.1 · DNS 192.168.1.1 (from the Proxmox host)")
        # a whole address fits in the field however narrow the window; the note goes under it where the row is short
        # (the user's test, 26/10: the field shrank to ".50" and the note was cut off)
        dlg.static_ip.setText("192.168.100.250")
        self.assertGreater(dlg.static_ip.width(), dlg.static_ip.fontMetrics().horizontalAdvance("255.255.255.255"))
        dlg.show()
        for width, rows in ((690, 2), (900, 1)):
            dlg.resize(width, dlg.height())
            self.assertTrue(wait_until(lambda: dlg.static_flow.rows() == rows), width)
            note = dlg.static_note.geometry()
            self.assertLessEqual(note.right(), dlg.static_note.parentWidget().width(), width)  # not cut off
        dlg.name.setText("srv-ai")
        dlg.password.setText("ai-pw")
        dlg.password2.setText("ai-pw")
        for address, words in (("", "an address such as"), ("192.168.1.26", "in use"), ("10.0.0.9", "not in")):
            dlg.static_ip.setText(address)
            dlg.create()
            self.assertIn(words, self.errors[-1][1])
        dlg.static_ip.setText("192.168.1.62")
        steps = []
        dlg.steps.said.connect(steps.append)
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        # what it was doing, on the status line, step by step (26/10: the window sat ~15 s without a word)
        self.assertEqual(steps, ["Writing the setup disc…", "Creating the VM…", "Starting it…"])
        cfg = self.cluster().guests[103]["cfg"]
        disc = cfg["ide3"].split(",")[0]
        self.assertEqual((kept[0]["volid"], kept[0]["drive"], kept[0]["agent"], str(cfg["agent"])),
                         (disc, "ide3", True, "1"))
        files = test_core_read_iso(self.cluster().files[disc.split("/")[1]])
        ai = json.loads(files["user-data"].decode().split("\n", 1)[1])["autoinstall"]
        self.assertEqual((ai["identity"]["username"], ai["network"]["ethernets"]["ens18"]["addresses"]),
                         ("user", ["192.168.1.62/24"]))
        self.assertNotIn(b"ai-pw", files["user-data"])
        self.assertEqual((dlg.boot_keys, dlg.boot_kind), (("pve", 103), "ubuntu"))  # the main window types yes
        self.assertIn("Ubuntu Server installs itself", dlg.done_text)

    def test_windows_installs_itself(self):
        self.client()
        self.cluster().isos += ["local:iso/Win11_25H2_Greek_x64.iso", "local:iso/virtio-win.iso"]
        kept = []
        dlg = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"], remember=kept.append)
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.iso.count()))
        self.assertTrue(self.visible(dlg, dlg.unattended))  # Linux with Ubuntu Server's ISO installs itself too …
        self.assertFalse(dlg.edition.isVisibleTo(dlg) or dlg.language.isVisibleTo(dlg))  # … nothing of Windows' in it
        self.assertFalse(self.visible(dlg, dlg.rdp))
        dlg.profile.setCurrentIndex(dlg.profile.findData("win11"))
        dlg.iso.setCurrentIndex(dlg.iso.findData("local:iso/Win11_25H2_Greek_x64.iso"))
        self.assertTrue(all(self.visible(dlg, f) for f in (dlg.unattended, dlg.user, dlg.rdp)))
        self.assertFalse(self.visible(dlg, dlg.ssh_key))  # (a Linux matter)
        self.assertEqual((dlg.edition.currentText(), dlg.language.currentText()), ("Windows 11 Pro", "el-GR"))
        self.assertEqual(dlg.virtio.currentData(), "local:iso/virtio-win.iso")
        self.assertIn("deletes the answer disc", dlg.hint.text())
        self.assertFalse([dlg.virtio.itemData(i) for i in range(dlg.virtio.count())
                          if "pvc-setup" in (dlg.virtio.itemData(i) or "")])
        dlg.name.setText("win-desk")
        dlg.rdp.setChecked(True)
        dlg.create()
        self.assertIn("Remote Desktop needs a password", self.errors[-1][1])
        dlg.password.setText("Pw-1")
        dlg.password2.setText("Pw-2")
        dlg.create()
        self.assertIn("not the same", self.errors[-1][1])
        dlg.edition.setCurrentText("Windows 11 Home")
        dlg.password2.setText("Pw-1")
        dlg.create()
        self.assertIn("Home", self.errors[-1][1])
        dlg.edition.setCurrentText("Windows 11 Pro")
        dlg.dark.setChecked(True)
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        cfg = self.cluster().guests[103]["cfg"]
        disc = cfg["ide3"].split(",")[0]
        self.assertEqual((dlg.boot_keys, kept[0]["volid"], kept[0]["drive"], kept[0]["agent"]),
                         (("pve", 103), disc, "ide3", True))
        self.assertEqual(self.cluster().guests[103]["status"], "running")
        xml = test_core_read_iso(self.cluster().files[disc.split("/")[1]])["autounattend.xml"].decode()
        self.assertIn("fDenyTSConnections", xml)
        self.assertIn("AppsUseLightTheme", xml)
        self.assertIn("<TimeZone>GTB Standard Time</TimeZone>", xml)  # the Proxmox host's place
        self.assertIn("<UserLocale>el-GR</UserLocale>", xml)
        self.assertNotIn("Pw-1<", xml)
        self.assertIn("Windows installs itself", dlg.done_text)
        again = self.dialog()  # the answer disc is not offered as an ISO to install from
        self.assertFalse([again.iso.itemData(i) for i in range(again.iso.count())
                          if "pvc-setup" in again.iso.itemData(i)])
        again.close()

    def test_windows_never_installs_from_the_virtio_disc(self):
        """The user's test, 24/10: the VirtIO disc landed in ISO image (the list right above VirtIO drivers) and the VM
        booted nothing. Windows now picks a Windows ISO by itself, and Create refuses the VirtIO disc there."""
        self.client()
        self.cluster().isos += ["local:iso/virtio-win-0.1.285.iso", "local:iso/Win11_25H2_English_x64.iso"]
        dlg = self.dialog()
        self.assertEqual(dlg.iso.currentData(), ISO)  # Linux: the first one, as before
        dlg.profile.setCurrentIndex(dlg.profile.findData("win11"))
        self.assertEqual(dlg.iso.currentData(), "local:iso/Win11_25H2_English_x64.iso")
        self.assertEqual(dlg.virtio.currentData(), "local:iso/virtio-win-0.1.285.iso")
        dlg.iso.setCurrentIndex(dlg.iso.findData("local:iso/virtio-win-0.1.285.iso"))
        dlg.name.setText("win-test")
        dlg.create()
        self.assertEqual(self.errors[-1][1], vm_dialog.VIRTIO_AS_SYSTEM)
        self.assertNotIn(103, self.cluster().guests)

    def test_windows_by_hand(self):
        dlg = self.dialog()
        dlg.profile.setCurrentIndex(dlg.profile.findData("win10"))
        dlg.unattended.setChecked(False)
        self.assertFalse(self.visible(dlg, dlg.user))  # the old way: its console, by hand
        dlg.name.setText("win10")
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertNotIn("ide3", self.cluster().guests[103]["cfg"])
        self.assertIsNone(dlg.boot_keys)

    def test_ready_made_ubuntu(self):
        kept = []
        dlg = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"], remember=kept.append)
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.iso.count()))
        dlg.from_cloud.setChecked(True)
        self.assertTrue(all(self.visible(dlg, f) for f in (dlg.release, dlg.user, dlg.ssh_key)))
        self.assertFalse(any(self.visible(dlg, f) for f in (dlg.iso, dlg.profile, dlg.unattended)))
        self.assertFalse(dlg.rdp.isEnabled())  # Server: no desktop to show
        self.assertEqual((dlg.cores.value(), dlg.memory.value(), dlg.disk.value()), (2, 2048, 20))
        dlg.name.setText("srv")
        dlg.create()
        self.assertIn("Get Image", self.errors[-1][1])
        self.assertTrue(dlg.image_btn.isVisible() or not dlg.isVisible())
        dlg.get_image()
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.image_state.text() == "image on the host"))
        dlg.create()
        self.assertIn("password, or an SSH key", self.errors[-1][1])
        dlg.password.setText("srv-pw")
        dlg.password2.setText("srv-pw")
        dlg.static.setChecked(True)  # a fixed address, the rest from the host's network
        dlg.static_ip.setText("192.168.1.63")
        steps = []
        dlg.steps.said.connect(steps.append)
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertIn("Copying Ubuntu's image into its disk — the longest part, about half a minute…", steps)
        self.assertEqual(steps[-2:], ["Growing its disk to 20 GB…", "Starting it…"])
        cfg, g = self.cluster().guests[103]["cfg"], self.cluster().guests[103]
        self.assertEqual((g["disk_gb"], g["status"]), (20, "running"))
        self.assertNotIn("ciuser", cfg)  # a server too sets itself up from the app's disc (25/10)
        self.assertEqual((len(kept), kept[0]["volid"]), (1, cfg["ide2"].split(",")[0]))
        srv = test_core_read_iso(self.cluster().files[kept[0]["volid"].split("/")[1]])
        self.assertIn(b"installing the updates and the QEMU guest agent", srv["user-data"])
        self.assertEqual(json.loads(srv["network-config"])["ethernets"]["ens18"]["addresses"], ["192.168.1.63/24"])
        self.assertNotIn(b"srv-pw", srv["user-data"])
        desk = vm_dialog.CreateVmDialog(None, self.client, self.runner, ["pve"], remember=kept.append)
        self.assertTrue(wait_until(lambda: desk.isEnabled() and desk.iso.count()))
        desk.from_cloud.setChecked(True)
        self.assertFalse(desk.host_cpu.isChecked() or desk.host_cpu.isHidden())  # a server: the portable type
        desk.cloud_edition.setCurrentIndex(desk.cloud_edition.findData("desktop"))
        self.assertEqual((desk.cores.value(), desk.memory.value(), desk.disk.value(), desk.host_cpu.isChecked()),
                         (4, 8192, 32, True))  # as the Windows VMs: smooth video and sound over Remote Desktop
        self.assertTrue(desk.rdp.isEnabled())
        self.assertFalse(desk.dark.isHidden())  # the dark theme: Ubuntu Desktop too
        desk.rdp.setChecked(True)
        desk.dark.setChecked(True)
        desk.name.setText("desk")
        desk.user.setText("Nikos")
        desk.password.setText("d-pw")
        desk.password2.setText("d-pw")
        desk.create()
        self.assertIn("Linux user name", self.errors[-1][1])
        desk.user.setText("nikos")
        desk.create()
        self.assertTrue(wait_until(lambda: desk.result() == desk.DialogCode.Accepted))
        cfg = self.cluster().guests[104]["cfg"]
        disc = cfg["ide2"].split(",")[0]
        self.assertEqual((kept[-1]["volid"], kept[-1]["drive"], self.cluster().guests[104]["disk_gb"]),
                         (disc, "ide2", 32))
        self.assertNotIn("ciuser", cfg)
        self.assertEqual((cfg["cpu"], str(cfg["cores"])), ("host", "4"))
        self.assertEqual(self.cluster().guests[103]["cfg"]["cpu"], "x86-64-v2-AES")
        files = test_core_read_iso(self.cluster().files[disc.split("/")[1]])
        data = files["user-data"].decode()
        self.assertIn('"gnome-remote-desktop"', data)
        self.assertIn('"dconf-cli"', data)
        self.assertEqual(files["rdp-password"], b"d-pw\n")
        self.assertIn('"timezone": "Europe/Athens"', data)
        self.assertNotIn("d-pw", data)
        self.assertEqual(desk.boot_keys, None)  # only Windows waits for a key

    def test_download_an_iso(self):
        dlg = self.dialog()
        dlg.download_iso()
        down = dlg.download_dialog
        down.url.setText("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.7.0-amd64-netinst.iso")
        self.assertEqual(down.filename.text(), "debian-12.7.0-amd64-netinst.iso")
        down.checksum.setText("not-a-checksum")
        down.download()
        self.assertIn("SHA-256", self.errors[-1][1])
        down.checksum.setText("")
        down.download()
        self.assertTrue(wait_until(lambda: dlg.iso.currentData() == "local:iso/debian-12.7.0-amd64-netinst.iso"))

    def test_upload_an_iso(self):
        dlg = self.dialog()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "Win11_24H2_English_x64.iso")
            with open(path, "wb") as fh:
                fh.write(b"\0" * (3 << 20))
            with mock.patch.object(vm_dialog.QFileDialog, "getOpenFileName", return_value=(path, "")):
                dlg.upload_iso()
                self.assertTrue(dlg.upload_progress.isVisible())
                self.assertTrue(wait_until(lambda: dlg.iso.currentData() == "local:iso/Win11_24H2_English_x64.iso"))
        self.assertEqual(self.cluster().uploaded, {"Win11_24H2_English_x64.iso": 3 << 20})
        self.assertFalse(dlg.upload_progress.isVisible())

    def test_new_vm_display_sound_and_usb(self):
        dlg = self.dialog()
        hw = dlg.hw
        # folded into one line until Change… (26/10: the window must fit a small screen)
        self.assertFalse(self.visible(dlg, hw.display) or self.visible(dlg, hw.usb_box))
        self.assertTrue(self.visible(dlg, dlg.hw_summary))
        self.assertEqual(dlg.hw_summary.text(), "SPICE display · USB tablet · Intel HD Audio (ich9) · no USB devices")
        folded = dlg.layout().totalMinimumHeightForWidth(680)
        dlg.hw_change.click()
        self.assertTrue(self.visible(dlg, hw.display) and self.visible(dlg, hw.usb_box))
        self.assertFalse(self.visible(dlg, dlg.hw_summary))
        self.assertGreater(dlg.layout().totalMinimumHeightForWidth(680), folded + 150)
        self.assertEqual((hw.display.currentData(), hw.sound.currentData(), hw.output.currentData()),
                         ("qxl", "ich9-intel-hda", "spice"))  # his choice: SPICE and sound by default
        items = self.usb_items(hw)
        self.assertEqual(set(items), {"0781:5581", "046d:c52b"})  # the hub is not offered
        items["0781:5581"].setCheckState(Qt.CheckState.Checked)
        hw.spice_usb.setChecked(True)
        dlg.unattended.setChecked(False)  # (installed by hand)
        dlg.name.setText("desk")
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        cfg = self.cluster().guests[103]["cfg"]
        self.assertEqual((cfg["vga"], cfg["audio0"]), ("qxl", "device=ich9-intel-hda,driver=spice"))
        self.assertTrue(hw.tablet.isChecked())
        self.assertEqual(cfg["tablet"], "1")  # Proxmox leaves the tablet out with SPICE unless it is set
        self.assertEqual((cfg["usb0"], cfg["usb1"], cfg["usb2"]), ("host=0781:5581,usb3=1", "spice", "spice"))
        hw.display.setCurrentIndex(hw.display.findData("std"))  # SPICE USB needs the SPICE display
        self.assertFalse(hw.spice_usb.isEnabled())
        self.assertIn("SPICE display", hw.hint.text())

    def test_new_vm_without_sound_and_template_copies(self):
        dlg = self.dialog()
        dlg.hw.sound.setCurrentIndex(0)  # None
        self.assertFalse(dlg.hw.output.isEnabled())
        self.assertNotIn("audio0", dlg.hw.params())
        dlg.from_template.setEnabled(True)
        dlg.from_template.setChecked(True)
        self.assertFalse(dlg.form.isRowVisible(dlg.hw.usb_box))  # a copy keeps the template's hardware

    def test_copy_a_template(self):
        DemoPve(DEMO_HOSTS[0])
        self.cluster().guests[9000] = {"vmid": 9000, "type": "qemu", "name": "ubuntu-tmpl", "status": "stopped",
                                       "cores": 2, "memory": 2048, "disk_gb": 20, "onboot": 0, "ip": "",
                                       "description": "", "template": 1}
        dlg = self.dialog()
        self.assertTrue(dlg.from_template.isEnabled())
        dlg.from_template.setChecked(True)
        self.assertTrue(wait_until(lambda: dlg.template_cfg))
        self.assertFalse(self.visible(dlg, dlg.iso))
        self.assertTrue(self.visible(dlg, dlg.template))
        self.assertEqual(dlg.cores.value(), 2)  # from the template
        dlg.name.setText("app-1")
        dlg.cores.setValue(4)
        dlg.create()
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        vm = self.cluster().guests[103]
        self.assertEqual((vm["name"], vm["cores"], vm["memory"], vm["status"]), ("app-1", 4, 2048, "running"))


class ConsoleTest(UiCase):
    def tearDown(self):
        console.close_all()
        super().tearDown()

    def open(self, vmid=201, kind="qemu"):
        pve = DemoPve(DEMO_HOSTS[0])
        win = console.show(f"t/{vmid}", "test", lambda: pve.open_vnc("pve", kind, vmid))
        self.assertTrue(wait_until(lambda: win.client is not None and not win.view.fb.isNull()))
        return win, pve

    def test_builtin_console(self):
        win, pve = self.open()
        srv = pve.cluster.consoles[-1]
        self.assertEqual((win.view.fb.width(), win.view.fb.height()), (720, 400))
        self.assertEqual(win.status.text(), "Connected")
        self.assertTrue(wait_until(lambda: win.view.fb.pixelColor(5, 5).name() == "#1e1e24"))  # the screen arrived
        self.assertTrue(win.client.ext_keys)  # a VM: physical key codes on offer
        QTest.keyClick(win.view, Qt.Key.Key_A)
        self.assertTrue(wait_until(lambda: len(srv.keys) >= 2))
        self.assertEqual([k[1:3] for k in srv.keys[:2]], [(True, ord("a")), (False, ord("a"))])
        self.assertTrue(wait_until(lambda: win.view.fb.pixelColor(14, 16).name() == "#c8c8d0"))  # the typed block
        win.ctrl_alt_del()
        self.assertTrue(wait_until(lambda: len(srv.keys) >= 8))
        self.assertEqual([k[2] for k in srv.keys[2:5]], [0xFFE3, 0xFFE9, 0xFFFF])
        t = win.view.target()
        QTest.mouseClick(win.view, Qt.MouseButton.LeftButton, pos=t.center().toPoint())
        self.assertTrue(wait_until(lambda: any(b == 1 for b, _x, _y in srv.pointer)))
        self.assertTrue(wait_until(lambda: any(b == 0 for b, _x, _y in srv.pointer[1:])))  # and released

    def typed(self, srv, since=0):
        """The text the guest received as typed keys (key downs, Shift, Ctrl and the like aside, Enter as a line
        end)."""
        out = []
        for k in srv.keys[since:]:
            if k[1] and not 0xFFE1 <= k[2] <= 0xFFEE:
                out.append("\n" if k[2] == 0xFF0D else "\t" if k[2] == 0xFF09 else chr(k[2]))
        return "".join(out)

    def test_paste_window(self):
        import shiboken6
        win, pve = self.open()
        srv = pve.cluster.consoles[-1]
        self.assertEqual([w.text() for w in (win.cad_btn, win.paste_btn, win.full_btn)],
                         ["Ctrl+Alt+Del", "Paste…", "Full Screen"])
        self.copied = "echo 'Γεια' > /tmp/A.txt\r\ncat /tmp/A.txt\n"
        with mock.patch.object(screen_core, "KEY_GAP_S", 0.0):
            win.paste_btn.click()
            dlg = win.paste_dialog
            self.assertEqual(dlg.edit.toPlainText(), "echo 'Γεια' > /tmp/A.txt\ncat /tmp/A.txt\n")
            self.assertEqual(dlg.info.text(), "2 lines, 35 characters — about 1 s. In a terminal each line runs as its "
                                              "Enter is typed. Not on a US keyboard, left out (marked): Γ α ε ι")
            self.assertEqual(len(dlg.edit.extraSelections()), 4)
            self.assertFalse(dlg.enter.isChecked())  # no Enter at the end unless ticked
            dlg.type_btn.click()
            self.assertTrue(wait_until(lambda: not shiboken6.isValid(dlg) or not dlg.isVisible()))
            self.assertEqual(self.typed(srv), "echo '' > /tmp/A.txt\ncat /tmp/A.txt")
            self.assertEqual([k[2] for k in srv.keys if k[2] == screen_core.SHIFT][:2], [screen_core.SHIFT] * 2)
            self.assertTrue(wait_until(lambda: win.status.text() == "Connected"))
            n = len(srv.keys)
            self.copied = "ls -la"
            dlg = win.paste()
            dlg.enter.setChecked(True)
            self.assertTrue(dlg.info.text().startswith("1 line, 7 characters"))
            dlg.type_btn.click()
            self.assertTrue(wait_until(lambda: self.typed(srv, n) == "ls -la\n"))
        self.copied = "   "
        dlg = win.paste()
        self.assertFalse(dlg.type_btn.isEnabled())
        self.assertEqual(dlg.info.text(), "Nothing to type.")
        dlg.close()

    def test_paste_stops_and_holds_the_users_keys(self):
        win, pve = self.open()
        srv = pve.cluster.consoles[-1]
        with mock.patch.object(screen_core, "KEY_GAP_S", 0.002):
            dlg = win.paste("x" * 5000)
            dlg.type_btn.click()
            self.assertTrue(wait_until(lambda: dlg.job is not None and dlg.job.typed > 20))
            self.assertEqual(dlg.cancel_btn.text(), "Stop")
            n = len(srv.keys)
            QTest.keyClick(win.view, Qt.Key.Key_Q)  # the user's own keys wait while it types
            dlg.cancel_btn.click()
            self.assertTrue(wait_until(lambda: dlg.info.text().startswith("Stopped after")))
        typed = self.typed(srv)
        self.assertTrue(20 < len(typed) < 5000)
        self.assertNotIn("q", typed)
        self.assertEqual(dlg.cancel_btn.text(), "Close")
        self.assertFalse(win.typing())
        QTest.keyClick(win.view, Qt.Key.Key_Q)  # and go again once it stopped
        self.assertTrue(wait_until(lambda: "q" in self.typed(srv, n)))
        dlg.close()

    def test_ctrl_shift_v_types_one_copied_line(self):
        win, pve = self.open()
        srv = pve.cluster.consoles[-1]
        ctrl_shift = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
        self.copied = "uname -a\n"
        with mock.patch.object(screen_core, "KEY_GAP_S", 0.0):
            QTest.keyClick(win.view, Qt.Key.Key_V, ctrl_shift)
            self.assertTrue(wait_until(lambda: self.typed(srv) == "uname -a"))  # no Enter: it does not run
        self.assertNotIn(ord("V"), [k[2] for k in srv.keys])  # the shortcut is the app's, not the guest's
        first = next(i for i, k in enumerate(srv.keys) if k[2] == ord("u"))
        held = [k for k in srv.keys[:first] if 0xFFE1 <= k[2] <= 0xFFEE]
        self.assertLessEqual({k[2] for k in held if k[1]}, {k[2] for k in held if not k[1]})  # let go before typing
        self.assertIsNone(win.paste_dialog)
        self.copied = "one\ntwo"  # more than one line: Paste… first
        QTest.keyClick(win.view, Qt.Key.Key_V, ctrl_shift)
        self.assertIsNotNone(win.paste_dialog)
        self.assertEqual(win.paste_dialog.edit.toPlainText(), "one\ntwo")
        win.paste_dialog.close()
        self.copied = ""
        QTest.keyClick(win.view, Qt.Key.Key_V, ctrl_shift)
        self.assertEqual(win.status.text(), "Nothing copied to paste.")

    def test_a_console_thread_ends_quietly_when_the_app_closes(self):
        """26/10: at every exit a console's thread printed "RuntimeError: Signal source has been deleted" — the app
        had gone, and with it the relay the thread reports to."""
        import shiboken6

        def refused():
            raise OSError("closed")
        session = console._Session(refused)
        shiboken6.delete(session.relay)  # (as the app's end leaves it)
        session.run()  # no exception: nothing left to tell
        self.assertTrue(session.stopping)

    def test_screen_is_opaque_when_scaled_down(self):
        """The white console: QEMU's pixels carry 0 in their fourth byte, Qt took it for alpha, and the window became
        see-through once the screen was drawn smaller than the guest's resolution."""
        from PySide6.QtCore import QRectF
        from PySide6.QtGui import QImage, QPainter
        win, _pve = self.open()
        self.assertTrue(wait_until(lambda: win.view.fb.pixelColor(5, 5).name() == "#1e1e24"))
        out = QImage(360, 200, QImage.Format.Format_ARGB32_Premultiplied)  # like a window's buffer, half size
        out.fill(0)
        p = QPainter(out)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        p.drawImage(QRectF(0, 0, 360, 200), win.view.fb)
        p.end()
        self.assertEqual(out.pixel(100, 100) >> 24, 255)
        self.assertEqual(out.pixelColor(100, 100).name(), "#1e1e24")

    def test_screen_fills_the_window(self):
        win, _pve = self.open()  # the guest's screen is 720 × 400
        for w, h in ((1800, 1000), (500, 600), (720, 400)):
            win.view.resize(w, h)
            t = win.view.target()
            self.assertAlmostEqual(t.width() / t.height(), 720 / 400, places=2)  # proportions kept
            self.assertTrue(abs(t.width() - w) < 1 or abs(t.height() - h) < 1)  # touches two sides: fills it
        win.view.resize(1800, 1000)
        x, y = win.view.to_screen(win.view.target().bottomRight())  # mouse mapping follows the scale
        self.assertEqual((x, y), (719, 399))

    def test_the_guests_pointer_is_used(self):
        win, _pve = self.open()
        self.assertTrue(wait_until(lambda: win.view.cursor().shape() == Qt.CursorShape.BitmapCursor))
        self.assertEqual(win.view.cursor().pixmap().size().width(), 8)
        self.assertEqual(win.view.cursor().hotSpot().x(), 0)
        win.view.set_pointer(0, 0, 0, 0, b"")  # the guest hides its pointer (text console): the normal arrow
        self.assertEqual(win.view.cursor().shape(), Qt.CursorShape.ArrowCursor)

    def test_tab_goes_to_the_guest_and_keys_are_let_go(self):
        win, pve = self.open(100, "lxc")
        srv = pve.cluster.consoles[-1]
        self.assertFalse(win.client.ext_keys)  # a container: key symbols
        QTest.keyClick(win.view, Qt.Key.Key_Tab)
        self.assertTrue(wait_until(lambda: ("sym", True, 0xFF09) in srv.keys))
        QTest.keyPress(win.view, Qt.Key.Key_Control)
        self.assertTrue(wait_until(lambda: ("sym", True, 0xFFE3) in srv.keys))
        win.view.release_all()  # what losing focus does
        self.assertTrue(wait_until(lambda: ("sym", False, 0xFFE3) in srv.keys))

    def test_one_window_per_guest_and_closing(self):
        win, pve = self.open()
        again = console.show("t/201", "test", lambda: pve.open_vnc("pve", "qemu", 201))
        self.assertIs(again, win)
        self.assertEqual(len(pve.cluster.consoles), 1)
        srv = pve.cluster.consoles[-1]
        win.close()
        self.assertNotIn("t/201", console.OPEN)
        self.assertTrue(wait_until(lambda: not srv.thread.is_alive()))  # the connection really ended

    def test_opening_and_closing_many_times(self):
        """The crash this guards against: the reading thread dropped the window's last reference, so Qt destroyed
        the window on that thread (segfault in QWidget's destructor)."""
        import gc
        pve = DemoPve(DEMO_HOSTS[0])
        for i in range(15):
            win = console.show("t/loop", "loop", lambda: pve.open_vnc("pve", "qemu", 201))
            self.assertTrue(wait_until(lambda: win.client is not None, 3))
            win.close()
            del win
            QTest.qWait(10)
            gc.collect()
        self.assertTrue(wait_until(lambda: not console._RUNNING, 5))  # every thread finished and was reaped
        self.assertTrue(all(not srv.thread.is_alive() for srv in pve.cluster.consoles))

    def test_lost_connection_offers_reconnect(self):
        win, pve = self.open()
        pve.cluster.consoles[-1].ws.close()  # the server side goes away
        self.assertTrue(wait_until(lambda: win.reconnect_btn.isVisibleTo(win)))
        self.assertIn("Disconnected", win.status.text())
        win.connect_now()
        self.assertTrue(wait_until(lambda: win.client is not None and win.status.text() == "Connected"))


class UpdateTest(UiCase):
    """A newer version (the user's choice, 26/10, from a mockup): the striped tab beside the ☰ of every page, the
    title says it, and the window its click opens — Install, or the download page where the app cannot update
    itself."""

    FEED = {"version": "9.1.0", "notes": ["Files: right-click menu", "Console: Paste…"], "page": "https://themechanic.store/pc",
            "linux": {"url": "https://themechanic.store/d/pc_9.1.0_amd64.deb", "sha256": "a" * 64, "size": 41_000_000},
            "windows": {"url": "https://themechanic.store/d/pc-9.1.0-setup.exe", "sha256": "b" * 64, "size": 38_000_000}}

    def test_tab_and_title(self):
        win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)
        self.addCleanup(win.close)
        self.assertFalse(any(t.isVisibleTo(win) for t in win.update_tabs))  # (the demo reads no feed)
        win.show_update(dict(self.FEED), "deb")
        tabs = [t for t in win.update_tabs if t.window() is win]
        self.assertTrue(tabs and all(not t.isHidden() for t in tabs))
        self.assertEqual(tabs[0].text(), "Update 9.1")
        self.assertTrue(win.windowTitle().endswith(" — Update 9.1 available"))
        win.show_host(DEMO_HOSTS[1].id)  # another host's page: its own tab, the title still says it
        self.assertTrue(win.windowTitle().endswith(" — Update 9.1 available"))
        self.assertTrue(all(not t.isHidden() for t in win.update_tabs))
        win.show_update(None, "")
        self.assertTrue(all(t.isHidden() for t in win.update_tabs))
        self.assertNotIn("Update", win.windowTitle())

    def test_read_at_the_start_and_kept(self):
        self.update_feed = dict(self.FEED)
        win = MainWindow([], DemoPve)
        self.addCleanup(win.close)
        win.check_updates()
        self.assertTrue(wait_until(lambda: win.update_feed is not None))
        self.assertEqual(win.update_how, "deb")
        self.assertFalse(win.update_tabs[0].isHidden())
        win.close()
        self.update_feed = None  # no network now: what was read is shown at the next start, at once
        again = MainWindow([], DemoPve)
        self.addCleanup(again.close)
        self.assertEqual(again.update_feed["version"], "9.1.0")
        self.assertFalse(again.update_tabs[0].isHidden())
        self.update_feed = dict(self.FEED, version="0.0.1")  # not newer: nothing
        again.check_updates()
        self.assertTrue(wait_until(lambda: again.update_feed is None))
        self.assertTrue(again.update_tabs[0].isHidden())

    def test_install_through_the_system(self):
        dlg = update_window.UpdateDialog(None, dict(self.FEED), "deb")
        self.addCleanup(dlg.close)
        self.assertIn("installed through the system (it asks for your password)",
                      " ".join(lbl.text() for lbl in dlg.findChildren(QLabel)))
        self.assertEqual(dlg.install_btn.text(), "Install")
        self.assertIn("about 41 MB", " ".join(l.text() for l in dlg.findChildren(QLabel)))
        installed, started, quit_ = [], [], []

        def download(feed, progress, cancel):
            progress(5, 10)
            return Path("/x.deb")
        with mock.patch.object(updates_core, "download", download), \
                mock.patch.object(updates_core, "install_deb", installed.append), \
                mock.patch("PySide6.QtCore.QProcess.startDetached", lambda *a: started.append(a) or True), \
                mock.patch.object(update_window.QApplication, "quit", lambda: quit_.append(1)):
            dlg.install_btn.click()
            self.assertTrue(wait_until(lambda: quit_, 5))
        self.assertEqual(installed, [Path("/x.deb")])
        self.assertEqual(started[0][0], updates_core.restart_command()[0])  # the app opens again
        self.assertEqual(dlg.state.text(), "Done — the app closes now and opens again.")

    def test_a_failed_download_says_why(self):
        dlg = update_window.UpdateDialog(None, dict(self.FEED), "setup")
        self.addCleanup(dlg.close)
        with mock.patch.object(updates_core, "download", side_effect=updates_core.UpdateError("its SHA-256 differs")), \
                mock.patch.object(updates_core, "start_setup") as setup:
            dlg.install_btn.click()
            self.assertTrue(wait_until(lambda: dlg.state.text().startswith("⚠")))
        self.assertEqual(dlg.state.text(), "⚠ its SHA-256 differs")
        self.assertTrue(dlg.install_btn.isEnabled())
        self.assertFalse(setup.called)

    def test_a_copy_that_cannot_update_itself(self):
        opened = []
        with mock.patch.object(update_window, "QDesktopServices", types.SimpleNamespace(
                openUrl=lambda url: opened.append(url.toString()) or True)):
            dlg = update_window.UpdateDialog(None, dict(self.FEED), "")
            self.addCleanup(dlg.close)
            self.assertEqual(dlg.install_btn.text(), "Download Page")
            self.assertIn("does not update itself", " ".join(l.text() for l in dlg.findChildren(QLabel)))
            dlg.install_btn.click()
        self.assertEqual(opened, ["https://themechanic.store/pc"])


class ConsoleChoiceTest(UiCase):
    def view_with(self, how):
        view = self.loaded_view(prefs={"console": how})
        return view

    def test_automatic_uses_spice_when_the_vm_has_it(self):
        view = self.view_with("auto")
        with mock.patch.object(DemoPve, "has_spice", return_value=True), \
                mock.patch.object(DemoPve, "spice_config", return_value={"type": "spice", "password": "x"}), \
                mock.patch.object(host_view.spice, "viewer", return_value="/usr/bin/remote-viewer"), \
                mock.patch.object(host_view.spice, "launch") as launch:
            self.select(view, 201)
            view.guest_action("console")
            self.assertTrue(wait_until(lambda: launch.called))
        self.assertEqual(launch.call_args[0][0]["type"], "spice")
        self.assertEqual(console.OPEN, {})

    def starting(self, vmid):
        """As VM 103 at its first boot (26/10): its USB tablet set, but its system has not started it yet — only
        QEMU's relative PS/2 mouse, so remote-viewer would capture the pointer."""
        cluster = DemoPve._clusters["demo-pve"]
        cluster.guests[vmid].setdefault("extra", {}).update(tablet="1", ostype="win11")
        cluster.pending_keys[vmid] = {"tablet"}

    def spice_ready(self):
        """remote-viewer here, the VM offering SPICE: what would open it is caught, nothing opens on the desktop."""
        patches = (mock.patch.object(DemoPve, "has_spice", return_value=True),
                   mock.patch.object(DemoPve, "spice_config", return_value={"type": "spice", "password": "x"}),
                   mock.patch.object(host_view.spice, "viewer", return_value="/usr/bin/remote-viewer"),
                   mock.patch.object(host_view.spice, "launch"))
        started = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)
        self.addCleanup(console.close_all)
        return started[-1]

    def test_no_spice_before_the_tablet(self):
        view = self.view_with("auto")
        self.starting(201)
        launch = self.spice_ready()
        self.select(view, 201)
        view.guest_action("console")  # automatic: the built-in console, and why
        self.assertTrue(wait_until(lambda: f"{DEMO_HOSTS[0].id}/201" in console.OPEN))
        self.assertFalse(launch.called)
        self.assertTrue(any("has not started its USB tablet yet" in n for n in self.notes))
        console.close_all()
        self.answer = False  # SPICE chosen outright: asked first — cancelled, nothing opens
        view.open_selected_console("spice")
        self.assertTrue(wait_until(lambda: "Open the built-in console instead?" in self.asked))
        self.assertEqual((console.OPEN, launch.called), ({}, False))
        self.answer = "instead"  # "SPICE Anyway"
        view.open_selected_console("spice")
        self.assertTrue(wait_until(lambda: launch.called))
        self.answer = True  # "Built-in Console"
        view.open_selected_console("spice")
        self.assertTrue(wait_until(lambda: f"{DEMO_HOSTS[0].id}/201" in console.OPEN))
        self.assertEqual(launch.call_count, 1)

    def test_spice_once_the_tablet_is_up_or_without_one(self):
        view = self.view_with("auto")
        self.starting(201)
        DemoPve._clusters["demo-pve"].pending_keys.pop(201)  # the system started it: SPICE as always
        launch = self.spice_ready()
        self.select(view, 201)
        view.guest_action("console")
        self.assertTrue(wait_until(lambda: launch.called))
        DemoPve._clusters["demo-pve"].guests[201]["extra"]["tablet"] = "0"  # no tablet (Proxmox's SPICE): as before
        view.guest_action("console")
        self.assertTrue(wait_until(lambda: launch.call_count == 2))
        self.assertEqual(console.OPEN, {})

    def test_automatic_falls_back_to_the_builtin_console(self):
        view = self.view_with("auto")
        self.select(view, 201)
        with mock.patch.object(host_view.spice, "viewer", return_value=None):  # no remote-viewer here
            view.guest_action("console")
            self.assertTrue(wait_until(lambda: f"{DEMO_HOSTS[0].id}/201" in console.OPEN))
        console.close_all()

    def test_each_way_from_the_arrow(self):
        view = self.view_with("spice")
        self.select(view, 100)  # a container: SPICE is for VMs
        view.open_selected_console("spice")
        self.assertIn(f"{DEMO_HOSTS[0].id}/100", console.OPEN)
        console.close_all()
        self.select(view, 201)
        with mock.patch.object(host_view.QDesktopServices, "openUrl") as open_url:
            view.open_selected_console("browser")
        self.assertIn("console=kvm", open_url.call_args[0][0].toString())
        view.open_selected_console("spice")  # demo mode has no SPICE: said so, with the alternative
        self.assertTrue(wait_until(lambda: self.errors))
        self.assertIn("built-in console", self.errors[-1][1])
        menu = view.act["console"].menu()
        self.assertEqual([a.text() for a in menu.actions()], [t for _h, t in host_view.CONSOLE_WAYS])


class GraphWallTest(UiCase):
    def open(self):
        DemoPve(DEMO_HOSTS[0])
        wall = graph_wall.show_wall("demo-pve", lambda: DemoPve(DEMO_HOSTS[0]), self.runner, "Home")
        wall.resize(1600, 1000)
        self.assertTrue(wait_until(lambda: wall.tiles))
        return wall

    def test_a_card_for_every_running_guest(self):
        wall = self.open()
        self.assertEqual(sorted(wall.tiles), [100, 101, 201])  # pihole, nextcloud, ubuntu-desktop
        self.assertIsNone(wall.parentWidget())  # its own window, for any screen
        self.assertTrue(wait_until(lambda: all(t.cpu.points and t.mem.points for t in wall.tiles.values())))
        self.assertIn("CPU", wall.tiles[201].numbers.text())
        wall.containers.setChecked(False)  # VMs only
        self.assertEqual(sorted(wall.tiles), [201])
        wall.containers.setChecked(True)
        self.assertEqual(sorted(wall.tiles), [100, 101, 201])

    def test_cards_come_and_go_with_the_guests(self):
        wall = self.open()
        pve = DemoPve(DEMO_HOSTS[0])
        pve.guest_action("pve", "lxc", 102, "start")
        pve.guest_action("pve", "qemu", 200, "start")
        wall.refresh_list()  # what its timer does every 10 seconds
        self.assertTrue(wait_until(lambda: sorted(wall.tiles) == [100, 101, 102, 200, 201]))
        self.assertTrue(wait_until(lambda: wall.tiles[200].cpu.points))  # a new card gets its charts at once
        pve.guest_action("pve", "lxc", 100, "stop")
        wall.refresh_list()
        self.assertTrue(wait_until(lambda: sorted(wall.tiles) == [101, 102, 200, 201]))
        self.assertIn("4 running", wall.status.text())

    def test_every_card_fits_and_shrinks_as_guests_start(self):
        wall = self.open()
        QTest.qWait(50)
        three = wall.tiles[201].height()
        pve = DemoPve(DEMO_HOSTS[0])
        for kind, vmid in (("lxc", 102), ("qemu", 200)):
            pve.guest_action("pve", kind, vmid, "start")
        for vmid in (300, 301, 302, 303):  # more running VMs than the demo has
            pve.cluster.guests[vmid] = {"vmid": vmid, "type": "qemu", "name": f"vm{vmid}", "status": "running",
                                        "cores": 2, "memory": 2048, "disk_gb": 10, "onboot": 0, "ip": "",
                                        "description": ""}
        wall.refresh_list()
        self.assertTrue(wait_until(lambda: len(wall.tiles) == 9))
        QTest.qWait(50)
        self.assertEqual(wall.columns, 3)  # 9 cards: 3 × 3
        self.assertLess(wall.tiles[201].height(), three)  # smaller, so that all of them fit
        self.assertEqual(wall.scroll.verticalScrollBar().maximum(), 0)  # nothing hidden below

    def test_best_columns(self):
        sizes = []
        for n in range(1, 15):
            cols = graph_wall.best_columns(n, 1880, 1000)
            rows = -(-n // cols)
            self.assertGreaterEqual(cols * rows, n)
            sizes.append(min(1880 / cols / graph_wall.TILE_ASPECT, 1000 / rows))
        self.assertEqual(sizes, sorted(sizes, reverse=True))  # more guests, never bigger cards

    def test_double_click_and_closing(self):
        wall = self.open()
        QTest.mouseDClick(wall.tiles[201], Qt.MouseButton.LeftButton)
        self.assertIn("demo-pve/201", guest_dialogs.GRAPHS)
        self.assertIs(graph_wall.show_wall("demo-pve", lambda: DemoPve(DEMO_HOSTS[0]), self.runner, "Home"), wall)
        wall.close()
        self.assertFalse(wall.list_timer.isActive() or wall.chart_timer.isActive())
        self.assertNotIn("demo-pve", graph_wall.WALLS)


class WindowsLookTest(UiCase):
    """What the app shows and does on Windows that it does not on Linux (and the reverse)."""

    def test_own_taskbar_button(self):
        class Shell32:
            def __init__(self):
                self.ids = []

            def SetCurrentProcessExplicitAppUserModelID(self, app_id):
                self.ids.append(app_id)
                return 0  # S_OK

        shell = Shell32()
        self.assertTrue(app_module.set_windows_app_id("win32", shell))
        self.assertEqual(shell.ids, ["store.themechanic.ProxmoxController"])  # the installer's shortcut: the same
        self.assertFalse(app_module.set_windows_app_id("linux", shell))
        self.assertFalse(app_module.set_windows_app_id("win32", object()))  # (no such call: nothing breaks)

    def test_openssh_hint(self):
        self.assertIn("Optional features → OpenSSH Client", ssh_core.install_hint("win32"))
        self.assertIn("apt install openssh-client", ssh_core.install_hint("linux"))

    def test_gnome_note_only_on_linux(self):
        from proxmox_controller.ui import settings as settings_ui
        from proxmox_controller.ui.settings import SettingsDialog
        win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)
        self.addCleanup(win.close)
        for platform, shown in (("linux", True), ("win32", False)):
            with mock.patch.object(settings_ui.sys, "platform", platform), mock.patch.object(store, "save_settings"):
                dlg = SettingsDialog(win)
            self.addCleanup(dlg.close)
            self.assertEqual(dlg.place_note.isVisibleTo(dlg), shown, platform)
            self.assertTrue(dlg.place.isVisibleTo(dlg))  # the option itself: on both

    def test_windows_toast_while_a_request_waits(self):
        shown = []

        class Tray:
            MessageIcon = mock.Mock()

            def __init__(self, icon):
                self.visible = False

            @staticmethod
            def isSystemTrayAvailable():
                return True

            def setToolTip(self, text):
                pass

            def show(self):
                self.visible = True

            def hide(self):
                self.visible = False

            def showMessage(self, title, body, icon, ms):
                shown.append((title, body, ms))

        connector._TRAY.clear()
        self.addCleanup(connector._TRAY.clear)
        with mock.patch.object(connector.sys, "platform", "win32"), \
                mock.patch("PySide6.QtWidgets.QSystemTrayIcon", Tray):
            connector.notify_desktop("Claude asks", "Start VM 100 (Win) — on Home")
        self.assertEqual(shown, [("Claude asks", "Start VM 100 (Win) — on Home", 20000)])
        self.assertTrue(connector._TRAY["icon"].visible)  # only while the toast is up
        self.assertTrue(connector._TRAY["timer"].isActive())
        connector._TRAY["timer"].timeout.emit()
        self.assertFalse(connector._TRAY["icon"].visible)


class WindowPlaceTest(UiCase):
    def test_xwayland_only_where_it_helps(self):
        on = {"remember_place": True}
        wayland = {"XDG_SESSION_TYPE": "wayland", "DISPLAY": ":0"}
        self.assertEqual(app_module.choose_platform(on, wayland, "linux"), "xcb")
        self.assertIsNone(app_module.choose_platform({"remember_place": False}, wayland, "linux"))  # turned off
        self.assertIsNone(app_module.choose_platform(on, {**wayland, "QT_QPA_PLATFORM": "wayland"}, "linux"))
        self.assertIsNone(app_module.choose_platform(on, {"XDG_SESSION_TYPE": "x11", "DISPLAY": ":0"}, "linux"))
        self.assertIsNone(app_module.choose_platform(on, {"XDG_SESSION_TYPE": "wayland"}, "linux"))  # no XWayland
        self.assertIsNone(app_module.choose_platform(on, wayland, "win32"))

    def test_startup_id_reaches_the_desktop_on_x11(self):
        sid = "gnome-shell/Proxmox Controller/3110-18-user-System_TIME30391863"  # as GNOME 50 gave it
        env = {"DESKTOP_STARTUP_ID": sid, "QT_QPA_PLATFORM": "xcb", "XDG_SESSION_TYPE": "wayland", "DISPLAY": ":0"}
        app_module.escape_startup_id(env)
        self.assertEqual(env["DESKTOP_STARTUP_ID"], "gnome-shell/Proxmox\\ Controller/3110-18-user-System_TIME30391863")
        try:  # read back the way the desktop reads it: the whole ID, not "gnome-shell/Proxmox"
            import ctypes
            sn = ctypes.CDLL("libstartup-notification-1.so.0")
        except OSError:
            sn = None
        if sn is not None:
            P = ctypes.POINTER(ctypes.c_char_p)
            prefix, names, values = ctypes.c_char_p(), P(), P()
            for message, wanted in ((f"remove: ID={sid}", "gnome-shell/Proxmox"),  # what Qt sent before
                                    (f"remove: ID={env['DESKTOP_STARTUP_ID']}", sid)):
                self.assertTrue(sn.sn_internal_unserialize_message(message.encode(), ctypes.byref(prefix),
                                                                   ctypes.byref(names), ctypes.byref(values)))
                self.assertEqual((names[0], values[0].decode()), (b"ID", wanted))
        same = {"DESKTOP_STARTUP_ID": sid, "XDG_SESSION_TYPE": "wayland", "DISPLAY": ":0"}  # Qt on Wayland
        app_module.escape_startup_id(same)
        self.assertEqual(same["DESKTOP_STARTUP_ID"], sid)
        both = {"DESKTOP_STARTUP_ID": sid, "QT_QPA_PLATFORM": "wayland;xcb"}
        app_module.escape_startup_id(both)
        self.assertEqual(both["DESKTOP_STARTUP_ID"], sid)
        x11 = {"DESKTOP_STARTUP_ID": 'a "b"\\c', "XDG_SESSION_TYPE": "x11", "DISPLAY": ":0"}  # an X11 session
        app_module.escape_startup_id(x11)
        self.assertEqual(x11["DESKTOP_STARTUP_ID"], 'a\\ \\"b\\"\\\\c')
        app_module.escape_startup_id(empty := {"QT_QPA_PLATFORM": "xcb"})  # started from a terminal: nothing to do
        self.assertNotIn("DESKTOP_STARTUP_ID", empty)

    def test_main_window_reopens_as_it_was_closed(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d, "APPDATA": d}):
            win = MainWindow([], DemoPve)
            win.resize(733, 577)  # (the test platform's screen is 800 × 800; a saved place is kept on screen)
            win.close()
            self.assertIn("main", store.load_settings()["geometry"])
            again = MainWindow([], DemoPve)
            try:
                self.assertEqual((again.width(), again.height()), (733, 577))
            finally:
                again.close()

    def test_wall_and_graphs_remember_their_place(self):
        prefs, saves = {"geometry": {}}, []
        DemoPve(DEMO_HOSTS[0])
        make = lambda: DemoPve(DEMO_HOSTS[0])  # noqa: E731
        wall = graph_wall.show_wall("h", make, self.runner, "Home", prefs, lambda: saves.append(1))
        wall.resize(750, 520)
        wall.close()
        self.assertIn("wall/h", prefs["geometry"])
        self.assertTrue(saves)
        wall = graph_wall.show_wall("h", make, self.runner, "Home", prefs, lambda: saves.append(1))
        self.assertEqual((wall.width(), wall.height()), (750, 520))
        g = next(x for x in make().guests() if x["vmid"] == 201)
        dlg = guest_dialogs.show_graphs("h/201", make, self.runner, g, "Home", prefs, lambda: saves.append(1))
        dlg.resize(700, 660)  # (its charts need about 600 of height)
        dlg.close()
        dlg = guest_dialogs.show_graphs("h/201", make, self.runner, g, "Home", prefs, lambda: saves.append(1))
        self.assertEqual((dlg.width(), dlg.height()), (700, 660))


class BackupsTest(UiCase):
    def client(self):
        return DemoPve(DEMO_HOSTS[0])

    def guest(self, vmid):
        return next(g for g in self.client().guests() if g["vmid"] == vmid)

    def dialog(self, vmid):
        dlg = backups.BackupsDialog(None, self.client, self.runner, self.guest(vmid))
        self.assertTrue(wait_until(lambda: dlg.storage.count()))
        return dlg

    def test_progress_lines(self):
        self.assertEqual(backups.progress_of("INFO:  42% (13.5 GiB of 32.0 GiB) in 1m 20s, read: 120 MiB/s"),
                         (42, "42 % — 13.5 GiB of 32.0 GiB"))
        self.assertEqual(backups.progress_of("progress 7% (read 1234 bytes, duration 3 sec)")[0], 7)
        self.assertEqual(backups.progress_of("INFO: starting new backup job"), (None, "starting new backup job"))

    def test_list_and_back_up_now(self):
        dlg = self.dialog(101)
        self.assertEqual(dlg.table.rowCount(), 2)
        self.assertEqual(dlg.heading.text(), "Backups of nextcloud  (2)")
        protected_row = next(r for r in range(2) if dlg.backups[r]["protected"])
        self.assertFalse(dlg.table.item(protected_row, 0).icon().isNull())  # the lock
        dlg.table.selectRow(protected_row)
        self.assertFalse(dlg.delete_btn.isEnabled())  # protected: unprotect first
        self.assertEqual(dlg.protect_btn.text(), "Unprotect")
        dlg.note.setText("{{guestname}} before an update")
        seen = []
        dlg.progress.valueChanged.connect(seen.append)
        dlg.back_up()
        self.assertFalse(dlg.backup_btn.isEnabled())  # one at a time
        self.assertTrue(wait_until(lambda: dlg.table.rowCount() == 3))
        self.assertIn("Backup finished", dlg.status.text())
        self.assertIn(100, seen)  # the bar followed Proxmox's percentages
        self.assertTrue(dlg.backup_btn.isEnabled())
        self.assertEqual(dlg.backups[0]["notes"], "nextcloud before an update")

    def test_protect_and_delete(self):
        dlg = self.dialog(101)
        row = next(r for r in range(2) if not dlg.backups[r]["protected"])
        volid = dlg.backups[row]["volid"]
        dlg.table.selectRow(row)
        dlg.toggle_protect()
        self.assertTrue(wait_until(lambda: dlg.selected() and dlg.selected()["protected"]))
        self.assertFalse(dlg.delete_btn.isEnabled())
        dlg.toggle_protect()
        self.assertTrue(wait_until(lambda: dlg.selected() and not dlg.selected()["protected"]))
        self.answer = False
        dlg.delete()
        QTest.qWait(100)
        self.assertEqual(len(dlg.backups), 2)
        self.answer = True
        dlg.delete()
        self.assertTrue(wait_until(lambda: dlg.table.rowCount() == 1))
        self.assertNotIn(volid, [b["volid"] for b in dlg.backups])

    def test_restore_choices(self):
        g = self.guest(101)  # running
        b = self.client().backups("pve", 101)[0]
        dlg = backups.RestoreDialog(None, g, b, 103, ["local-lvm"])
        self.assertFalse(dlg.replace.isEnabled())  # running: only as a new one
        self.assertTrue(dlg.as_new.isChecked())
        self.assertEqual(dlg.choice(), {"vmid": 103, "replace": False, "storage": "", "start": False, "unique": None})
        self.assertFalse(dlg.keep_mac.isVisibleTo(dlg))  # the guest exists: a copy gets new addresses
        stopped = {**self.guest(102)}
        dlg = backups.RestoreDialog(None, stopped, b, 103, ["local-lvm"])
        self.assertTrue(dlg.replace.isChecked())
        self.assertFalse(dlg.go.isEnabled())  # replacing needs the name typed
        dlg.typed.setText("test-box")
        self.assertTrue(dlg.go.isEnabled())
        self.assertTrue(dlg.choice()["replace"])

    def test_restore_as_a_new_guest(self):
        dlg = self.dialog(101)
        dlg.table.selectRow(0)

        class Chooser:
            def __init__(self, parent, guest, backup, next_id, storages):
                self.next_id = next_id

            def exec(self):
                return QDialog.DialogCode.Accepted

            def choice(self):
                return {"vmid": self.next_id, "replace": False, "storage": "", "start": True}

        with mock.patch.object(backups, "RestoreDialog", Chooser):
            dlg.restore()
            self.assertTrue(wait_until(lambda: 103 in self.cluster().guests and "Restored" in dlg.status.text()))
        new = self.cluster().guests[103]
        self.assertEqual((new["name"], new["status"]), ("nextcloud", "running"))


class DeletedBackupsTest(UiCase):
    def client(self):
        return DemoPve(DEMO_HOSTS[0])

    def deleted(self, vmid, *protected):
        """Backups of a guest, then the guest deleted with them kept: what this window is for."""
        self.client()  # (the pretend cluster comes with the first connection)
        c = self.cluster()
        for hours, p in enumerate(protected, 1):
            c.backups.append(c._backup_entry(c.guests[vmid], "local", time.time() - hours * 3600,
                                             c.guests[vmid]["name"], p))
        del c.guests[vmid]

    def dialog(self, rows):
        dlg = backups.DeletedBackupsDialog(None, self.client, self.runner, "Home")
        self.addCleanup(dlg.close)
        self.assertTrue(wait_until(lambda: dlg.table.rowCount() == rows and (
            dlg.heading.text().endswith(f"({rows})") if rows else dlg.heading.text().startswith("No backups"))))
        return dlg

    def test_none(self):
        dlg = self.dialog(0)
        self.assertIn("every backup here belongs to a guest that exists", dlg.heading.text())

    def test_list_protect_and_delete(self):
        self.deleted(102, False, True)
        dlg = self.dialog(2)
        self.assertEqual([b["vmid"] for b in dlg.backups], [102, 102])  # 101's are not here: 101 exists
        self.assertEqual(dlg.table.item(0, 1).text(), "Container 102 (test-box)")
        locked = next(r for r in range(2) if dlg.backups[r]["protected"])
        dlg.table.selectRow(locked)
        self.assertEqual((dlg.delete_btn.isEnabled(), dlg.protect_btn.text()), (False, "Unprotect"))
        dlg.table.selectRow(1 - locked)
        self.answer = True
        dlg.delete()
        self.assertTrue(wait_until(lambda: dlg.table.rowCount() == 1))
        self.assertTrue(dlg.backups[0]["protected"])

    def test_restore_brings_the_guest_back(self):
        self.deleted(102, False)
        dlg = self.dialog(1)
        dlg.table.selectRow(0)
        seen = {}

        class Chooser:
            def __init__(self, parent, guest, backup, next_id, storages, gone=False):
                seen.update(guest=guest, next_id=next_id, gone=gone)

            def exec(self):
                return QDialog.DialogCode.Accepted

            def choice(self):
                return {"vmid": seen["next_id"], "replace": False, "storage": "", "start": False, "unique": False}

        with mock.patch.object(backups, "RestoreDialog", Chooser):
            dlg.restore()
            self.assertTrue(wait_until(lambda: 102 in self.cluster().guests and "Restored" in dlg.status.text()))
        self.assertEqual((seen["next_id"], seen["gone"], seen["guest"]["type"]), (102, True, "lxc"))  # its old ID
        self.assertNotIn("unique", self.cluster().restored_with)  # and its old network addresses
        self.assertTrue(wait_until(lambda: dlg.heading.text().startswith("No backups")))  # it is its own again
        self.assertIn("Restored", dlg.status.text())  # and what was done is still said (it was written over)

    def test_old_id_taken_and_the_restore_window(self):
        self.deleted(102, False)
        c = self.cluster()
        c.guests[102] = {**c.guests[100], "vmid": 102, "name": "someone-else", "status": "stopped"}  # the ID reused
        c.backups.append(c._backup_entry({**c.guests[100], "vmid": 150, "type": "qemu"}, "local", time.time(),
                                         "old-vm", False))
        dlg = self.dialog(1)  # 102's backup now belongs to the new 102; only 150's is a deleted guest's
        self.assertEqual(dlg.table.item(0, 1).text(), "VM 150 (old-vm)")
        b = dlg.backups[0]
        win = backups.RestoreDialog(None, {"vmid": 150, "type": "qemu", "name": "old-vm"}, b, 150, ["local-lvm"],
                                    gone=True)
        self.assertFalse(win.replace.isVisibleTo(win))  # nothing to replace
        self.assertTrue(win.keep_mac.isVisibleTo(win) and win.keep_mac.isChecked())
        self.assertTrue(win.go.isEnabled())
        self.assertEqual(win.choice(), {"vmid": 150, "replace": False, "storage": "", "start": False, "unique": False})
        win.keep_mac.setChecked(False)
        self.assertTrue(win.choice()["unique"])

    def test_from_the_host_page(self):
        self.deleted(102, False)
        view = self.loaded_view()
        self.addCleanup(view.close)
        self.assertTrue(wait_until(lambda: view.nodes))
        actions = [a.text() for a in view.jobs_btn.menu().actions()]
        self.assertEqual(actions, ["Backup Jobs…", "Backups of Deleted Guests…"])
        view.jobs_btn.menu().actions()[1].trigger()
        self.assertTrue(wait_until(lambda: view.deleted_dialog and view.deleted_dialog.table.rowCount() == 1))
        view.deleted_dialog.close()


class HostShellTest(UiCase):
    """Console and Upgrade of the host: SSH set up the first time (its host key confirmed, a key if wanted), then the
    terminal. ssh itself and the terminal are stand-ins here: nothing reaches a host, no window opens."""

    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyOfThePretendPve"
    PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITheAppsOwnKeyForTests proxmox-controller@box"

    def setUp(self):
        super().setUp()
        config = os.path.join(self.private, "config")
        env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config, "APPDATA": config})
        env.start()  # the app's own ssh folder, never the real one
        self.addCleanup(env.stop)
        self.host_key, self.ran, self.fail_password = self.KEY, [], None
        for name, fake in (("missing_tools", lambda: []), ("scan_host_key", lambda h, p=22: self.host_key),
                           ("ensure_key", lambda: self.PUB), ("public_line", lambda: self.PUB),
                           ("run_with_password", self.fake_password), ("run_with_key", self.fake_key)):
            patch = mock.patch.object(ssh_core, name, fake)
            patch.start()
            self.addCleanup(patch.stop)
        self.saves = []

    def fake_password(self, host, port, user, password, script, **_):
        if self.fail_password:
            raise ssh_core.SshError(self.fail_password)
        self.ran.append(("password", host, port, user, password, script))
        return ""

    def fake_key(self, host, port, user, script, **_):
        self.ran.append(("key", host, port, user, script))
        return ""

    def host(self, **ssh_settings):
        h = Host(id="h", name="Home", address="192.0.2.80:8006", extra={"ssh": ssh_settings} if ssh_settings else {})
        return h

    def dialog(self, host, first_time=True):
        dlg = host_shell.SshDialog(None, host, self.runner, lambda: self.saves.append(1), first_time=first_time)
        self.addCleanup(dlg.close)
        self.assertTrue(wait_until(lambda: bool(dlg.scanned)))
        return dlg

    def test_first_time_with_a_key(self):
        h = self.host()
        dlg = self.dialog(h)
        self.assertIn(host_shell.fingerprint_lines(ssh_core.fingerprint(self.KEY)), dlg.hostkey.text())
        self.assertTrue(dlg.use_key.isChecked())  # offered at first
        self.assertTrue(dlg.password.isVisibleTo(dlg))
        self.assertFalse(dlg.go.isEnabled())  # not without the password the key is added with
        dlg.password.setText("root pw")
        self.assertTrue(dlg.go.isEnabled())
        dlg.save()
        self.assertTrue(wait_until(lambda: dlg.result() == QDialog.DialogCode.Accepted))
        kind, host, port, user, password, script = self.ran[0]
        self.assertEqual((kind, host, port, user, password), ("password", "192.0.2.80", 22, "root", "root pw"))
        self.assertIn(ssh_core.key_body(self.PUB), script)  # the app's key added on the host
        self.assertEqual(self.ran[1], ("key", "192.0.2.80", 22, "root", "true"))  # and tried once
        self.assertEqual(dlg.password.text(), "")  # the password is not kept
        s = h.extra["ssh"]
        self.assertEqual((s["user"], s["port"], s["key"], s["key_fp"]), ("root", 22, True, ssh_core.fingerprint(self.PUB)))
        self.assertEqual(self.saves, [1])
        self.assertEqual(ssh_core.trusted_host_key("192.0.2.80"), self.KEY)
        self.assertTrue(host_shell.ready(h))

    def test_password_only_and_a_refused_password(self):
        h = self.host()
        dlg = self.dialog(h)
        dlg.use_key.setChecked(False)
        self.assertFalse(dlg.password.isVisibleTo(dlg))
        self.assertTrue(dlg.go.isEnabled())
        dlg.save()
        self.assertTrue(wait_until(lambda: dlg.result() == QDialog.DialogCode.Accepted))
        self.assertEqual((self.ran, h.extra["ssh"]["key"]), ([], False))  # nothing ran on the host
        h2, self.fail_password = self.host(), "The host did not accept the password (or the user name)."
        dlg = self.dialog(h2)
        dlg.password.setText("wrong")
        dlg.save()
        self.assertTrue(wait_until(lambda: "did not accept" in dlg.status.text()))
        self.assertNotEqual(dlg.result(), QDialog.DialogCode.Accepted)  # stays open to try again
        self.assertEqual(h2.extra, {})

    def test_changed_host_key_and_removing_the_key(self):
        ssh_core.trust_host_key("192.0.2.80", 22, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKey")
        h = self.host(user="root", port=22, key=True, key_fp="SHA256:x")
        dlg = self.dialog(h, first_time=False)
        self.assertIn("Not the key confirmed before", dlg.hostkey.text())
        self.assertTrue(dlg.remove_btn.isVisibleTo(dlg))
        self.assertFalse(dlg.use_key.isEnabled())
        dlg.remove_key()
        self.assertTrue(wait_until(lambda: h.extra["ssh"]["key"] is False))
        self.assertEqual(self.ran[-1][:4], ("key", "192.0.2.80", 22, "root"))
        self.assertIn("grep -vF", self.ran[-1][4])  # taken off through the link, not with sed -i
        self.assertNotIn("key_fp", h.extra["ssh"])

    def test_missing_openssh(self):
        with mock.patch.object(ssh_core, "missing_tools", lambda: ["ssh-keyscan"]):
            dlg = host_shell.SshDialog(None, self.host(), self.runner, lambda: None, first_time=True)
            self.addCleanup(dlg.close)
        self.assertFalse(dlg.go.isEnabled())
        self.assertIn(ssh_core.install_hint(), dlg.status.text())  # this computer's way to get it

    def test_buttons_console_and_upgrade(self):
        view = self.loaded_view()
        self.addCleanup(view.close)
        head = view.edit_btn.parentWidget().layout().itemAt(0).layout()
        shown = [head.itemAt(i).widget() for i in range(head.count()) if head.itemAt(i).widget() is not None]
        order = [w for w in shown if w in (view.reboot_btn, view.console_btn, view.upgrade_btn)]
        self.assertEqual(order, [view.reboot_btn, view.console_btn, view.upgrade_btn])  # after Reboot Host, as asked
        self.assertTrue(wait_until(lambda: view.upgrade_btn.text() == "Upgrade (1)"))  # Debian's: enterprise refuses
        # set up already: the terminal opens at once, with the app's key
        view.host.extra["ssh"] = {"user": "root", "port": 22, "key": True}
        ssh_core.trust_host_key(view.host.hostname, 22, self.KEY)
        view.open_host_console()
        self.assertEqual(len(self.terminals), 1)
        self.assertEqual(self.titles[0], f"Proxmox Console — {view.host.name}")  # (it said "sh")
        self.assertIn(f"root@{view.host.hostname}", self.terminals[0])
        self.assertIn("-i", self.terminals[0])
        # the upgrade, on a host without a subscription (as the user's): only Debian's update shows, the check is
        # refused by the enterprise repository — said in the window, not as an error — and No-Subscription fixes it
        view.open_upgrade()
        dlg = view.upgrade_dialog
        self.assertTrue(wait_until(lambda: dlg.table.rowCount() == 1 and dlg.switch_btn.isVisibleTo(dlg)))
        self.assertIn("1 update waiting", dlg.heading.text())
        self.assertIn("Proxmox: Enterprise on", dlg.sources.text())
        self.assertIn("Ceph: Enterprise on", dlg.sources.text())
        dlg.check_now()
        self.assertTrue(wait_until(lambda: "Refused:" in dlg.status.text()))
        self.assertIn("enterprise.proxmox.com (401 Unauthorized — it needs a Proxmox subscription)", dlg.status.text())
        self.assertIn("The other sources were checked.", dlg.status.text())
        self.assertEqual(self.errors, [])  # no error window for what is normal without a subscription
        self.answer = False
        dlg.use_no_subscription()
        self.assertEqual(self.asked[-1], "Use the No-Subscription repository?")
        self.assertTrue(self.cluster()._repos_on("enterprise.proxmox.com"))  # Cancel: nothing changed
        self.answer = True
        dlg.use_no_subscription()
        self.assertTrue(wait_until(lambda: dlg.table.rowCount() == 3 and "every source answered" in dlg.status.text()))
        self.assertFalse(self.cluster()._repos_on("enterprise.proxmox.com"))
        self.assertTrue(wait_until(lambda: not dlg.switch_btn.isVisibleTo(dlg)))
        self.assertIn("Proxmox: Enterprise off, No-Subscription on", dlg.sources.text())
        self.assertEqual(dlg.table.item(0, 0).text(), "openssl")  # sorted by name
        dlg.go.click()
        self.assertEqual(self.terminals[-1][-1], "pveupgrade")
        self.assertEqual(self.titles[-1], f"Proxmox Upgrade — {view.host.name}")
        dlg.close()

    def test_first_console_asks_for_ssh_first(self):
        view = self.loaded_view()
        self.addCleanup(view.close)
        answers = []

        class Setup:  # the SSH window, answered as the user would
            def __init__(self_, parent, host, runner, saved, first_time=False):
                self_.host, self_.saved = host, saved

            def exec(self_):
                if answers.pop(0):
                    self_.host.extra["ssh"] = {"user": "root", "port": 22, "key": False}
                    ssh_core.trust_host_key(self_.host.hostname, 22, self.KEY)
                    self_.saved()
                    return QDialog.DialogCode.Accepted
                return QDialog.DialogCode.Rejected

        with mock.patch.object(host_shell, "SshDialog", Setup):
            answers.append(False)
            view.open_host_console()
            self.assertEqual(self.terminals, [])  # Cancel: nothing opens
            answers.append(True)
            view.open_host_console()
        self.assertEqual(len(self.terminals), 1)
        self.assertNotIn("-i", self.terminals[0])  # no key: ssh asks for the password in the terminal


class BackupJobsTest(UiCase):
    def client(self):
        return DemoPve(DEMO_HOSTS[0])

    def dialog(self):
        dlg = backup_jobs.BackupJobsDialog(None, self.client, self.runner, ["pve"], "Home")
        self.assertTrue(wait_until(lambda: dlg.table.rowCount() and dlg.storages))
        return dlg

    def cells(self, dlg, row=0):
        return [dlg.table.item(row, c).text() for c in range(dlg.table.columnCount())]

    def test_list_and_uncovered(self):
        dlg = self.dialog()
        on, when, who, storage, keep, nxt, comment = self.cells(dlg)
        self.assertEqual((on, when, who, storage, keep, comment),
                         ("Yes", "Every day at 03:00", "pihole, nextcloud", "local", "7 daily, 4 weekly", "the services"))
        self.assertNotEqual(nxt, "—")
        self.assertIn("102 test-box", dlg.uncovered.text())
        self.assertIn("201 ubuntu-desktop", dlg.uncovered.text())

    def test_job_settings(self):
        job = self.client().backup_jobs()[0]
        dlg = backup_jobs.JobDialog(None, job, self.client().guests(), ["local"])
        self.assertEqual((dlg.preset.currentData(), dlg.at.time().hour()), ("daily", 3))
        self.assertEqual(dlg.ticked(), [100, 101])
        self.assertEqual(dlg.keep["keep-daily"].value(), 7)
        dlg.which.setCurrentIndex(dlg.which.findData("except"))  # everyone but…
        for i in range(dlg.guests.count()):
            item = dlg.guests.item(i)
            item.setCheckState(Qt.CheckState.Checked if item.data(Qt.ItemDataRole.UserRole) == 102
                               else Qt.CheckState.Unchecked)
        dlg.preset.setCurrentIndex(dlg.preset.findData("weekly"))
        dlg.day.setCurrentIndex(dlg.day.findData("sat"))
        dlg.comment.setText("")
        p = dlg.params()
        self.assertEqual((p["schedule"], p["all"], p["exclude"]), ("sat 03:00", True, "102"))
        self.assertEqual(set(p["delete"].split(",")), {"vmid", "comment"})  # what no longer applies goes
        dlg.which.setCurrentIndex(dlg.which.findData("only"))
        for i in range(dlg.guests.count()):
            dlg.guests.item(i).setCheckState(Qt.CheckState.Unchecked)
        self.assertIn("Tick the guests", dlg.problem())

    def test_new_disable_run_and_delete(self):
        dlg = self.dialog()

        class Fake:
            def __init__(self, *a):
                pass

            def exec(self):
                return QDialog.DialogCode.Accepted

            def params(self):
                return {"enabled": True, "schedule": "sun 04:00", "storage": "local", "all": True, "mode": "stop"}

        with mock.patch.object(backup_jobs, "JobDialog", Fake):
            dlg.new()
            self.assertTrue(wait_until(lambda: dlg.table.rowCount() == 2))
        self.assertEqual(dlg.uncovered.text(), "Every guest is backed up by a job.")
        row = next(r for r in range(2) if self.cells(dlg, r)[1] == "Sundays at 04:00")
        dlg.table.selectRow(row)
        dlg.toggle()
        self.assertTrue(wait_until(lambda: dlg.selected() and str(dlg.selected()["enabled"]) == "0"))
        self.assertEqual(dlg.toggle_btn.text(), "Enable")
        nightly = next(r for r in range(2) if self.cells(dlg, r)[1] == "Every day at 03:00")
        dlg.table.selectRow(nightly)
        dlg.run_now()
        self.assertFalse(dlg.run_btn.isEnabled())
        self.assertTrue(wait_until(lambda: "The job ran" in dlg.status.text()))
        self.assertEqual(len(self.client().backups("pve", 101)), 3)  # its two old ones and this run's
        dlg.table.selectRow(row if row < dlg.table.rowCount() else 0)
        target = dlg.selected()["id"]
        dlg.delete()
        self.assertTrue(wait_until(lambda: target not in [j["id"] for j in dlg.jobs]))

    def test_guest_backups_say_which_job(self):
        g101 = next(g for g in self.client().guests() if g["vmid"] == 101)
        dlg = backups.BackupsDialog(None, self.client, self.runner, g101)
        self.assertTrue(wait_until(lambda: dlg.schedule.text()))
        self.assertEqual(dlg.schedule.text(), "Scheduled: Every day at 03:00 to local, keeps 7 daily, 4 weekly")
        g102 = next(g for g in self.client().guests() if g["vmid"] == 102)
        dlg = backups.BackupsDialog(None, self.client, self.runner, g102)
        self.assertTrue(wait_until(lambda: dlg.schedule.text()))
        self.assertIn("No backup job covers", dlg.schedule.text())


class BulkAndTasksTest(UiCase):
    def panel_column(self, view, col):
        t = view.tasks_panel.table
        return [t.item(r, col).text() for r in range(t.rowCount())]

    def bulk_dialog(self, view):
        dlgs = [d for d in view.findChildren(bulk.BulkDialog) if d.isVisible()]
        self.assertEqual(len(dlgs), 1)
        self.addCleanup(dlgs[0].close)
        return dlgs[0]

    def rows(self, dlg):
        return [(int(dlg.table.item(r, 0).text()), dlg.table.item(r, 0).checkState() == Qt.CheckState.Checked)
                for r in range(dlg.table.rowCount())]

    def test_tasks_panel_lists_and_folds(self):
        prefs = {}
        view = self.loaded_view(prefs=prefs)
        panel = view.tasks_panel
        self.assertEqual(self.panel_column(view, tasks_panel.COL_TASK),
                         ["VM 201 (ubuntu-desktop) — Start", "Backup", "Bulk start"])  # newest first
        self.assertEqual(panel.summary.text(), "last: VM 201 (ubuntu-desktop) — Start — OK")
        self.cluster().long_task("vzdump", 101, ["INFO: starting new backup job"])
        view.refresh()
        self.assertTrue(wait_until(lambda: panel.summary.text() == "1 running"))
        self.assertEqual(self.panel_column(view, tasks_panel.COL_STATUS)[0], "Running")
        self.assertEqual(self.panel_column(view, tasks_panel.COL_TASK)[0], "Container 101 (nextcloud) — Backup")
        self.assertTrue(panel.table.isVisibleTo(panel))  # open the first time
        self.assertTrue(panel.ticker.isActive())  # a running task's Took counts up between refreshes
        panel.toggle.click()
        self.assertFalse(panel.table.isVisibleTo(panel))
        self.assertFalse(panel.ticker.isActive())
        self.assertEqual((prefs["tasks_open"], self.saved_prefs), (False, 1))
        again = HostView(DEMO_HOSTS[0], DemoPve, self.runner, self.notes.append, lambda h: None, prefs=prefs)
        self.assertFalse(again.tasks_panel.table.isVisibleTo(again.tasks_panel))  # remembered

    def test_task_log_follows_and_stops(self):
        view = self.loaded_view()
        c = self.cluster()
        upid = c.long_task("vzdump", 101, ["INFO: starting new backup job", "INFO:  10% (3.2 GiB of 32.0 GiB)"])
        view.refresh()
        self.assertTrue(wait_until(lambda: view.tasks_panel.summary.text() == "1 running"))
        task = view.tasks_panel.tasks[0]
        view.open_task_log(task)
        view.open_task_log(task)  # the same window again, not a second one
        self.assertEqual(len(view.task_logs), 1)
        dlg = view.task_logs[upid]
        self.addCleanup(dlg.close)
        dlg.close()
        self.assertFalse(dlg.timer.isActive())
        view.open_task_log(task)  # closed and opened again: the same window follows the task again
        self.assertIs(view.task_logs[upid], dlg)
        self.assertTrue(dlg.isVisible() and dlg.timer.isActive())
        self.assertEqual(dlg.windowTitle(), "Task — Container 101 (nextcloud) — Backup")
        self.assertTrue(wait_until(lambda: "10% (3.2 GiB" in dlg.log.toPlainText()))
        self.assertTrue(dlg.stop_btn.isVisibleTo(dlg))
        c.task_logs[upid].append("INFO:  60% (19.2 GiB of 32.0 GiB)")
        self.assertTrue(wait_until(lambda: "60%" in dlg.log.toPlainText()))  # followed live
        self.assertEqual(dlg.log.toPlainText().count("10%"), 1)  # each line once
        dlg.stop()
        self.assertTrue(wait_until(lambda: dlg.ended))
        self.assertIn("Stop this task?", self.asked)
        self.assertIn("interrupted by signal", dlg.state.text())
        self.assertFalse(dlg.stop_btn.isVisibleTo(dlg))
        self.assertTrue(wait_until(lambda: self.panel_column(view, tasks_panel.COL_STATUS)[0] == "interrupted by signal"))
        self.assertEqual(view.tasks_panel.table.item(0, tasks_panel.COL_STATUS).foreground().color().name(),
                         theme.colors().danger)
        self.assertIn("1 failed", view.tasks_panel.summary.text())
        long_log = [f"INFO: line {i}" for i in range(1, 1201)]  # more than one read of the log brings
        c.finish_task(c.long_task("vzdump", 100, long_log))
        view.refresh()
        self.assertTrue(wait_until(lambda: view.tasks_panel.tasks[0]["id"] == "100" and
                                   not tasks_panel.tasks.running(view.tasks_panel.tasks[0])))
        view.open_task_log(view.tasks_panel.tasks[0])
        big = view.task_logs[view.tasks_panel.tasks[0]["upid"]]
        self.addCleanup(big.close)
        self.assertTrue(wait_until(lambda: "TASK OK" in big.log.toPlainText()))  # read to the end
        self.assertEqual(big.log.toPlainText().count("INFO: line"), 1200)
        done = next(t for t in view.tasks_panel.tasks if t["type"] == "qmstart")
        view.open_task_log(done)  # a finished one: its log, nothing to stop
        old = view.task_logs[done["upid"]]
        self.addCleanup(old.close)
        self.assertTrue(wait_until(lambda: "TASK OK" in old.log.toPlainText()))
        self.assertFalse(old.stop_btn.isVisibleTo(old))
        self.assertFalse(old.timer.isActive())

    def test_closed_logs_are_freed(self):
        view = self.loaded_view()
        for _ in range(8):
            self.cluster()._task("qmstart", 201)
        view.refresh()
        self.assertTrue(wait_until(lambda: len(view.tasks_panel.tasks) == 11))
        for task in view.tasks_panel.tasks[:9]:
            view.open_task_log(task)
            dlg = view.task_logs[task["upid"]]
            self.assertTrue(wait_until(lambda: not dlg.polling))
            dlg.close()
        self.assertEqual(len(view.task_logs), host_view.CLOSED_LOGS_KEPT + 1)  # the newest closed ones are kept

    def test_bulk_start_in_boot_order(self):
        view = self.loaded_view()
        pve = view.client()
        pve.update_config("pve", "qemu", 200, {"onboot": 1, "startup": "order=1,up=20"})
        pve.update_config("pve", "lxc", 102, {"onboot": 1, "startup": "order=2"})
        view._refresh_details(force=True)
        self.assertTrue(wait_until(lambda: (view.details.get(200) or {}).get("onboot")))
        view.bulk_start_btn.click()
        dlg = self.bulk_dialog(view)
        self.assertEqual(self.rows(dlg), [(200, True), (102, True)])  # the stopped ones, in boot order
        self.assertEqual(dlg.table.item(0, 3).text(), "1 · at boot")
        self.assertEqual(dlg.go.text(), "Start 2")
        dlg.tick("none")
        self.assertFalse(dlg.go.isEnabled())

        def click(row, col, dx=None):
            r = dlg.table.visualRect(dlg.table.model().index(row, col))
            at = r.center() if dx is None else QPoint(r.left() + dx, r.center().y())
            QTest.mouseClick(dlg.table.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, at)

        click(1, 1)  # on the name: the row is ticked too
        self.assertEqual(self.rows(dlg), [(200, False), (102, True)])
        QTest.qWait(400)  # not a double-click
        click(0, 0, 17)  # on the box itself: ticked once, not ticked and unticked again
        self.assertEqual(self.rows(dlg), [(200, True), (102, True)])
        self.assertEqual(dlg.go.text(), "Start 2")
        dlg.tick("onboot")
        dlg.go.click()
        self.assertTrue(wait_until(lambda: dlg.finished_ok, 10))
        self.assertEqual(self.cluster().last_bulk["vms"], "200,102")
        self.assertEqual(dlg.status.text(), "Done — 2 guest(s) started.")
        self.assertFalse(dlg.go.isVisibleTo(dlg))
        self.assertEqual(dlg.close_btn.text(), "Close")
        self.assertTrue(wait_until(lambda: {g["vmid"]: g["status"] for g in view.guests}[102] == "running"))
        self.assertTrue(wait_until(lambda: self.panel_column(view, tasks_panel.COL_TASK)[0] == "Bulk start"))

    def test_bulk_shut_down_options(self):
        view = self.loaded_view()
        view.bulk_stop_btn.click()
        dlg = self.bulk_dialog(view)
        self.assertEqual(self.rows(dlg), [(201, True), (101, True), (100, True)])  # running, reverse order
        dlg.table.item(0, 0).setCheckState(Qt.CheckState.Unchecked)
        dlg.timeout.setValue(60)
        dlg.force.setChecked(False)
        self.assertEqual(dlg.go.text(), "Shut Down 2")
        dlg.run()
        self.assertTrue(wait_until(lambda: dlg.finished_ok, 10))
        self.assertEqual(self.cluster().last_bulk, {"vms": "101,100", "timeout": "60", "force-stop": "0"})
        self.assertTrue(wait_until(lambda: {g["vmid"]: g["status"] for g in view.guests} ==
                                   {100: "stopped", 101: "stopped", 102: "stopped", 200: "stopped", 201: "running"}))

    def test_several_selected(self):
        view = self.loaded_view()
        enabled = lambda: {k for k, b in view.act.items() if b.isEnabled()}  # noqa: E731
        view._select([100, 102, 200])
        self.assertEqual(view.selected_vmids(), [100, 102, 200])
        self.assertIsNone(view.selected())  # one-guest actions need one guest
        self.assertEqual(enabled(), {"start", "shutdown", "stop", "reboot"})
        view.guest_action("start")  # through Bulk Start, with the selection ticked
        dlg = self.bulk_dialog(view)
        self.assertEqual(self.rows(dlg), [(102, True), (200, True)])  # none starts at boot, both chosen
        dlg.close()
        view._select([100, 101])
        view.guest_action("stop")
        self.assertEqual(self.asked, ["Stop 2 guests now?"])
        self.assertTrue(wait_until(lambda: [g["status"] for g in view.guests if g["vmid"] in (100, 101)] ==
                                   ["stopped", "stopped"]))
        view._select([102, 201])
        view.refresh()
        self.assertTrue(wait_until(lambda: not view.inflight))
        self.assertEqual(view.selected_vmids(), [102, 201])  # kept through a refresh
        view.hide_stopped.setChecked(True)
        self.assertEqual(view.selected_vmids(), [201])  # a hidden guest is not acted on unseen

    def test_tasks_that_cannot_be_read(self):
        DemoPve(DEMO_HOSTS[0]).cluster.forbidden.add(r"GET /nodes/pve/tasks")
        view = self.loaded_view()
        self.assertTrue(view.online)  # the rest of the page works
        self.assertTrue(view.tasks_panel.summary.text().startswith("Could not read the tasks"))
        self.assertEqual(view.tasks_panel.table.rowCount(), 0)


class VaultDialogTest(UiCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        for p in (mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name, "APPDATA": self.tmp.name}),
                  mock.patch.object(vault, "KDF", {"n": 1 << 10, "r": 8, "p": 1})):  # quick keys for the test
            p.start()
            self.addCleanup(p.stop)
        store.lock_session()
        self.addCleanup(store.lock_session)
        self.addCleanup(self.tmp.cleanup)
        store.save_hosts([Host(id="h1", name="Home", address="192.168.1.80", token_id="root@pam!c",
                               token_secret="s3cret", fingerprint="AB:CD")])

    def test_set_change_and_remove(self):
        dlg = vault_dialogs.PasswordDialog(None, "set")
        dlg.apply()
        self.assertEqual(dlg.problem.text(), "Type a password.")  # any password, but one
        dlg.new.setText("correct horse")
        dlg.again.setText("correct horsE")
        dlg.apply()
        self.assertIn("not the same", dlg.problem.text())
        dlg.again.setText("correct horse")
        dlg.apply()
        self.assertEqual((dlg.result(), store.secrets_state()), (QDialog.DialogCode.Accepted, "locked"))
        short = vault_dialogs.PasswordDialog(None, "change")
        short.current.setText("correct horse")
        short.new.setText("ab")
        short.again.setText("ab")
        short.apply()
        self.assertEqual(short.result(), QDialog.DialogCode.Accepted)  # no length rule: the user chooses
        store.set_password("correct horse")
        change = vault_dialogs.PasswordDialog(None, "change")
        change.current.setText("wrong horse")
        change.new.setText("battery staple")
        change.again.setText("battery staple")
        change.apply()
        self.assertIn("current password is wrong", change.problem.text())
        change.current.setText("correct horse")
        change.apply()
        self.assertEqual(change.result(), QDialog.DialogCode.Accepted)
        store.lock_session()
        with self.assertRaises(vault.WrongPassword):
            store.unlock("correct horse")  # the old one no longer opens them
        store.unlock("battery staple")
        remove = vault_dialogs.PasswordDialog(None, "remove")
        remove.current.setText("correct horse")
        remove.apply()
        self.assertEqual(store.secrets_state(), "locked")
        remove.current.setText("battery staple")
        remove.apply()
        self.assertEqual((store.secrets_state(), store.load_hosts()[0].token_secret), ("plain", "s3cret"))

    def test_unlock_and_forget(self):
        store.set_password("correct horse")
        store.lock_session()  # as at the next start
        dlg = vault_dialogs.UnlockDialog()
        dlg.password.setText("wrong horse")
        dlg.try_unlock()
        self.assertEqual((dlg.problem.text(), dlg.password.text()), ("Wrong password.", ""))
        self.assertFalse(store.is_unlocked())
        dlg.password.setText("correct horse")
        dlg.try_unlock()
        self.assertEqual(dlg.result(), QDialog.DialogCode.Accepted)
        self.assertEqual(store.load_hosts()[0].token_secret, "s3cret")
        store.lock_session()
        again = vault_dialogs.UnlockDialog()
        self.answer = False
        again.forget()
        self.assertEqual(store.secrets_state(), "locked")  # asked, and kept
        self.answer = True
        again.forget()
        self.assertEqual((again.result(), store.secrets_state()), (QDialog.DialogCode.Accepted, "none"))
        self.assertEqual([h.name for h in store.load_hosts()], ["Home"])  # the host stays, without its token

    def test_settings_show_the_lock(self):
        from proxmox_controller.ui.settings import SettingsDialog
        win = MainWindow(store.load_hosts(), DemoPve)
        try:
            dlg = SettingsDialog(win)
            shown = lambda: [b.text() for b in (dlg.lock_btn, dlg.change_btn, dlg.unlock_btn)  # noqa: E731
                             if b.isVisibleTo(dlg)]
            self.assertEqual(shown(), ["Lock with a Password…"])
            self.assertIn("could read them", dlg.lock_state.text())
            store.set_password("correct horse")
            dlg._show_lock()
            self.assertEqual(shown(), ["Change Password…", "Remove Password…"])
            demo = SettingsDialog(MainWindow(list(DEMO_HOSTS), DemoPve, demo=True))
            self.assertFalse(demo.lock_btn.isVisibleTo(demo))  # the pretend hosts have nothing to lock
        finally:
            win.close()


class ConnectorTest(UiCase):
    """Claude's requests through the app: the switches, the approval window, the lent privileges, the log."""

    def setUp(self):
        super().setUp()
        self.win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)
        self.addCleanup(self.win.close)
        self.conn = self.win.connector
        self.conn.notify_desktop = lambda title, body: self.desktop.append(body)
        self.desktop, self.windows, self.acted = [], [], []
        self.conn.asking.connect(self.windows.append)
        self.conn.acted.connect(self.acted.append)
        self.win.settings["claude"] = {"enabled": True}
        self.admin = DemoPve(DEMO_HOSTS[0])
        self.secret, _ = claude_access.setup(self.admin, claude_policy.host_switches(self.win.settings, "demo-pve"))
        self.conn.tokens.set("demo-pve", self.secret)

    def request(self, tool, wait=True, **args):
        """Claude's request, from a thread of its own as the link server would run it."""
        box = {}
        msg = {"key": f"k{len(self.windows)}-{tool}", "tool": tool, "args": args, "client": "Claude Code"}
        t = threading.Thread(target=lambda: box.setdefault("answer", self.conn.handle(msg)), daemon=True)
        t.start()
        box["key"] = msg["key"]
        if wait:
            self.assertTrue(wait_until(lambda: "answer" in box, 10), f"{tool} gave no answer")
        return box

    @staticmethod
    def text(box) -> str:
        return box["answer"]["result"]["content"][-1].get("text", "")

    def role(self):
        return self.admin.cluster.roles.get(claude_access.ROLE, [])

    def test_off_and_not_set_up(self):
        self.win.settings["claude"]["enabled"] = False
        self.assertIn("turned off", self.text(self.request("list_hosts")))
        self.win.settings["claude"]["enabled"] = True
        hosts = json.loads(self.text(self.request("list_hosts")))["hosts"]
        self.assertEqual([(h["host"], h["claude_access_set_up"]) for h in hosts], [("demo-pve", True), ("demo-pc", False)])
        self.assertEqual(hosts[0]["allowed"]["destroy"], "off")
        self.assertIn("not set up", self.text(self.request("list_guests", host="demo-pc")))
        answer = self.request("delete_guest", host="demo-pve", vmid=102, reason="tidy up")
        self.assertTrue(answer["answer"]["result"]["isError"])
        self.assertIn("Off for Home server (demo)", self.text(answer))
        self.assertIn(102, self.admin.cluster.guests)
        self.assertIn("unknown argument", self.text(self.request("list_guests", host="demo-pve", x=1)).lower())
        log = connector_log.last()
        self.assertEqual([e["decision"] for e in log], ["off", "allowed", "not-set-up", "off", "error"])
        self.assertEqual((log[3]["what"], log[3]["reason"]), ("Delete Container 102 (test-box)", "tidy up"))
        self.assertTrue(str(connector_log.path()).startswith(self.private))  # (the test's own log)

    def test_read_runs_at_once(self):
        guests = json.loads(self.text(self.request("list_guests", host="demo-pve")))
        self.assertEqual(len(guests), 5)
        self.assertEqual(self.windows, [])  # Read is On: no window
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))  # nothing was lent for it
        # Proxmox hides backups from a token that may not make them (Claude's, at rest): they are read with the user's
        self.assertEqual(len(self.admin.backups("pve", 101)), 2)
        self.assertEqual(len(json.loads(self.text(self.request("list_backups", host="demo-pve", vmid=101)))), 2)
        media = json.loads(self.text(self.request("list_install_media", host="demo-pve")))
        self.assertEqual(media["bridges"], ["vmbr0"])  # Proxmox hides bridges without SDN.Audit: Read has it

    def test_ask_allow_deny_and_an_hour(self):
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start",
                           reason="the test box is needed for the build")
        self.assertTrue(wait_until(lambda: self.windows))
        dlg = self.windows[-1]
        self.assertEqual(dlg.what.text(), "Start Container 102 (test-box)")
        self.assertIn("Claude asks", dlg.windowTitle())
        self.assertEqual(self.desktop, ["Start Container 102 (test-box) — on Home server (demo)"])
        claude = DemoPve(Host(id="demo-pve", name="x", address="192.0.2.80", token_id=claude_access.TOKEN_ID,
                              token_secret=self.secret, fingerprint="DEMO"))
        with self.assertRaises(PveError):  # while the user decides, Claude's token still cannot start anything
            claude.guest_action("pve", "lxc", 102, "start")
        dlg.allow_btn.click()
        self.assertFalse(dlg.isVisible())  # the window goes once answered
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        self.assertFalse(box["answer"]["result"]["isError"], self.text(box))
        self.assertEqual(self.admin.cluster.guests[102]["status"], "running")
        self.assertEqual(self.acted, ["demo-pve"])  # the host's page refreshes
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))  # what was lent went back
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="stop", reason="r")
        self.assertTrue(wait_until(lambda: len(self.windows) == 2))
        self.windows[-1].close()  # the window's X is a No
        self.assertFalse(self.windows[-1].isVisible())
        self.assertTrue(wait_until(lambda: "answer" in box))
        self.assertIn("denied", self.text(box))
        self.assertEqual(self.admin.cluster.guests[102]["status"], "running")
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="shutdown", reason="r")
        self.assertTrue(wait_until(lambda: len(self.windows) == 3))
        self.windows[-1].hour_btn.click()  # the button itself (not its arrow): 1 hour
        self.assertTrue(wait_until(lambda: "answer" in box))
        self.assertTrue(3600 - 60 < self.conn.allowances.remaining("demo-pve", "power") <= 3600)
        self.request("guest_power", host="demo-pve", vmid=102, action="start", reason="r")
        self.assertEqual(len(self.windows), 3)  # within the hour: no window
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=100, action="reboot", reason="r")
        self.request("guest_details", host="demo-pve", vmid=100)  # (reads go on meanwhile)
        self.assertEqual(len(self.windows), 3)
        self.assertTrue(wait_until(lambda: "answer" in box))
        decisions = [e["decision"] for e in connector_log.last()][-6:]
        self.assertEqual(decisions[:4], ["approved", "denied", "approved", "granted"])  # (hours given, not On)
        self.assertEqual(sorted(decisions[4:]), ["allowed", "granted"])  # the read (On) and the reboot, either first

    def test_hours_from_the_arrow(self):
        """The arrow beside 'Allow This Kind for 1 Hour' (19/10: Claude works the night through): 1, 3, 8 or 12
        hours of that kind — shown in Claude Access, and ended there by a click on the kind's switch."""
        access = claude_window.ClaudeWindow(self.win, self.conn, self.win.runner)
        self.addCleanup(access.close)
        access.show()
        power = next(r for r in access.rows if r.key == "power")
        self.assertFalse(power.grant.isVisible())
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start", reason="the tests")
        self.assertTrue(wait_until(lambda: self.windows))
        dlg = self.windows[-1]
        self.assertEqual(dlg.hour_btn.popupMode(), QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.assertEqual(dlg.hour_btn.height(), dlg.allow_btn.sizeHint().height())  # as tall as Allow beside it
        hours = dlg.hour_btn.menu().actions()
        self.assertEqual([a.text() for a in hours], ["For 1 Hour", "For 3 Hours", "For 8 Hours", "For 12 Hours"])
        hours[2].trigger()
        self.assertFalse(dlg.isVisible())
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        self.assertFalse(box["answer"]["result"]["isError"], self.text(box))
        self.assertTrue(8 * 3600 - 60 < self.conn.allowances.remaining("demo-pve", "power") <= 8 * 3600)
        self.assertEqual(self.conn.allowances.remaining("demo-pve", "change"), 0)  # that kind only
        self.assertTrue(wait_until(power.grant.isVisible))
        self.assertRegex(power.grant.text(), r"^· allowed without asking until \d\d:\d\d$")
        end = time.strftime("%H:%M", time.localtime(time.time() + 8 * 3600))
        self.assertIn(power.grant.text()[-5:], (end, time.strftime("%H:%M", time.localtime(time.time() + 8 * 3600 - 60))))
        self.assertFalse(next(r for r in access.rows if r.key == "change").grant.isVisible())
        self.request("guest_power", host="demo-pve", vmid=102, action="stop", reason="r")
        self.assertEqual(len(self.windows), 1)  # no window while the hours last
        self.assertTrue(wait_until(lambda: access.log.rowCount() >= 2))
        self.assertEqual(access.log.item(0, 4).text(), "Allowed (hours you gave)")
        self.assertEqual(access.log.item(1, 4).text(), "Approved by you")
        power.buttons["ask"].click()  # already Ask: the click ends the hours
        self.assertEqual(self.conn.allowances.remaining("demo-pve", "power"), 0)
        self.assertFalse(power.grant.isVisible())
        self.assertEqual(claude_policy.host_switches(self.win.settings, "demo-pve")["power"], "ask")
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start", reason="r")
        self.assertTrue(wait_until(lambda: len(self.windows) == 2))  # asked again
        self.windows[-1].deny_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box))
        self.assertEqual([connector.allowed_hours(a) for a in ("allow-hours:12", "allow-hours:5", "allow-hours:",
                                                               "allow-hours:24", "allow", "deny")],
                         [12, 0, 0, 0, 0, 0])  # only what the window offers

    def test_no_answer_and_cancel(self):
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start", reason="r")
        self.assertTrue(wait_until(lambda: self.windows))
        self.windows[-1].left = 1
        self.windows[-1]._tick()  # the two minutes are up
        self.assertTrue(wait_until(lambda: "answer" in box))
        self.assertIn("No answer from the user", self.text(box))
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start", reason="r")
        self.assertTrue(wait_until(lambda: len(self.windows) == 2))
        threading.Thread(target=lambda: self.conn.handle({"cancel": box["key"]}), daemon=True).start()
        self.assertTrue(wait_until(lambda: "answer" in box))
        self.assertIn("Cancelled", self.text(box))
        self.assertFalse(self.windows[-1].isVisible())
        self.assertEqual(self.admin.cluster.guests[102]["status"], "stopped")

    def test_host_command_shown_each_time_nothing_lent(self):
        """Host commands: Off for a new host (refused); on Ask the window shows the command, with a red Allow and no
        'for 1 hour' — every command seen — and Claude's token is lent nothing: it goes over SSH."""
        from proxmox_controller.core import connector_tools
        answer = self.request("host_command", host="demo-pve", command="systemctl is-active cloudflared", reason="r")
        self.assertIn("Host commands requests are Off", self.text(answer))
        claude_policy.set_switch(self.win.settings, "demo-pve", "host_commands", "ask")
        next(h for h in self.win.hosts if h.id == "demo-pve").extra["ssh"] = {"user": "root", "port": 22, "key": True}
        with mock.patch.object(connector_tools.ssh, "trusted_host_key", return_value="ssh-ed25519 AAAA"), \
                mock.patch.object(connector_tools.ssh, "run_command", return_value=(0, "active\n", "")) as run:
            box = self.request("host_command", wait=False, host="demo-pve", command="systemctl is-active cloudflared",
                               reason="see whether the tunnel's connector runs")
            self.assertTrue(wait_until(lambda: self.windows))
            dlg = self.windows[-1]
            shown = " ".join(w.text() for w in dlg.findChildren(type(dlg.what)))
            self.assertIn("systemctl is-active cloudflared", shown)
            self.assertFalse(dlg.hour_btn.isVisibleTo(dlg))
            self.assertEqual(dlg.allow_btn.property("kind"), "destructive")
            self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))
            dlg.allow_btn.click()
            self.assertTrue(wait_until(lambda: "answer" in box, 10))
        self.assertFalse(box["answer"]["result"]["isError"], self.text(box))
        self.assertEqual(json.loads(self.text(box))["stdout"], "active\n")
        run.assert_called_once()
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))  # nothing was lent

    def test_container_root_password_through_the_window(self):
        """A container's new root password: under Host commands (it goes over SSH as root); the window shows what
        runs and asks the user for the password twice; it reaches the host only as the command's input — Claude's
        answer and the log never hold it, and nothing is lent to Claude's token."""
        from proxmox_controller.core import connector_tools
        answer = self.request("set_container_root_password", host="demo-pve", vmid=100, reason="r")
        self.assertIn("Host commands requests are Off", self.text(answer))
        claude_policy.set_switch(self.win.settings, "demo-pve", "host_commands", "ask")
        next(h for h in self.win.hosts if h.id == "demo-pve").extra["ssh"] = {"user": "root", "port": 22, "key": True}
        with mock.patch.object(connector_tools.ssh, "trusted_host_key", return_value="ssh-ed25519 AAAA"), \
                mock.patch.object(connector_tools.ssh, "run_command", return_value=(0, "", "")) as run:
            box = self.request("set_container_root_password", wait=False, host="demo-pve", vmid=100,
                               reason="its root password is lost")
            self.assertTrue(wait_until(lambda: self.windows))
            dlg = self.windows[-1]
            shown = " ".join(w.text() for w in dlg.findChildren(type(dlg.what)))
            self.assertIn("pct exec 100 -- chpasswd", shown)
            self.assertIn("New root password of container 100", shown)
            self.assertFalse(dlg.hour_btn.isVisibleTo(dlg))
            self.assertEqual(dlg.allow_btn.property("kind"), "destructive")
            dlg.password.setText("abcd")
            dlg.again.setText("abcd")
            self.assertFalse(dlg.allow_btn.isEnabled())  # at least 5 characters, as Proxmox wants for a container
            dlg.password.setText("N3w root pass")
            dlg.again.setText("N3w root pass")
            self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))
            dlg.allow_btn.click()
            self.assertTrue(wait_until(lambda: "answer" in box, 10))
        self.assertFalse(box["answer"]["result"]["isError"], self.text(box))
        self.assertEqual(run.call_args.kwargs["input"], "root:N3w root pass\n")
        self.assertNotIn("N3w", run.call_args.args[3])  # not on the command line
        self.assertNotIn("N3w", json.dumps(box["answer"]))  # Claude is told only that it was changed
        self.assertNotIn("N3w", connector_log.path().read_text())  # nor is it in the log
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))  # nothing was lent

    def test_refusal_says_what_proxmox_checked(self):
        """Approved, yet Proxmox says no: Claude is told which privilege on which path — the way to find why."""
        self.admin.cluster.forbidden.add(r"POST /nodes/pve/lxc/\d+/status/.*")
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start", reason="r")
        self.assertTrue(wait_until(lambda: self.windows))
        self.windows[-1].allow_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        self.assertTrue(box["answer"]["result"]["isError"])
        self.assertIn("no privilege for this", self.text(box))
        self.assertIn("Proxmox said: Permission check failed (/vms, VM.PowerMgmt)", self.text(box))
        self.assertIn("Proxmox said: Permission check failed (/vms, VM.PowerMgmt)", connector_log.last()[-1]["outcome"])
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))  # what was lent went back all the same
        self.assertEqual(connector.refused_403(PveError("x", status=403)), connector.REFUSED_403)  # (Proxmox gave none)

    def test_start_after_making_lends_power(self):
        """A guest made or restored with start: Proxmox checks VM.PowerMgmt too (found on the real pve 15/10: the
        whole create_vm was refused) — lent with the request's own kind while Power is not Off; Off → made, not started."""
        from PySide6.QtWidgets import QLabel
        from proxmox_controller.core import connector_tools

        def answer(box, password=""):
            self.assertTrue(wait_until(lambda: self.windows and self.windows[-1].isVisible()))
            dlg = self.windows[-1]
            shown = " ".join(w.text() for w in dlg.findChildren(QLabel))
            if password:
                dlg.password.setText(password)
                dlg.again.setText(password)
            dlg.allow_btn.click()
            self.assertTrue(wait_until(lambda: "answer" in box, 10))
            self.assertFalse(box["answer"]["result"]["isError"], self.text(box))
            self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))  # all lent went back
            return json.loads(self.text(box)), shown

        iso = self.admin.isos("pve")[0]["volid"]
        made, shown = answer(self.request("create_vm", wait=False, host="demo-pve", name="web", iso=iso, start=True,
                                          reason="r"))
        self.assertIn("starts when created", shown)
        self.assertEqual(self.admin.cluster.guests[made["vmid"]]["status"], "running")
        template = self.admin.templates("pve")[0]["volid"]
        ct, _ = answer(self.request("create_container", wait=False, host="demo-pve", hostname="db", template=template,
                                    start=True, reason="r"), password="rootpw1")
        self.assertEqual(self.admin.cluster.guests[ct["vmid"]]["status"], "running")
        backup = self.admin.backups("pve", 101)[1]["volid"]
        back, _ = answer(self.request("restore_backup", wait=False, host="demo-pve", vmid=101, volid=backup,
                                      start=True, reason="r"))
        self.assertEqual(self.admin.cluster.guests[back["vmid"]]["status"], "running")
        claude_policy.set_switch(self.win.settings, "demo-pve", "power", "off")
        made, shown = answer(self.request("create_vm", wait=False, host="demo-pve", name="web2", iso=iso, start=True,
                                          reason="r"))
        self.assertNotIn("starts when created", shown)
        self.assertIn("Power requests are Off", shown)  # the window says so before the user allows it
        self.assertEqual(self.admin.cluster.guests[made["vmid"]]["status"], "stopped")
        self.assertIn("Power requests are Off", made["started"])
        tool = connector_tools.TOOLS["create_vm"]
        self.assertEqual((tool.also_of({}), tool.also_of({"start": True})), ((), ("power",)))  # lent only for a start

    def test_password_typed_by_the_user(self):
        self.admin.cluster.images.append("local:import/ubuntu-24.04-server-cloudimg-amd64.qcow2")
        claude_policy.set_switch(self.win.settings, "demo-pve", "change", "on")  # On — the password is asked anyway
        box = self.request("create_cloud_vm", wait=False, host="demo-pve", name="web",
                           image="local:import/ubuntu-24.04-server-cloudimg-amd64.qcow2", reason="a web server")
        self.assertTrue(wait_until(lambda: self.windows))
        dlg = self.windows[-1]
        self.assertFalse(dlg.hour_btn.isVisibleTo(dlg))  # a password is given each time
        self.assertFalse(dlg.allow_btn.isEnabled())
        dlg.password.setText("s3cret pass")
        dlg.again.setText("s3cret pas")
        self.assertFalse(dlg.allow_btn.isEnabled())
        self.assertIn("not the same", dlg.secret_note.text())
        dlg.again.setText("s3cret pass")
        dlg.allow_btn.click()
        self.assertEqual(dlg.password.text(), "")  # not kept in the window
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        self.assertFalse(box["answer"]["result"]["isError"], self.text(box))
        vmid = json.loads(self.text(box))["vmid"]
        disc = self.admin.cluster.guests[vmid]["cfg"]["ide2"].split(",")[0]
        data = test_core_read_iso(self.admin.cluster.files[disc.split("/")[1]])["user-data"].decode()
        salted = json.loads(data.split("\n", 1)[1])["password"]
        self.assertEqual(salted, cloudseed.sha512_crypt("s3cret pass", salted.split("$")[2]))  # it reached the VM
        self.assertNotIn("s3cret", json.dumps(box["answer"]))  # Claude is told only that it was set
        self.assertNotIn("s3cret", connector_log.path().read_text())  # nor is it in the log
        self.assertEqual(self.admin.cluster.guests[vmid]["status"], "running")  # its start lent Power for a moment
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))
        claude_policy.set_switch(self.win.settings, "demo-pve", "power", "off")
        box = self.request("create_cloud_vm", wait=False, host="demo-pve", name="web2",
                           image="local:import/ubuntu-24.04-server-cloudimg-amd64.qcow2", reason="r")
        self.assertTrue(wait_until(lambda: len(self.windows) == 2))
        self.windows[-1].password.setText("p")
        self.windows[-1].again.setText("p")
        self.windows[-1].allow_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        self.assertIn("Power requests are Off", json.loads(self.text(box))["started"])  # made, not started
        self.windows.pop()
        claude_policy.set_switch(self.win.settings, "demo-pve", "console", "ask")
        box = self.request("console_type_password", wait=False, host="demo-pve", vmid=201, reason="log in")
        self.assertTrue(wait_until(lambda: len(self.windows) == 2))
        dlg = self.windows[-1]
        self.assertFalse(dlg.again.isVisibleTo(dlg))  # typing an existing password: asked once
        self.assertTrue(any(isinstance(w, connector.QLabel) and w.pixmap() and not w.pixmap().isNull()
                            for w in dlg.findChildren(connector.QLabel)))  # the screen, to see where it goes
        dlg.password.setText("pw")
        dlg.allow_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        server = self.admin.cluster.consoles[-1]
        self.assertTrue(wait_until(lambda: [k[2] for k in server.keys if k[1]][-3:] == [ord("p"), ord("w"), 0xFF0D]))
        box = self.request("console_type_password", wait=False, host="demo-pve", vmid=201, reason="again")
        self.assertTrue(wait_until(lambda: len(self.windows) == 3))
        self.windows[-1].deny_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box))
        self.assertIn("denied", self.text(box))

    def test_click_shows_where_and_a_password_goes_into_both_fields(self):
        claude_policy.set_switch(self.win.settings, "demo-pve", "console", "ask")
        box = self.request("console_click", wait=False, host="demo-pve", vmid=201, x=40, y=30, reason="Next button")
        self.assertTrue(wait_until(lambda: len(self.windows) == 1))
        dlg = self.windows[-1]
        self.assertTrue(any(isinstance(w, connector.QLabel) and w.pixmap() and not w.pixmap().isNull()
                            for w in dlg.findChildren(connector.QLabel)))  # the screen with the red mark
        dlg.allow_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        server = self.admin.cluster.consoles[-1]
        self.assertTrue(wait_until(lambda: (1, 40, 30) in server.pointer))
        box = self.request("console_type_password", wait=False, host="demo-pve", vmid=201, confirm=True,
                           enter=False, reason="the installer's password and its confirmation")
        self.assertTrue(wait_until(lambda: len(self.windows) == 2))
        dlg = self.windows[-1]
        self.assertTrue(dlg.again.isVisibleTo(dlg))  # a new password: asked twice, so a typo shows
        dlg.password.setText("pw")
        dlg.again.setText("pX")
        self.assertFalse(dlg.allow_btn.isEnabled())
        dlg.again.setText("pw")
        dlg.allow_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box, 10))
        server = self.admin.cluster.consoles[-1]
        self.assertTrue(wait_until(lambda: [k[2] for k in server.keys if k[1]] ==
                                   [ord("p"), ord("w"), 0xFF09, ord("p"), ord("w")]))
        claude_policy.set_switch(self.win.settings, "demo-pve", "console", "on")
        before = len(self.admin.cluster.consoles)
        self.request("console_click", host="demo-pve", vmid=201, x=1, y=1, reason="r")
        self.assertEqual(len(self.admin.cluster.consoles), before + 1)  # On: no window, so no picture first
        self.assertEqual(len(self.windows), 2)

    def test_role_put_back_once_the_host_answers(self):
        """The app starts before the server (14/10: by a minute): the role is put back when the host answers."""
        self.win.demo = False  # (as with a real host)
        claude_access.apply(self.admin, list(claude_policy.PRIVILEGES["read"]) + ["VM.PowerMgmt"])  # left lent

        class Starting:  # the host, still booting
            def __getattr__(self, name):
                raise PveError("Could not reach the host")

        real = self.win.make_client
        self.win.make_client = lambda h: Starting()
        self.win._claude_tidy()
        self.assertTrue(wait_until(lambda: not self.win.tidying))
        self.assertNotIn("demo-pve", self.win.tidied)
        self.assertIn("VM.PowerMgmt", self.role())  # not yet: the host did not answer
        self.win.make_client = real
        self.win._set_state("demo-pve", "online")
        self.assertTrue(wait_until(lambda: "demo-pve" in self.win.tidied))
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))
        claude_access.apply(self.admin, list(claude_policy.PRIVILEGES["read"]) + ["VM.PowerMgmt"])
        self.win._set_state("demo-pve", "online")
        QTest.qWait(200)
        self.assertIn("VM.PowerMgmt", self.role())  # once a run of the app, not at every ping

    def test_console_picture(self):
        claude_policy.set_switch(self.win.settings, "demo-pve", "console", "on")
        box = self.request("console_screenshot", host="demo-pve", vmid=201, reason="see the installer")
        content = box["answer"]["result"]["content"]
        self.assertEqual((content[0]["type"], content[0]["mimeType"]), ("image", "image/png"))
        self.assertEqual(self.role(), list(claude_policy.PRIVILEGES["read"]))  # VM.Console only while it ran

    def test_approval_window_stands_out(self):
        """Hazard stripes along the top (the title on a plate in the middle) and all round, and the sound chosen in
        Claude Access, once, as the window opens (the user's wish, 23/10: it was lost among many windows)."""
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start", reason="r")
        self.assertTrue(wait_until(lambda: self.windows))
        dlg = self.windows[-1]
        self.assertEqual(self.played, [])  # the sound is off until the user turns it on
        self.assertEqual(dlg.band.text, "Claude asks")
        self.assertIs(dlg.layout().itemAt(0).widget(), dlg.band)  # first, above "… asks to:"
        dlg.adjustSize()
        img = dlg.grab().toImage()
        stripe = {hazard.YELLOW.name(), hazard.BLACK.name()}
        for x, y in ((3, 3), (img.width() - 4, img.height() // 2), (img.width() // 2, img.height() - 4),
                     (3, img.height() - 4)):
            self.assertIn(img.pixelColor(x, y).name(), stripe, (x, y))  # the frame, all round
        band = dlg.band.geometry()
        self.assertGreaterEqual(band.top(), hazard.FRAME)  # inside the frame, not over it
        self.assertIn(img.pixelColor(band.left() + 4, band.center().y()).name(), stripe)  # the band's left end
        plate = img.pixelColor(band.center().x(), band.top() + 6)  # (above the title's letters)
        self.assertEqual(plate.name(), QColor(theme.colors().window).name())  # the plate in the middle
        dlg.deny_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box))

        self.win.settings["claude"].update(sound_on=True, sound="bell")
        box = self.request("guest_power", wait=False, host="demo-pve", vmid=102, action="start", reason="r")
        self.assertTrue(wait_until(lambda: len(self.windows) == 2))
        self.assertEqual(self.played, ["bell"])  # once, as it opened
        self.windows[-1].deny_btn.click()
        self.assertTrue(wait_until(lambda: "answer" in box))
        self.assertEqual(self.played, ["bell"])

    def test_claude_window_sound(self):
        dlg = claude_window.ClaudeWindow(self.win, self.conn, self.win.runner)
        self.addCleanup(dlg.close)
        self.assertFalse(dlg.sound_on.isChecked())
        self.assertEqual([dlg.sound.itemText(i) for i in range(dlg.sound.count())], ["Double beep", "Beep", "Bell"])
        self.assertEqual(dlg.sound.currentData(), "double-beep")
        dlg.sound_on.setChecked(True)
        dlg.sound.setCurrentIndex(dlg.sound.findData("beep"))
        self.assertEqual((self.win.settings["claude"]["sound_on"], self.win.settings["claude"]["sound"]),
                         (True, "beep"))
        self.assertEqual(sounds.chosen(self.win.settings), "beep")
        dlg.sound_test.click()
        self.assertEqual(self.played, ["beep"])
        again = claude_window.ClaudeWindow(self.win, self.conn, self.win.runner)  # as saved
        self.addCleanup(again.close)
        self.assertEqual((again.sound_on.isChecked(), again.sound.currentData()), (True, "beep"))
        with mock.patch.object(sounds, "play", lambda name: False):  # nothing here can play it
            dlg.sound_test.click()
        self.assertIn("pw-play", self.errors[-1][1])
        dlg.sound_on.setChecked(False)
        self.assertIsNone(sounds.chosen(self.win.settings))

    def test_claude_window(self):
        dlg = claude_window.ClaudeWindow(self.win, self.conn, self.win.runner)
        self.addCleanup(dlg.close)
        self.assertTrue(dlg.enabled.isChecked())
        self.assertIn("set up", dlg.access.text())
        self.assertFalse(dlg.code_btn.isEnabled())  # demo mode: nothing is written to the Claude apps
        self.assertTrue(dlg.rows[0].buttons["on"].isChecked())  # Read
        dlg.set_switch("read", "ask")
        self.assertEqual(claude_policy.host_switches(self.win.settings, "demo-pve")["read"], "ask")
        self.assertTrue(wait_until(lambda: not [e for e in self.admin.cluster.acl if e["roleid"] == claude_access.ROLE]))
        dlg.set_switch("read", "on")
        self.assertTrue(wait_until(lambda: [e for e in self.admin.cluster.acl if e["roleid"] == claude_access.ROLE]))
        self.request("list_guests", host="demo-pve")
        self.assertTrue(wait_until(lambda: dlg.log.rowCount() >= 1))
        self.assertEqual(dlg.log.item(0, 4).text(), "Allowed (On)")
        dlg.host.setCurrentIndex(dlg.host.findData("demo-pc"))
        self.assertIn("not set up", dlg.access.text())
        dlg.set_up()
        self.assertTrue(wait_until(lambda: self.conn.tokens.get("demo-pc")))
        pc = DemoPve(DEMO_HOSTS[1]).cluster
        self.assertIn(claude_access.USER, pc.users)
        dlg.remove()
        self.assertTrue(wait_until(lambda: not self.conn.tokens.get("demo-pc")))
        self.assertNotIn(claude_access.USER, pc.users)
        dlg.enabled.setChecked(False)
        self.assertFalse(claude_policy.enabled(self.win.settings))


class ConnectorEndToEndTest(UiCase):
    def test_bridge_to_app(self):
        """The real bridge process, the real socket, the app (not demo mode, its own folders), the pretend cluster."""
        import subprocess
        config = os.path.join(self.private, "config")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config, "APPDATA": config}):
            win = MainWindow(list(DEMO_HOSTS), DemoPve)
            self.addCleanup(win.close)
            self.assertTrue(win.connector.listening)
            win.settings["claude"] = {"enabled": True}
            admin = DemoPve(DEMO_HOSTS[0])
            secret, _ = claude_access.setup(admin, claude_policy.host_switches(win.settings, "demo-pve"))
            win.connector.tokens.set("demo-pve", secret)
            self.assertEqual(store.claude_token("demo-pve"), secret)  # kept with the user's own tokens
            messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude-code"}}},
                        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "list_guests", "arguments": {"host": "demo-pve"}}},
                        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "host_power", "arguments": {"host": "demo-pve", "action": "shutdown",
                                                                        "reason": "test"}}}]
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            box = {}

            from proxmox_controller.core import claude_connect

            def bridge():  # as Claude starts it (Windows: its Python with bin/launch.py)
                done = subprocess.run([*claude_connect.bridge_command(), "--mcp"], text=True,
                                      input="".join(json.dumps(m) + "\n" for m in messages), capture_output=True,
                                      timeout=30, env=dict(os.environ))
                box["out"] = done.stdout

            threading.Thread(target=bridge, daemon=True).start()
            self.assertTrue(wait_until(lambda: "out" in box, 30))
            answers = {m["id"]: m for m in map(json.loads, box["out"].splitlines())}
            guests = json.loads(answers[2]["result"]["content"][0]["text"])
            self.assertEqual(len(guests), 5)
            self.assertTrue(answers[3]["result"]["isError"])  # Host is Off
            self.assertIn("Off", answers[3]["result"]["content"][0]["text"])
            self.assertEqual([e["client"] for e in connector_log.last()], ["claude-code", "claude-code"])
        address = win.connector.server.address
        win.close()
        if connector_link.WINDOWS:
            with self.assertRaises(connector_link.AppNotRunning):  # the pipe goes with the app
                connector_link.request({}, path=address)
        else:
            self.assertFalse(win.connector.server.path.exists())  # the socket goes with the app


class ClaudeConnectTest(unittest.TestCase):
    def test_connect_both_apps(self):
        from proxmox_controller.core import claude_connect
        home = tempfile.mkdtemp(dir=SHORT_TMP)
        self.addCleanup(__import__("shutil").rmtree, home, True)
        calls = os.path.join(home, "calls.txt")
        if os.name == "nt":  # a .cmd, as npm installs it, handing its arguments to a Python that notes them
            notes = os.path.join(home, "note.py")
            with open(notes, "w") as fh:
                fh.write(f"import sys\nopen({calls!r}, 'a').write(''.join(a + '\\n' for a in sys.argv[1:]))\n")
            fake = os.path.join(home, "claude.cmd")
            with open(fake, "w") as fh:
                fh.write(f'@"{sys.executable}" -I "{notes}" %*\r\n')
        else:
            fake = os.path.join(home, "claude")  # stands in for Claude Code's program: notes what it was asked
            with open(fake, "w") as fh:
                fh.write(f"#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done >> {calls}\n")  # an argument a line
            os.chmod(fake, 0o755)
        config = os.path.join(home, ".config")
        os.makedirs(os.path.join(config, "Claude"))
        with open(os.path.join(config, "Claude", "claude_desktop_config.json"), "w") as fh:
            json.dump({"preferences": {"keep": True}}, fh)
        with mock.patch.dict(os.environ, {"HOME": home, "XDG_CONFIG_HOME": config, "APPDATA": config,
                                          "CLAUDE_CONFIG_DIR": home}), \
                mock.patch.object(claude_connect, "claude_cli", lambda: fake):
            self.assertFalse(claude_connect.code_connected() or claude_connect.desktop_connected())
            claude_connect.connect_code()
            with open(calls) as fh:
                self.assertEqual(fh.read().splitlines(), ["mcp", "add", "--scope", "user", "proxmox-controller",
                                                          "--", *claude_connect.bridge_command(), "--mcp"])
            claude_connect.connect_desktop()
            data = json.loads(claude_connect.desktop_config().read_text())
            command = claude_connect.bridge_command()
            self.assertEqual(data["mcpServers"]["proxmox-controller"],
                             {"command": command[0], "args": [*command[1:], "--mcp"]})
            self.assertEqual(data["preferences"], {"keep": True})  # the rest of the file is left as it was
            self.assertTrue(claude_connect.desktop_connected())
            claude_connect.disconnect_desktop()
            self.assertFalse(claude_connect.desktop_connected())
            self.assertEqual(json.loads(claude_connect.desktop_config().read_text())["preferences"], {"keep": True})
            desktop = claude_connect.desktop_config()
            # with a BOM, as Windows' Notepad and PowerShell 5 save it: read, and kept as it was beside our entry
            desktop.write_bytes(b"\xef\xbb\xbf" + json.dumps({"preferences": {"keep": True}}).encode())
            claude_connect.connect_desktop()
            self.assertTrue(claude_connect.desktop_connected())
            self.assertEqual(json.loads(desktop.read_text(encoding="utf-8-sig"))["preferences"], {"keep": True})
            # a file that cannot be read is never written over: the user's other servers would be lost
            desktop.write_text('{"mcpServers": {"other": {}}, oops', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                claude_connect.connect_desktop()
            self.assertEqual(desktop.read_text(encoding="utf-8"), '{"mcpServers": {"other": {}}, oops')


class HostDialogTest(UiCase):
    def test_checks_before_saving(self):
        dlg = HostDialog(None, self.runner, DemoPve)
        self.assertGreaterEqual(dlg.height(), dlg.layout().heightForWidth(dlg.width()))  # no squeezed fields
        self.assertEqual(dlg.build(), "Write the host's address.")
        dlg.address.setText("192.0.2.80")
        dlg.secret.setText("secret")
        self.assertIn("Get Certificate", dlg.build())
        dlg.fp_value = "DEMO"
        self.assertIn("tick the box", dlg.build())
        dlg.fp_ok.setChecked(True)
        dlg.mac.setText("3c:ec:ef")
        self.assertIn("MAC", dlg.build())
        dlg.mac.setText("3C-EC-EF-6E-A7-96")
        h = dlg.build()
        self.assertEqual((h.name, h.mac, h.port), ("192.0.2.80", "3c:ec:ef:6e:a7:96", 8006))

    def test_whole_fingerprint_is_visible(self):
        # the real pve-ssl.pem fingerprint of the user's host (public): on one line its last 5 bytes were cut off
        fp = "2B:1E:01:0A:8C:97:D5:65:89:37:E5:74:07:02:F8:DF:9E:B4:68:07:2B:7B:34:DD:04:43:3D:C7:36:2D:39:D4"
        host = Host(id="h", name="Home", address="192.168.1.80", token_id="root@pam!controller", token_secret="s",
                    fingerprint=fp)
        dlg = HostDialog(None, self.runner, DemoPve, host)
        dlg.show()
        QTest.qWait(50)
        lbl = dlg.fingerprint
        self.assertIn("2B:7B:34:DD:04:43:3D:C7:36:2D:39:D4", lbl.text().replace("<br>", ""))
        self.assertLessEqual(lbl.fontMetrics().horizontalAdvance(fp[:47]) * 1.1, lbl.width())  # 16 bytes fit
        self.assertGreaterEqual(lbl.height(), lbl.heightForWidth(lbl.width()))  # both lines get their room
        dlg.close()

    def test_changing_the_address_forgets_the_certificate(self):
        host = Host(id="h", name="Home", address="192.0.2.80", token_id="root@pam!controller", token_secret="s",
                    fingerprint="AB:CD")
        dlg = HostDialog(None, self.runner, DemoPve, host)
        self.assertTrue(dlg.fp_ok.isChecked())
        dlg.address.setText("192.0.2.81")
        self.assertFalse(dlg.fp_ok.isChecked())
        self.assertEqual(dlg.fp_value, "")

    def filled(self, make_client):
        dlg = HostDialog(None, self.runner, make_client)
        dlg.address.setText("192.0.2.80")
        dlg.secret.setText("secret")
        dlg.fp_value = "DEMO"
        dlg.fp_ok.setChecked(True)
        return dlg

    def test_save_tests_the_connection_first(self):
        def refused(_host):
            pve = DemoPve(DEMO_HOSTS[0])
            pve.request = mock.Mock(side_effect=PveError("Proxmox refused the API token"))
            return pve

        dlg = self.filled(refused)
        dlg.test(save_after=True)
        self.assertTrue(wait_until(lambda: dlg.isEnabled() and dlg.status.text().startswith("✗")))
        self.assertIsNone(dlg.result_host)  # a host that does not answer is not saved
        self.assertIn("refused", dlg.status.text())

        dlg = self.filled(lambda _host: DemoPve(DEMO_HOSTS[0]))
        dlg.test(save_after=True)
        self.assertTrue(wait_until(lambda: dlg.result() == dlg.DialogCode.Accepted))
        self.assertTrue(dlg.status.text().startswith("✓ Connected"))
        self.assertEqual(dlg.result_host.address, "192.0.2.80")


class MainWindowTest(UiCase):
    def menu_texts(self, win):
        win._fill_menu()
        return [a.text() for a in win.menu.actions() if not a.isSeparator()]

    def test_demo_window(self):
        with mock.patch.object(store, "save_settings") as save_settings, \
                mock.patch.object(store, "save_hosts") as save_hosts:
            win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)
            try:
                view = win.current_view()
                self.assertEqual(view.host.id, "demo-pve")
                self.assertTrue(wait_until(lambda: view.online))
                self.assertEqual(win.windowTitle(), "Home server (demo) — Proxmox Controller (demo)")
                # two hosts: the ☰ menu lists them, with their keys
                self.assertEqual(self.menu_texts(win), ["Home server (demo)\tCtrl+1", "Old desktop PC (demo)\tCtrl+2",
                                                        "Hosts and Settings…", "Claude Access…", "Help", "Quit"])
                win.menu.actions()[1].trigger()
                second = win.current_view()
                self.assertEqual(second.host.id, "demo-pc")
                self.assertTrue(wait_until(lambda: second.online))
                self.assertIn("Ryzen", second.cpu_card.caption.text())
                self.assertTrue(wait_until(lambda: win.state.get("demo-pc") == "online"))
                win.show_host_index(0)
                self.assertIs(win.current_view(), view)
                win.show_help()
                self.assertTrue(win.help_dialog.isVisible())
                self.assertIs(win.current_view(), view)  # Help no longer takes the host's place
                win.remove_host(DEMO_HOSTS[1])
                self.assertEqual(self.menu_texts(win), ["Hosts and Settings…", "Claude Access…", "Help", "Quit"])  # one host: no list
            finally:
                win.close()
            save_settings.assert_not_called()  # demo mode never writes the real settings
            save_hosts.assert_not_called()

    def test_graphs_open_from_the_page_and_close_with_the_app(self):
        with mock.patch.object(store, "save_settings"):
            win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)
            view = win.current_view()
            self.assertTrue(wait_until(lambda: view.online))
            self.select(view, 201)
            view.guest_action("graphs")
            self.assertIn("demo-pve/201", guest_dialogs.GRAPHS)
            win.close()
            self.assertEqual(guest_dialogs.GRAPHS, {})

    def test_settings_hold_the_hosts(self):
        from proxmox_controller.ui.settings import SettingsDialog
        with mock.patch.object(store, "save_settings"):
            win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)
            try:
                dlg = SettingsDialog(win)
                self.assertEqual(dlg.list.count(), 2)
                self.assertEqual(dlg.selected().id, "demo-pve")  # the shown host is preselected
                self.assertTrue(dlg.remove_btn.isEnabled())
                self.answer = False
                dlg.remove()
                self.assertEqual(dlg.list.count(), 2)
                self.answer = True
                dlg.remove()
                self.assertEqual(dlg.list.count(), 1)
                self.assertEqual([h.id for h in win.hosts], ["demo-pc"])
                self.assertEqual(win.current_view().host.id, "demo-pc")  # the window moves to the one left
                dlg.refresh.setCurrentIndex(dlg.refresh.findData(30))
                self.assertEqual((win.settings["refresh_seconds"], win.timer.interval()), (30, 30_000))
                dlg.list.setCurrentRow(0)
                dlg.remove()
                self.assertEqual(dlg.list.count(), 0)
                self.assertFalse(dlg.edit_btn.isEnabled())
                self.assertIs(win.pages.currentWidget(), win.empty)
                self.assertEqual(win.windowTitle(), "Proxmox Controller (demo)")
            finally:
                win.close()

    def test_start_with_the_computer(self):
        from proxmox_controller.core import autostart
        from proxmox_controller.ui.settings import SettingsDialog
        from tests.test_core import FakeRegistry
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d, "APPDATA": d}), \
                mock.patch.object(store, "save_settings"), mock.patch.object(autostart, "registry", FakeRegistry()):
            win = MainWindow(list(DEMO_HOSTS), DemoPve, demo=True)  # (Windows: a pretend registry, not the real one)
            try:
                dlg = SettingsDialog(win)
                self.assertTrue(dlg.login.isVisibleTo(dlg))
                self.assertFalse(dlg.login.isChecked())
                dlg.login.setChecked(True)
                self.assertTrue(autostart.is_enabled())
                if not autostart.WINDOWS:
                    self.assertTrue(autostart.entry_path().exists())
                self.assertTrue(SettingsDialog(win).login.isChecked())  # read back from the entry itself
                dlg.login.setChecked(False)
                self.assertFalse(autostart.is_enabled())
            finally:
                win.close()

    def test_empty_window(self):
        with mock.patch.object(store, "save_settings"):
            win = MainWindow([], DemoPve, demo=True)
            try:
                self.assertIs(win.pages.currentWidget(), win.empty)
                self.assertEqual(self.menu_texts(win), ["Hosts and Settings…", "Claude Access…", "Help", "Quit"])
                # the card's words whole at any width (Windows 11, 1024 px: its height was reckoned for the page's
                # width, the centred card then narrower — the second line cut off, the third gone)
                words = [w for w in win.empty.findChildren(QLabel) if w.wordWrap()]
                self.assertEqual(len(words), 1)
                win.show()
                for width in (1024, 1600, 760):
                    win.resize(width, 700)
                    QApplication.processEvents()
                    w = words[0]
                    self.assertGreaterEqual(w.height(), w.heightForWidth(w.width()), width)
            finally:
                win.close()


@unittest.skipIf(QApplication is None, "needs PySide6")
class ChartTest(unittest.TestCase):
    def test_ticks_cover_the_data(self):
        for lo, hi in ((0, 7.3), (0.4, 0.95), (12, 15000), (0, 0)):
            t = nice_ticks(lo, hi)
            self.assertLessEqual(t[0], lo)
            self.assertGreaterEqual(t[-1], hi)
            self.assertGreaterEqual(len(t), 2)


if __name__ == "__main__":
    unittest.main()
