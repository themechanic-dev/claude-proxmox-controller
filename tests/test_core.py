"""The Qt-free core: Wake-on-LAN, address and fingerprint handling, the API client against a local HTTPS
server that answers like Proxmox, settings storage and MAC discovery. No real Proxmox is touched."""

import base64
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import struct
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

from proxmox_controller.core import apt, ssh as sshmod
from proxmox_controller.core import (autostart, claude_access, claude_policy, connector_link, connector_tools, jobs,
                                     mcp, netinfo, screen, sounds, spice, startup, store, tasks, vault, vmhw, wol)
from proxmox_controller.core import cloudseed, guestfiles, isofs, setupdisc, winsetup
from proxmox_controller.core.des import encrypt_block, vnc_response
from proxmox_controller.core.fakevnc import FakeVncServer
from proxmox_controller.core.rfb import RfbClient, RfbError, qnum_from_evdev, qnum_from_windows
from proxmox_controller.core.websocket import WebSocket
from proxmox_controller.core.demo import DEMO_HOSTS, DemoPve
from proxmox_controller.core.pve import (CertificateMismatch, Host, Pve, PveError, agent_enabled, fetch_fingerprint,
                                         format_fingerprint, guest_macs, normalize_fingerprint, split_address,
                                         storage_order, upload_name)

try:
    from tests.fake_server import FakePveServer, openssl_available
except ImportError:  # pragma: no cover
    openssl_available = lambda: False  # noqa: E731


class WolTest(unittest.TestCase):
    def test_mac_formats(self):
        for text in ("3c:ec:ef:6e:a7:96", "3C-EC-EF-6E-A7-96", "3cecef6ea796", " 3c:ec:ef:6e:a7:96 "):
            self.assertEqual(wol.normalize_mac(text), "3c:ec:ef:6e:a7:96")
        for bad in ("3c:ec:ef:6e:a7", "zz:ec:ef:6e:a7:96", "3c:ec-ef:6e:a7:96", ""):
            with self.assertRaises(ValueError):
                wol.normalize_mac(bad)

    def test_magic_packet(self):
        p = wol.magic_packet("3c:ec:ef:6e:a7:96")
        self.assertEqual(len(p), 102)
        self.assertEqual(p[:6], b"\xff" * 6)
        self.assertEqual(p[6:12], bytes.fromhex("3cecef6ea796"))
        self.assertEqual(p[6:], bytes.fromhex("3cecef6ea796") * 16)

    def test_send_reaches_a_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx:
            rx.bind(("127.0.0.1", 0))
            rx.settimeout(2)
            port = rx.getsockname()[1]
            self.assertEqual(wol.send("3c:ec:ef:6e:a7:96", broadcast="127.0.0.1", ports=(port,), repeat=2), 2)
            self.assertEqual(rx.recv(200), wol.magic_packet("3c:ec:ef:6e:a7:96"))


class AddressTest(unittest.TestCase):
    def test_split_address(self):
        self.assertEqual(split_address("192.168.1.80"), ("192.168.1.80", 8006))
        self.assertEqual(split_address("https://pve.lan:8443/"), ("pve.lan", 8443))
        self.assertEqual(split_address("[fd00::5]:8006"), ("fd00::5", 8006))
        self.assertEqual(split_address("fd00::5"), ("fd00::5", 8006))

    def test_fingerprint_forms(self):
        fp = format_fingerprint(b"hello")
        self.assertEqual(len(fp.split(":")), 32)
        self.assertEqual(normalize_fingerprint(fp.lower().replace(":", " ")), fp)


@unittest.skipUnless(openssl_available(), "needs the openssl command")
class ApiTest(unittest.TestCase):
    def setUp(self):
        self.srv = FakePveServer()
        self.fp = format_fingerprint(self.srv.cert_der)
        self.host = Host(id="h1", name="Test PVE", address=self.srv.address, token_id="root@pam!controller",
                         token_secret="secret", fingerprint=self.fp)
        self.pve = Pve(self.host, timeout=5)

    def tearDown(self):
        self.srv.close()

    def test_fetch_fingerprint_matches_certificate(self):
        self.assertEqual(fetch_fingerprint(self.srv.address), self.fp)

    def test_wrong_certificate_sends_nothing(self):
        self.host.fingerprint = "00:" * 31 + "00"
        with self.assertRaises(CertificateMismatch):
            self.pve.version()
        self.assertEqual(self.srv.requests, [])  # the token never left this computer

    def test_unconfirmed_certificate_refused(self):
        self.host.fingerprint = ""
        with self.assertRaises(PveError):
            self.pve.version()

    def test_version_nodes_guests(self):
        self.assertEqual(self.pve.version()["release"], "8.4")
        self.assertEqual(self.pve.nodes()[0]["node"], "pve")
        guests = {g["vmid"]: g for g in self.pve.guests()}
        self.assertEqual(guests[100]["name"], "pihole")
        self.assertEqual(guests[200]["type"], "qemu")
        self.assertEqual(self.srv.requests[0][2], "PVEAPIToken=root@pam!controller=secret")

    def test_guest_action_and_task(self):
        upid = self.pve.guest_action("pve", "lxc", 102, "start")
        self.assertTrue(upid.startswith("UPID:pve:"))
        self.assertEqual(self.pve.wait_task("pve", upid, timeout=5)["exitstatus"], "OK")
        self.assertTrue(self.srv.requests[-1][1].startswith("/nodes/pve/tasks/UPID:"))  # encoded, decoded intact
        status = {g["vmid"]: g["status"] for g in self.pve.guests()}
        self.assertEqual(status[102], "running")
        with self.assertRaises(ValueError):
            self.pve.guest_action("pve", "lxc", 102, "explode")

    def test_config_resize_and_ips(self):
        self.pve.update_config("pve", "lxc", 102, {"cores": 2, "memory": 2048, "onboot": True})
        cfg = self.pve.guest_config("pve", "lxc", 102)
        self.assertEqual((cfg["cores"], cfg["memory"], cfg["onboot"]), (2, 2048, 1))
        self.pve.resize_disk("pve", "lxc", 102, "rootfs", 4)
        self.assertIn("size=12G", self.pve.guest_config("pve", "lxc", 102)["rootfs"])
        with self.assertRaises(ValueError):
            self.pve.resize_disk("pve", "lxc", 102, "rootfs", 0)
        self.assertEqual(self.pve.interfaces("pve", "lxc", 100), ["192.0.2.10"])
        self.assertEqual(self.pve.interfaces("pve", "qemu", 201), ["192.0.2.21"])
        self.assertEqual(self.pve.interfaces("pve", "lxc", 102), [])  # stopped: unknown, not an error

    def test_create_container_flow(self):
        node = "pve"
        self.assertIn("vmbr0", self.pve.bridges(node))
        vmid = self.pve.next_id()
        self.assertEqual(vmid, 103)
        app = next(a for a in self.pve.appliances(node) if a["os"] == "alpine")
        self.pve.wait_task(node, self.pve.download_template(node, "local", app["template"]), timeout=5)
        volids = [t["volid"] for t in self.pve.templates(node)]
        self.assertIn(f"local:vztmpl/{app['template']}", volids)
        upid = self.pve.create_container(node, {"vmid": vmid, "hostname": "new-box", "ostemplate": volids[0],
                                                "cores": 2, "memory": 1024, "swap": 512, "rootfs": "local-lvm:8",
                                                "net0": "name=eth0,bridge=vmbr0,ip=dhcp", "unprivileged": True,
                                                "start": True})
        self.pve.wait_task(node, upid, timeout=5)
        new = {g["vmid"]: g for g in self.pve.guests()}[vmid]
        self.assertEqual((new["name"], new["status"], new["maxcpu"]), ("new-box", "running", 2))

    def test_snapshots(self):
        self.assertEqual([s["name"] for s in self.pve.snapshots("pve", "lxc", 101)], ["before-upgrade"])
        self.pve.create_snapshot("pve", "lxc", 101, "today", "before a change")
        self.assertEqual(len(self.pve.snapshots("pve", "lxc", 101)), 2)
        self.pve.rollback_snapshot("pve", "lxc", 101, "today")
        self.pve.delete_snapshot("pve", "lxc", 101, "today")
        self.assertEqual(len(self.pve.snapshots("pve", "lxc", 101)), 1)

    def test_isos_download_and_upload(self):
        self.assertEqual([i["volid"] for i in self.pve.isos("pve")], ["local:iso/ubuntu-24.04.1-live-server-amd64.iso"])
        self.pve.wait_task("pve", self.pve.download_url("pve", "local", "https://example.org/d12.iso", "debian-12.iso"),
                           timeout=5)
        with self.assertRaises(PveError) as ctx:  # Proxmox never overwrites a file
            self.pve.download_url("pve", "local", "https://example.org/d12.iso", "debian-12.iso")
        self.assertIn("refusing", str(ctx.exception))
        size = 3 * 65536 + 123
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "Win 11 (24H2).iso")
            with open(path, "wb") as fh:
                fh.write(os.urandom(size))
            seen = []
            upid = self.pve.upload("pve", "local", path, progress=lambda sent, total: seen.append((sent, total)),
                                   chunk=65536)
        self.pve.wait_task("pve", upid, timeout=5)
        self.assertEqual(self.srv.cluster.uploaded, {"Win_11__24H2_.iso": size})  # every byte arrived
        self.assertEqual(seen, [(65536, size), (131072, size), (196608, size), (size, size)])
        self.assertIn("local:iso/Win_11__24H2_.iso", [i["volid"] for i in self.pve.isos("pve")])
        with self.assertRaises(ValueError):
            upload_name("/home/me/notes.txt")

    def test_upload_cancelled_or_wrong_certificate(self):
        with tempfile.NamedTemporaryFile(suffix=".iso") as fh:
            fh.write(b"x" * 300_000)
            fh.flush()
            with self.assertRaises(PveError) as ctx:
                self.pve.upload("pve", "local", fh.name, cancelled=lambda: True)
            self.assertIn("cancelled", str(ctx.exception))
            self.assertEqual(self.srv.cluster.uploaded, {})
            sent_before = len(self.srv.requests)
            self.host.fingerprint = "00:" * 31 + "00"
            with self.assertRaises(CertificateMismatch):
                self.pve.upload("pve", "local", fh.name)
            self.assertEqual(len(self.srv.requests), sent_before)  # not a byte, not the token

    def test_create_and_clone_vm(self):
        iso = "local:iso/ubuntu-24.04.1-live-server-amd64.iso"
        params = {"vmid": 103, "name": "web", "ostype": "l26", "cores": 2, "memory": 2048,
                  "scsihw": "virtio-scsi-single", "scsi0": "local-lvm:32,iothread=1,discard=on",
                  "ide2": f"{iso},media=cdrom", "net0": "virtio,bridge=vmbr0,firewall=1",
                  "boot": "order=scsi0;ide2;net0", "agent": "1", "start": True}
        self.pve.wait_task("pve", self.pve.create_vm("pve", params), timeout=5)
        cfg = self.pve.guest_config("pve", "qemu", 103)
        self.assertIn("size=32G", cfg["scsi0"])
        self.assertTrue(agent_enabled(cfg))
        self.assertEqual({g["vmid"]: g["status"] for g in self.pve.guests()}[103], "running")
        with self.assertRaises(PveError):  # an ISO that is not there
            self.pve.create_vm("pve", {**params, "vmid": 104, "ide2": "local:iso/nope.iso,media=cdrom"})
        self.srv.cluster.guests[103]["template"] = 1
        self.pve.wait_task("pve", self.pve.clone_vm("pve", 103, 104, "web-2", full=True, storage="local-lvm"),
                           timeout=5)
        new = {g["vmid"]: g for g in self.pve.guests()}[104]
        self.assertEqual((new["name"], new["status"], new["template"]), ("web-2", "stopped", 0))

    def test_vnc_console_through_the_api(self):
        ws, password = self.pve.open_vnc("pve", "qemu", 201)  # vncproxy, then the WebSocket upgrade
        self.assertEqual(len(password), 8)  # generate-password: not the ticket
        client = RfbClient(ws, password)
        self.assertEqual(client.handshake()[:2], (80, 60))
        self.assertEqual(client.next_update()[0][:5], ("raw", 0, 0, 80, 60))
        self.assertTrue(client.ext_keys)  # QEMU takes physical key codes
        client.key(True, 0x61, 0x1E)
        client.key(False, 0x61, 0x1E)
        client.next_update()
        self.assertEqual(self.srv.consoles[0].keys[0], ("qnum", True, 0x61, 0x1E))
        ws.close()
        upgrade = [r for r in self.srv.requests if r[1].endswith("/vncwebsocket")][0]
        self.assertEqual(upgrade[2], "PVEAPIToken=root@pam!controller=secret")  # the token, not a browser login

    def test_container_console_and_refusals(self):
        ws, password = self.pve.open_vnc("pve", "lxc", 100)
        self.assertTrue(password.startswith("PVEVNC:"))  # containers: the ticket is the password
        client = RfbClient(ws, password)
        client.handshake()
        client.next_update()
        self.assertFalse(client.ext_keys)  # vncterm: key symbols
        ws.close()
        with self.assertRaises(PveError):
            self.pve.open_vnc("pve", "lxc", 102)  # stopped
        self.srv.cluster.token = "root@pam!controller=other"  # the token stops working between the two steps
        with self.assertRaises(PveError):
            self.pve.open_vnc("pve", "qemu", 201)

    def test_spice(self):
        self.assertTrue(self.pve.has_spice("pve", 201))
        self.assertFalse(self.pve.has_spice("pve", 200))  # stopped
        cfg = self.pve.spice_config("pve", 201)
        self.assertEqual((cfg["type"], cfg["proxy"]), ("spice", f"http://{self.host.hostname}:3128"))
        text = spice.vv_text(cfg)
        self.assertTrue(text.startswith("[virt-viewer]\n"))
        self.assertIn("delete-this-file=1", text)
        self.assertIn("ca=-----BEGIN CERTIFICATE-----\\n", text)  # kept on one line, as Proxmox sends it

    def test_usb_devices_and_pending(self):
        self.assertEqual([vmhw.usb_id(d) for d in self.pve.usb_devices("pve")], ["0781:5581", "046d:c52b"])  # no hub
        self.pve.update_config("pve", "qemu", 201, {"audio0": "device=ich9-intel-hda,driver=spice",
                                                     "usb0": "host=046d:c52b"})
        self.assertEqual(self.pve.pending("pve", 201), ["audio0"])  # running: the sound card waits for a restart
        cfg = self.pve.guest_config("pve", "qemu", 201)
        self.assertEqual((cfg["audio0"], cfg["usb0"]), ("device=ich9-intel-hda,driver=spice", "host=046d:c52b"))
        self.pve.wait_task("pve", self.pve.guest_action("pve", "qemu", 201, "reboot"), timeout=5)
        self.assertEqual(self.pve.pending("pve", 201), [])
        self.pve.update_config("pve", "qemu", 201, {"delete": "audio0,usb0"})
        cfg = self.pve.guest_config("pve", "qemu", 201)
        self.assertNotIn("audio0", cfg)
        self.assertNotIn("usb0", cfg)

    def test_backups(self):
        old = self.pve.backups("pve", 101)
        self.assertEqual(len(old), 2)
        self.assertGreater(old[0]["ctime"], old[1]["ctime"])  # newest first
        self.assertEqual([b["protected"] for b in old], [0, 1])
        lines = []
        upid = self.pve.backup_now("pve", 201, "local", "snapshot", "zstd", "{{guestname}} weekly", protected=True)
        self.pve.wait_task("pve", upid, timeout=5, poll=0.05, on_log=lines.append)
        self.assertTrue(any("50%" in ln for ln in lines))
        self.assertEqual(lines[-1], "INFO: Backup job finished successfully")  # the last line is not missed
        new = self.pve.backups("pve", 201)[0]
        self.assertEqual((new["notes"], new["protected"]), ("ubuntu-desktop weekly", 1))
        with self.assertRaises(PveError):  # running: cannot be replaced
            self.pve.restore("pve", "qemu", 201, new["volid"], replace=True)
        self.pve.wait_task("pve", self.pve.restore("pve", "qemu", 205, new["volid"]), timeout=5)  # as a new VM
        self.assertEqual({g["vmid"]: g["name"] for g in self.pve.guests()}[205], "ubuntu-desktop")
        with self.assertRaises(PveError):  # protected
            self.pve.delete_backup("pve", "local", new["volid"])
        self.pve.protect_backup("pve", "local", new["volid"], False)
        self.pve.wait_task("pve", self.pve.delete_backup("pve", "local", new["volid"]), timeout=5)
        self.assertEqual(self.pve.backups("pve", 201), [])
        with self.assertRaises(ValueError):
            self.pve.backup_now("pve", 201, "local", mode="hibernate")

    def test_package_sources_over_https(self):
        """Through the real request path: Proxmox's parameter is called "path", like post()'s own argument (it broke)."""
        self.pve.change_repository("pve", "/etc/apt/sources.list.d/pve-enterprise.sources", 0, False)
        self.assertEqual(self.srv.cluster.repo_files[1]["repositories"][0]["Enabled"], 0)
        self.pve.add_repository("pve", "no-subscription")
        self.assertTrue(self.srv.cluster._repos_on("download.proxmox.com/debian/pve"))
        std = {r["handle"]: r.get("status") for r in self.pve.apt_repositories("pve")["standard-repos"]}
        self.assertEqual((std["enterprise"], std["no-subscription"], std.get("test")), (0, 1, None))

    def test_backups_of_deleted_guests(self):
        self.assertEqual(self.pve.deleted_guests_backups(), [])  # every backup's guest exists
        c = self.srv.cluster
        c.backups.append(c._backup_entry(c.guests[102], "local", time.time() - 60, "test-box", False))
        del c.guests[102]
        self.assertEqual([(b["vmid"], b["node"]) for b in self.pve.deleted_guests_backups()], [(102, "pve")])
        self.pve.wait_task("pve", self.pve.restore("pve", "lxc", 102, c.backups[-1]["volid"], unique=False), timeout=5)
        self.assertNotIn("unique", c.restored_with)  # its old MAC addresses kept
        self.assertEqual(self.pve.deleted_guests_backups(), [])  # it exists again
        self.pve.wait_task("pve", self.pve.restore("pve", "lxc", 150, c.backups[-1]["volid"]), timeout=5)
        self.assertEqual(c.restored_with["unique"], "1")  # a copy beside it: new addresses, as before

    def test_delete_backups_skips_protected_and_goes_on_after_a_failure(self):
        old = self.pve.backups("pve", 101)  # one plain, one protected
        gone = {"volid": "local:backup/vzdump-lxc-101-2020_01_01-00_00_00.tar.zst", "storage": "local"}
        failed = self.pve.delete_backups("pve", [gone] + old)
        self.assertEqual([b["volid"] for b, _ in failed], [gone["volid"]])
        self.assertIn("does not exist", failed[0][1])
        self.assertEqual([b["protected"] for b in self.pve.backups("pve", 101)], [1])

    def test_backup_jobs(self):
        self.assertEqual([j["id"] for j in self.pve.backup_jobs()], ["backup-nightly"])
        self.assertEqual(sorted(g["vmid"] for g in self.pve.not_backed_up()), [102, 200, 201])
        self.pve.create_backup_job({"schedule": "sat,sun 02:00", "storage": "local", "all": True, "exclude": "102",
                                    "mode": "snapshot", "enabled": True})
        self.assertEqual([g["vmid"] for g in self.pve.not_backed_up()], [102])
        new = next(j for j in self.pve.backup_jobs() if j["id"] != "backup-nightly")
        self.pve.update_backup_job(new["id"], {"enabled": False, "delete": "exclude"})
        changed = next(j for j in self.pve.backup_jobs() if j["id"] == new["id"])
        self.assertEqual((changed["enabled"], "exclude" in changed), (0, False))
        self.pve.delete_backup_job(new["id"])
        self.assertEqual(len(self.pve.backup_jobs()), 1)
        lines = []
        upid = self.pve.run_job_now("pve", self.pve.backup_jobs()[0])  # both of its guests, in one task
        self.pve.wait_task("pve", upid, timeout=5, poll=0.05, on_log=lines.append)
        self.assertEqual(sum("Backup job finished" in ln for ln in lines), 2)
        self.assertEqual(len(self.pve.backups("pve", 100)), 1)

    def test_bulk_start_shutdown_and_tasks(self):
        c = self.srv.cluster
        self.pve.update_config("pve", "lxc", 102, {"startup": "order=1"})
        lines = []
        upid = self.pve.start_all("pve", [200, 102])
        self.pve.wait_task("pve", upid, timeout=5, poll=0.05, on_log=lines.append)
        self.assertEqual(lines, ["Starting CT 102", "Starting VM 200", "TASK OK"])  # boot order, not the order asked
        self.assertEqual(c.last_bulk, {"vms": "200,102", "force": "1"})  # force: also those without Start at boot
        lines = []
        upid = self.pve.stop_all("pve", [100, 102, 200], timeout=60, force_stop=False)
        self.pve.wait_task("pve", upid, timeout=5, poll=0.05, on_log=lines.append)
        self.assertEqual(lines[:3], ["Stopping VM 200", "Stopping CT 100", "Stopping CT 102"])  # the reverse
        self.assertEqual((c.last_bulk["timeout"], c.last_bulk["force-stop"]), ("60", "0"))
        self.assertEqual({g["vmid"]: g["status"] for g in self.pve.guests()}[102], "stopped")
        listed = self.pve.tasks("pve", limit=10)
        self.assertEqual([t["type"] for t in listed[:2]], ["stopall", "startall"])  # newest first
        running = c.long_task("vzdump", 101, ["INFO: starting new backup job"])
        self.assertNotIn(running, [t["upid"] for t in c.list_tasks({}, "pve")])  # Proxmox's default leaves it out…
        task = next(t for t in self.pve.tasks("pve") if t["upid"] == running)  # …the app asks for it
        self.assertTrue(tasks.running(task))
        self.pve.stop_task("pve", running)
        self.assertEqual(self.srv.requests[-1][:2], ("DELETE", f"/nodes/pve/tasks/{running}"))  # encoded, intact
        with self.assertRaises(PveError) as ctx:
            self.pve.wait_task("pve", running, timeout=5)
        self.assertIn("interrupted by signal", str(ctx.exception))

    def test_errors_are_worded(self):
        with self.assertRaises(PveError) as ctx:
            self.pve.delete_guest("pve", "lxc", 100)  # running
        self.assertIn("stop it first", str(ctx.exception))
        self.srv.cluster.forbidden.add(r"POST /nodes/pve/lxc/\d+/status/.*")
        with self.assertRaises(PveError) as ctx:
            self.pve.guest_action("pve", "lxc", 100, "stop")
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn("not allowed", str(ctx.exception))
        self.host.token_secret = "wrong"
        with self.assertRaises(PveError) as ctx:
            self.pve.version()
        self.assertIn("refused the API token", str(ctx.exception))

    def test_unreachable_host(self):
        dead = Host(id="x", name="Dead", address="127.0.0.1:1", fingerprint=self.fp)
        with self.assertRaises(PveError) as ctx:
            Pve(dead, timeout=2).version()
        self.assertIn("Could not reach", str(ctx.exception))


class DemoTest(unittest.TestCase):
    def test_demo_answers_like_the_api(self):
        pve = DemoPve(DEMO_HOSTS[0])
        self.assertTrue(pve.guests())
        upid = pve.guest_action("pve", "qemu", 200, "start")
        self.assertEqual(pve.wait_task("pve", upid)["exitstatus"], "OK")
        self.assertIn("console=kvm", pve.console_url("pve", "qemu", 200))


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name, "APPDATA": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_hosts_roundtrip_secrets_apart(self):
        h = Host(id=store.new_host_id(), name="Home", address="192.168.1.80", token_id="root@pam!c",
                 token_secret="s3cret", fingerprint="AB:CD", mac="3c:ec:ef:6e:a7:96")
        store.save_hosts([h])
        folder = store.config_dir()
        hosts_text = (folder / "hosts.json").read_text()
        self.assertNotIn("s3cret", hosts_text)
        self.assertEqual(json.loads((folder / "secrets.json").read_text())["tokens"][h.id], "s3cret")
        if os.name == "posix":  # (Windows: %APPDATA% is the user's own already)
            for name in ("hosts.json", "secrets.json"):
                self.assertEqual(stat.S_IMODE(os.stat(folder / name).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700)
        again = store.load_hosts()
        self.assertEqual(again, [h])

    @unittest.skipUnless(sys.platform.startswith("linux"), "names an fsync'd file through /proc")
    def test_writes_survive_a_power_cut(self):
        synced = []
        real_fsync = os.fsync
        with mock.patch.object(store.os, "fsync", lambda fd: (synced.append(os.path.realpath(f"/proc/self/fd/{fd}")),
                                                              real_fsync(fd))):
            store.save_settings(dict(store.SETTINGS_DEFAULTS))
        folder = os.path.realpath(store.config_dir())
        self.assertEqual(synced, [os.path.join(folder, "settings.tmp"), folder])  # the data, then the rename
        self.assertFalse(os.path.exists(os.path.join(folder, "settings.tmp")))
        order = []
        with mock.patch.object(store, "_write_private", lambda path, payload: order.append(path.name)):
            store.save_hosts([])
        self.assertEqual(order, ["secrets.json", "hosts.json"])  # never a host without its token secret

    def test_settings_keep_true_and_false(self):
        store.save_settings({**store.SETTINGS_DEFAULTS, "hide_stopped": True, "refresh_seconds": 30})
        cfg = store.load_settings()
        self.assertEqual((cfg["hide_stopped"], cfg["refresh_seconds"]), (True, 30))
        (store.config_dir() / "settings.json").write_text('{"hide_stopped": 1, "refresh_seconds": true}')
        cfg = store.load_settings()
        self.assertEqual((cfg["hide_stopped"], cfg["refresh_seconds"]), (False, 10))  # wrong types: defaults

    def test_broken_files_are_ignored(self):
        folder = store.config_dir()
        folder.mkdir(parents=True)
        (folder / "hosts.json").write_text('{"hosts": [{"name": "no id"}, 5, {"id": "a", "address": "x"}]}')
        self.assertEqual([h.id for h in store.load_hosts()], ["a"])
        (folder / "settings.json").write_text('{"refresh_seconds": 7}')
        self.assertEqual(store.load_settings()["refresh_seconds"], 10)


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name, "APPDATA": self.tmp.name})
        self.env.start()
        store.lock_session()

    def tearDown(self):
        store.lock_session()  # the key must not outlive the test
        self.env.stop()
        self.tmp.cleanup()

    def test_seal_and_open(self):
        key = vault.derive("correct horse", n=1 << 10)  # a small cost: the test is about the format, not the strength
        blob = vault.seal({"tokens": {"h": "s3cret"}}, key)
        self.assertTrue(vault.is_locked(blob))
        self.assertNotIn("s3cret", json.dumps(blob))
        self.assertEqual(vault.open_with(blob, "correct horse")[0], {"tokens": {"h": "s3cret"}})
        self.assertNotEqual(blob["locked"]["nonce"], vault.seal({}, key)["locked"]["nonce"])  # never reused
        with self.assertRaises(vault.WrongPassword):
            vault.open_with(blob, "wrong horse")
        data = bytearray(base64.b64decode(blob["locked"]["data"]))
        data[0] ^= 1  # one bit changed on disk
        bad = {"locked": dict(blob["locked"], data=base64.b64encode(bytes(data)).decode())}
        with self.assertRaises(vault.WrongPassword):
            vault.open_with(bad, "correct horse")
        self.assertEqual((vault.KDF["n"], vault.KDF["r"]), (1 << 17, 8))  # what real passwords get

    def test_lock_the_store(self):
        h = Host(id="h1", name="Home", address="192.168.1.80", token_id="root@pam!c", token_secret="s3cret",
                 fingerprint="AB:CD")
        store.save_hosts([h])
        store.save_claude_token("h1", "claude-secret")
        self.assertEqual(store.secrets_state(), "plain")
        with mock.patch.object(vault, "KDF", {"n": 1 << 10, "r": 8, "p": 1}):  # quick, for the test
            with self.assertRaises(ValueError):
                store.set_password("")  # any password, but one
            store.set_password("x")  # however short
            store.set_password("correct horse")
            raw = (store.config_dir() / "secrets.json").read_text()
            self.assertEqual(store.secrets_state(), "locked")
            self.assertNotIn("s3cret", raw)
            self.assertNotIn("claude-secret", raw)
            self.assertEqual(store.load_hosts()[0].token_secret, "s3cret")  # this run keeps the key
            store.lock_session()  # the next start
            self.assertEqual(store.load_hosts()[0].token_secret, "")  # the host, but not its token
            self.assertEqual(store.claude_token("h1"), "")
            with self.assertRaises(store.Locked):
                store.save_hosts([h])  # never overwritten with nothing
            with self.assertRaises(vault.WrongPassword):
                store.unlock("wrong horse")
            store.unlock("correct horse")
            self.assertEqual((store.load_hosts()[0].token_secret, store.claude_token("h1")),
                             ("s3cret", "claude-secret"))
            store.save_hosts([h])  # saved again: still locked, Claude's token kept
            self.assertEqual(store.secrets_state(), "locked")
            self.assertEqual(store.claude_token("h1"), "claude-secret")
            store.save_hosts([])  # the host removed: its Claude token goes with it
            store.save_hosts([h])
            self.assertEqual(store.claude_token("h1"), "")
            with self.assertRaises(vault.WrongPassword):
                store.remove_password("wrong horse")
            store.remove_password("correct horse")
            self.assertEqual(store.secrets_state(), "plain")
            self.assertEqual(store.load_hosts()[0].token_secret, "s3cret")
            store.set_password("correct horse")
            store.forget_secrets()  # a forgotten password
            self.assertEqual((store.secrets_state(), store.load_hosts()[0].token_secret), ("none", ""))



class BridgeEncodingTest(unittest.TestCase):
    """MCP talks UTF-8 a line at a time, whatever the computer's code page: on Windows the bridge's pipes came in
    cp1252 — the — of the tools' descriptions went out as the byte 0x97 (measured with the built program)."""

    def test_bridge_speaks_utf8_whatever_the_code_page(self):
        messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "Δοκιμή"}}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        raw_in = io.BytesIO("".join(json.dumps(m, ensure_ascii=False) + "\n" for m in messages).encode("utf-8"))
        raw_out = io.BytesIO()
        stdin = io.TextIOWrapper(raw_in, encoding="cp1252")  # as Windows gives a program's pipes
        stdout = io.TextIOWrapper(raw_out, encoding="cp1252", newline="\r\n", write_through=True)
        with mock.patch.object(mcp.sys, "stdin", stdin), mock.patch.object(mcp.sys, "stdout", stdout):
            mcp.main()
        data = raw_out.getvalue()
        text = data.decode("utf-8")  # strict: every byte is UTF-8
        self.assertIn("\u2014".encode("utf-8"), data)  # the dash in the descriptions, as UTF-8
        self.assertNotIn(b"\r\n", data)  # a message a line, ended by \n alone
        answers = [json.loads(line) for line in text.splitlines()]
        self.assertEqual([a["id"] for a in answers], [1, 2])
        self.assertEqual(len(answers[1]["result"]["tools"]), len(connector_tools.TOOLS))

    def test_askpass_gives_the_passwords_own_bytes(self):
        from proxmox_controller.core import claude_connect
        password = "κωδικός—1 & ^%"
        done = subprocess.run([*claude_connect.bridge_command(), "--askpass"], capture_output=True, timeout=60,
                              env={**os.environ, "PROXMOX_CONTROLLER_SSH_SECRET": password})
        self.assertEqual(done.stdout.rstrip(b"\r\n"), password.encode("utf-8"))


class McpBridgeTest(unittest.TestCase):
    """The bridge Claude starts: MCP over stdin/stdout, every request handed to the app (here a recorder)."""

    def talk(self, messages, call):
        out = io.StringIO()
        bridge = mcp.Bridge(out=out, call=call)
        mcp.serve([json.dumps(m) if isinstance(m, dict) else m for m in messages], bridge)
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def test_handshake_tools_and_calls(self):
        seen = []

        def call(message, timeout=600):
            seen.append(message)
            return {"result": {"content": [{"type": "text", "text": "fine"}], "isError": False}}

        out = self.talk([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "claude-code"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "list_guests", "arguments": {"host": "h1"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "nope"},
            "not json",
            {"jsonrpc": "2.0", "id": 5, "method": "ping"}], call)
        by_id = {m.get("id"): m for m in out}
        init = by_id[1]["result"]
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        self.assertEqual(init["serverInfo"]["name"], "proxmox-controller")
        self.assertIn("list_hosts", init["instructions"])
        tools = {t["name"]: t for t in by_id[2]["result"]["tools"]}
        self.assertEqual(len(tools), len(connector_tools.TOOLS))
        self.assertTrue(tools["list_guests"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["delete_guest"]["annotations"]["destructiveHint"])
        self.assertIn("reason", tools["guest_power"]["inputSchema"]["required"])  # every non-read request says why
        self.assertNotIn("reason", tools["list_guests"]["inputSchema"]["properties"])
        self.assertEqual(by_id[3]["result"]["content"][0]["text"], "fine")
        self.assertEqual((seen[0]["tool"], seen[0]["args"], seen[0]["client"]), ("list_guests", {"host": "h1"},
                                                                                "claude-code"))
        self.assertEqual(by_id[4]["error"]["code"], -32601)
        self.assertEqual(by_id[None]["error"]["code"], -32700)
        self.assertEqual(by_id[5]["result"], {})
        newest = self.talk([{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "1999-01-01"}}], call)
        self.assertEqual(newest[0]["result"]["protocolVersion"], mcp.PROTOCOLS[0])  # one it does not know: the newest

    def test_app_not_running_and_cancel(self):
        def closed(message, timeout=600):
            raise connector_link.AppNotRunning("no")

        out = self.talk([{"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                          "params": {"name": "list_hosts", "arguments": {}}}], closed)
        self.assertTrue(out[0]["result"]["isError"])
        self.assertIn("not running", out[0]["result"]["content"][0]["text"])
        seen, release = [], threading.Event()

        def slow(message, timeout=600):
            seen.append(message)
            if "cancel" in message:
                release.set()
                return {"result": {}}
            release.wait(5)
            return {"error": "Cancelled before the user answered."}

        out = io.StringIO()
        bridge = mcp.Bridge(out=out, call=slow)
        with mock.patch.object(mcp, "PROGRESS_EVERY_S", 0.05):
            bridge.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                           "params": {"name": "guest_power", "arguments": {}, "_meta": {"progressToken": "p1"}}})
            time.sleep(0.2)  # long enough for a few progress notes
            bridge.handle({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}})
            for t in bridge.threads:
                t.join(5)
        lines = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual(seen[1], {"cancel": seen[0]["key"]})  # the app hears which request was given up
        progress = [m for m in lines if m.get("method") == "notifications/progress"]
        self.assertTrue(progress and progress[0]["params"]["progressToken"] == "p1")
        self.assertEqual([p["params"]["progress"] for p in progress], list(range(1, len(progress) + 1)))
        self.assertIn("Cancelled", lines[-1]["result"]["content"][0]["text"])


class ConnectorLinkTest(unittest.TestCase):
    def fresh_address(self):
        """A line of the test's own: a Unix socket in a short folder (its path must be short), or on Windows a named
        pipe."""
        if connector_link.WINDOWS:
            return "\\\\.\\pipe\\pvc-test-" + os.urandom(8).hex()
        folder = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, folder, True)
        return Path(folder) / "c.sock"

    def test_round_trip_and_privacy(self):
        path = self.fresh_address()
        server = connector_link.LinkServer(lambda m: {"echo": m["n"] * 2}, path)
        self.assertTrue(server.start())
        self.addCleanup(server.stop)
        if not connector_link.WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)  # this user's alone
        self.assertEqual(connector_link.request({"n": 21}, path=path), {"echo": 42})
        self.assertEqual(connector_link.request({"n": 4}, path=path), {"echo": 8})  # one request a connection
        other = connector_link.LinkServer(lambda m: {}, path)
        self.assertFalse(other.start())  # one app answers; a second window leaves it be
        server.stop()
        if not connector_link.WINDOWS:
            self.assertFalse(path.exists())
        with self.assertRaises(connector_link.AppNotRunning):
            connector_link.request({"n": 1}, path=path)
        if not connector_link.WINDOWS:
            Path(path).touch()  # left by an app that ended in a power cut
        again = connector_link.LinkServer(lambda m: {"ok": True}, path)
        self.assertTrue(again.start())  # (Windows: the pipe's name is free again once its maker stops)
        self.addCleanup(again.stop)
        self.assertEqual(connector_link.request({}, path=path), {"ok": True})

    def test_a_failing_handler_still_answers(self):
        path = self.fresh_address()
        server = connector_link.LinkServer(lambda m: 1 / 0, path)
        self.assertTrue(server.start())
        self.addCleanup(server.stop)
        self.assertIn("ZeroDivisionError", connector_link.request({}, path=path)["error"])

    def test_pipe_name(self):
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": ""}), \
                mock.patch.object(connector_link.getpass, "getuser", return_value="DOMAIN\\Jo Doe"):
            plain = connector_link.pipe_name()
        self.assertEqual(plain, "\\\\.\\pipe\\proxmox-controller-DOMAIN_Jo_Doe")  # the same for the app and the bridge
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/tmp/pvc-a"}):
            a = connector_link.pipe_name()
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/tmp/pvc-b"}):
            b = connector_link.pipe_name()
        self.assertNotEqual(a, b)  # each test's runtime folder, its own pipe

    @unittest.skipIf(connector_link.WINDOWS, "Unix sockets")
    def test_socket_path(self):
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}), \
                mock.patch.object(connector_link, "_private_folder", lambda f: f):
            self.assertEqual(str(connector_link.socket_path()), "/run/user/1000/proxmox-controller/connector.sock")
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/very" + "/long" * 30}), \
                mock.patch.object(connector_link, "_private_folder", lambda f: f):
            self.assertTrue(str(connector_link.socket_path()).startswith(f"/tmp/proxmox-controller-{os.getuid()}/"))
        bare = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
        with mock.patch.dict(os.environ, bare, clear=True), \
                mock.patch.object(connector_link, "_private_folder", lambda f: f):
            with mock.patch.object(connector_link, "user_runtime_dir", lambda: "/run/user/1000"):
                self.assertEqual(str(connector_link.socket_path()), "/run/user/1000/proxmox-controller/connector.sock")
            with mock.patch.object(connector_link, "user_runtime_dir", lambda: ""):
                self.assertTrue(str(connector_link.socket_path()).startswith("/tmp/proxmox-controller-"))

    @unittest.skipIf(connector_link.WINDOWS, "Unix sockets")
    def test_user_runtime_dir_only_when_it_is_the_users(self):
        root = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, root, True)
        self.assertEqual(connector_link.user_runtime_dir(root), "")  # not there
        os.mkdir(os.path.join(root, str(os.getuid())))
        self.assertEqual(connector_link.user_runtime_dir(root), os.path.join(root, str(os.getuid())))
        os.mkdir(os.path.join(root, "4242"))
        with mock.patch.object(connector_link.os, "getuid", return_value=4242):
            self.assertEqual(connector_link.user_runtime_dir(root), "")  # there, but not this user's
        odd = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, odd, True)
        Path(odd, str(os.getuid())).touch()
        self.assertEqual(connector_link.user_runtime_dir(odd), "")  # a file, not a folder

    @unittest.skipIf(connector_link.WINDOWS, "Unix sockets")
    def test_bridge_without_xdg_runtime_dir_meets_the_app(self):
        """Claude Desktop starts the bridge with a bare environment — no XDG_RUNTIME_DIR — while the app has it (the
        user's sessions all said 'not running (or is still locked)' with the app open, 17/10): both must still land
        on the same socket."""
        root = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, root, True)
        runtime = os.path.join(root, str(os.getuid()))
        os.mkdir(runtime, 0o700)
        real = connector_link.user_runtime_dir
        with mock.patch.object(connector_link, "user_runtime_dir", lambda: real(root)):
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime}):
                app_side = connector_link.socket_path()
            bare = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
            with mock.patch.dict(os.environ, bare, clear=True):
                bridge_side = connector_link.socket_path()
            self.assertEqual(bridge_side, app_side)
            server = connector_link.LinkServer(lambda m: {"echo": m["n"]}, app_side)
            self.assertTrue(server.start())
            self.addCleanup(server.stop)
            with mock.patch.dict(os.environ, bare, clear=True):
                self.assertEqual(connector_link.request({"n": 7}), {"echo": 7})  # the bridge's own way to the app


class ScreenTest(unittest.TestCase):
    def test_picture_and_keys(self):
        DemoPve._clusters.clear()
        pve = DemoPve(DEMO_HOSTS[0])
        opener = lambda: pve.open_vnc("pve", "qemu", 201)  # noqa: E731
        w, h, pixels = screen.capture(opener)
        self.assertEqual((w, h, len(pixels)), (720, 400, 720 * 400 * 4))
        image, iw, ih = screen.png(w, h, pixels)
        self.assertEqual(image[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", image[16:24]), (720, 400))
        raw = zlib.decompress(image[image.index(b"IDAT") + 4:image.index(b"IEND") - 8])
        self.assertEqual(len(raw), 400 * (1 + 720 * 3))
        b, g, r, _ = pixels[:4]
        self.assertEqual(tuple(raw[1:4]), (r, g, b))  # blue-green-red becomes red-green-blue
        _, sw, sh = screen.png(2600, 4, bytes(2600 * 4 * 4))
        self.assertEqual((sw, sh), (867, 2))  # wide screens are scaled by a whole factor
        self.assertEqual(screen.send(opener, "Hi!", ["enter", "ctrl+alt+delete"]), 5)
        server = pve.cluster.consoles[-1]
        self.assertTrue(wait_for(lambda: len(server.keys) >= 18))
        syms = [k[2] for k in server.keys if k[1]]
        self.assertEqual(syms[:6], [0xFFE1, ord("H"), ord("i"), 0xFFE1, ord("!"), 0xFF0D])  # Shift for H and !
        self.assertEqual(syms[6:9], [0xFFE3, 0xFFE9, 0xFFFF])  # ctrl, alt, delete held together
        with self.assertRaises(ValueError):
            screen.send(opener, keys=["hyperspace"])  # nothing typed when a key name is wrong

    def test_click_scroll_and_mark(self):
        DemoPve._clusters.clear()
        pve = DemoPve(DEMO_HOSTS[0])
        opener = lambda: pve.open_vnc("pve", "qemu", 201)  # noqa: E731

        def events(n):
            srv = pve.cluster.consoles[-1]
            self.assertTrue(wait_for(lambda: len(srv.pointer) >= n))
            return srv.pointer

        self.assertEqual(screen.click(opener, 100, 50), (100, 50))
        self.assertEqual(events(3), [(0, 100, 50), (1, 100, 50), (0, 100, 50)])  # there first, press, let go
        screen.click(opener, 10, 20, "right", double=True)
        self.assertEqual([p[0] for p in events(5)], [0, 4, 0, 4, 0])
        screen.click(opener, 10, 20, scroll=-2)
        self.assertEqual([p[0] for p in events(5)], [0, 16, 0, 16, 0])  # the wheel, down
        with self.assertRaises(ValueError):
            screen.click(opener, 720, 10)  # 720 wide: 0–719
        with self.assertRaises(ValueError):
            screen.click(opener, 1, 1, "thumb")
        wide = []

        def wide_opener():  # a screen wider than the pictures: they are a third as wide, and so are the click's numbers
            mine, theirs = socket.socketpair()
            wide.append(FakeVncServer(WebSocket(theirs, client=False), "pw", 2600, 100, "wide").start())
            return WebSocket(mine), "pw"

        self.assertEqual(screen.scale_of(2600), 3)
        self.assertEqual(screen.click(wide_opener, 400, 30), (1200, 90))
        self.assertTrue(wait_for(lambda: len(wide[-1].pointer) >= 3))
        self.assertEqual(wide[-1].pointer[1], (1, 1200, 90))
        self.assertEqual(screen.click(wide_opener, 866, 0), (2598, 0))  # the picture's last column
        with self.assertRaises(ValueError):
            screen.click(wide_opener, 867, 0)
        w, h = 64, 48
        marked = screen.mark(w, h, bytes(w * h * 4), 32, 24)
        px = lambda x, y: marked[(y * w + x) * 4:(y * w + x) * 4 + 4]  # noqa: E731
        red = b"\x00\x00\xff\xff"
        self.assertEqual((px(32, 24), px(32 + 18, 24), px(32 + 8, 24), px(32, 24 - 8)), (bytes(4), red, red, red))
        self.assertEqual(len(marked), w * h * 4)
        screen.mark(w, h, bytes(w * h * 4), 0, 0)  # at a corner: what falls outside is left out


def wait_for(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


class ClaudeAccessTest(unittest.TestCase):
    def setUp(self):
        DemoPve._clusters.clear()
        self.admin = DemoPve(DEMO_HOSTS[0])
        self.cluster = self.admin.cluster
        self.switches = claude_policy.host_switches({}, "demo-pve")

    def claude(self, secret):
        return DemoPve(Host(id="demo-pve", name="Home", address="192.0.2.80", token_id=claude_access.TOKEN_ID,
                            token_secret=secret, fingerprint="DEMO"))

    def refused(self, fn):
        with self.assertRaises(PveError) as ctx:
            fn()
        self.assertEqual(ctx.exception.status, 403)

    def test_read_at_rest_and_lent_per_request(self):
        secret, given = claude_access.setup(self.admin, self.switches)
        self.assertEqual(given, list(claude_policy.PRIVILEGES["read"]))  # between requests: reading only
        c = self.claude(secret)
        self.assertEqual(len(c.guests()), 5)
        self.refused(lambda: c.delete_guest("pve", "lxc", 102))  # Change is Ask, Destroy Off: neither stands
        self.refused(lambda: c.guest_action("pve", "lxc", 102, "start"))
        status, _, _ = self.cluster.handle("GET", "/access/users", {}, f"PVEAPIToken={claude_access.TOKEN_ID}={secret}")
        self.assertEqual(status, 403)  # and never the users, roles or permissions themselves
        loans = claude_access.Loans()
        with loans.lend("demo-pve", self.admin, lambda: self.switches, claude_policy.PRIVILEGES["power"]):
            c.guest_action("pve", "lxc", 102, "start")  # lent for the request
            with loans.lend("demo-pve", self.admin, lambda: self.switches, claude_policy.PRIVILEGES["power"]):
                pass
            c.guest_action("pve", "lxc", 102, "stop")  # the inner request ended; the outer one still runs
        self.refused(lambda: c.guest_action("pve", "lxc", 102, "start"))  # given back
        self.assertEqual(self.cluster.roles[claude_access.ROLE], list(claude_policy.PRIVILEGES["read"]))

    def test_switches_and_removal(self):
        secret, _ = claude_access.setup(self.admin, self.switches)
        c = self.claude(secret)
        self.switches["read"] = "ask"
        self.assertEqual(claude_access.sync(self.admin, self.switches), [])  # nothing at rest: the permission goes
        self.refused(lambda: c.guest_config("pve", "lxc", 100))
        self.switches["read"] = "on"
        claude_access.sync(self.admin, self.switches)
        self.assertTrue(c.guest_config("pve", "lxc", 100))
        again, _ = claude_access.setup(self.admin, self.switches)  # set up again: a new token
        with self.assertRaises(PveError):
            c.guests()  # the old secret no longer works
        claude_access.remove(self.admin)
        claude_access.remove(self.admin)  # twice: nothing left to remove is fine
        self.assertEqual(([u["userid"] for u in self.admin.get("/access/users")], self.cluster.roles,
                          self.cluster.acl), (["root@pam"], {}, []))

    def test_older_proxmox_without_the_network_privilege(self):
        self.cluster.has_access_network = False
        secret, _ = claude_access.setup(self.admin, self.switches)
        with claude_access.Loans().lend("demo-pve", self.admin, lambda: self.switches,
                                        claude_policy.PRIVILEGES["change"]):
            role = self.cluster.roles[claude_access.ROLE]
            self.assertIn("VM.Allocate", role)
            self.assertNotIn("Sys.AccessNetwork", role)  # left out rather than failing
        self.cluster.has_access_network = True
        with claude_access.Loans().lend("demo-pve", self.admin, lambda: self.switches,
                                        claude_policy.PRIVILEGES["change"]):
            self.assertIn("Sys.AccessNetwork", self.cluster.roles[claude_access.ROLE])

    def test_policy(self):
        settings = {}
        self.assertEqual(claude_policy.decide(settings, "h", "read"), "off")  # the switch for all starts off
        settings["claude"] = {"enabled": True}
        self.assertEqual([claude_policy.decide(settings, "h", k) for k in claude_policy.KEYS],
                         ["on", "ask", "ask", "off", "off", "off", "off", "off", "off"])  # the user's chosen defaults
        # (the eighth, Host commands, 17/10: Off for every new host — root on the host is the most there is)
        allow = claude_policy.Allowances()
        self.assertEqual(allow.remaining("h", "power"), 0)
        allow.grant("h", "power", 60)
        self.assertEqual(claude_policy.decide(settings, "h", "power", allow), "on")  # "for 1 hour"
        self.assertTrue(59 < allow.remaining("h", "power") <= 60)
        self.assertEqual(claude_policy.TEMP_ALLOW_HOURS, (1, 3, 8, 12))  # the arrow's choices (the user's, 19/10)
        self.assertEqual(claude_policy.decide(settings, "other", "power", allow), "ask")
        claude_policy.set_switch(settings, "h", "power", "off")
        self.assertEqual(claude_policy.decide(settings, "h", "power", allow), "off")  # Off beats an hour granted
        with self.assertRaises(ValueError):
            claude_policy.set_switch(settings, "h", "power", "maybe")


class ConnectorToolsTest(unittest.TestCase):
    """Each tool against the pretend cluster (here with root's token: the switches and the lending are the
    connector's part, tested in the UI tests)."""

    def setUp(self):
        DemoPve._clusters.clear()
        self.pve = DemoPve(DEMO_HOSTS[0])
        self.cluster = self.pve.cluster
        self.woken = []

    def ctx(self, host=DEMO_HOSTS[0]):
        return connector_tools.Context(host=host, pve=self.pve, admin=self.pve,
                                       wake=lambda mac, broadcast: self.woken.append(mac))

    def run_tool(self, tool_name, /, secret="", **args):
        tool = connector_tools.TOOLS[tool_name]
        ctx = self.ctx()
        ctx.secret = secret  # (what the user would type in the app's window)
        return tool.run(ctx, connector_tools.check(tool, args))

    def words(self, tool_name, /, **args):
        tool = connector_tools.TOOLS[tool_name]
        return tool.words(self.ctx(), connector_tools.check(tool, args))

    def status(self, vmid):
        return self.cluster.guests[vmid]["status"]

    def test_arguments_are_checked(self):
        T, ToolError = connector_tools, connector_tools.ToolError
        power = T.TOOLS["guest_power"]
        for args, problem in (({"host": "h", "vmid": 1, "action": "start"}, "Missing: reason"),
                              ({"host": "h", "vmid": 1, "action": "fly", "reason": "x"}, "action must be one of"),
                              ({"host": "h", "vmid": "1", "action": "start", "reason": "x"}, "vmid must be integer"),
                              ({"host": "h", "vmid": True, "action": "start", "reason": "x"}, "vmid must be integer"),
                              ({"host": "h", "vmid": 1, "action": "start", "reason": "x", "sudo": 1}, "Unknown")):
            with self.assertRaises(ToolError) as ctx:
                T.check(power, args)
            self.assertIn(problem, str(ctx.exception))
        with self.assertRaises(ToolError):
            T.check(T.TOOLS["list_tasks"], {"host": "h", "limit": 500})  # beyond the maximum

    def test_reading(self):
        status = self.run_tool("host_status", host="demo-pve")
        self.assertEqual(status["nodes"][0]["node"], "pve")
        self.assertIn("local", [s["storage"] for s in status["nodes"][0]["storages"]])
        guests = {g["vmid"]: g for g in self.run_tool("list_guests", host="demo-pve")}
        self.assertEqual(sorted(guests), [100, 101, 102, 200, 201])
        self.assertEqual((guests[100]["ips"], guests[100]["start_at_boot"], guests[101]["tags"]),
                         (["192.0.2.10"], True, ["cloud", "prod"]))
        details = self.run_tool("guest_details", host="demo-pve", vmid=201)
        self.assertEqual(details["guest"], "VM 201 (ubuntu-desktop)")
        self.assertIn("pending_until_next_start", details)
        self.assertEqual([s["name"] for s in self.run_tool("list_snapshots", host="demo-pve", vmid=101)],
                         ["before-upgrade"])
        self.assertEqual(len(self.run_tool("list_backups", host="demo-pve", vmid=101)), 2)
        jobs = self.run_tool("list_backup_jobs", host="demo-pve")
        self.assertEqual((jobs["jobs"][0]["when"], sorted(g["vmid"] for g in jobs["guests_no_job_covers"])),
                         ("Every day at 03:00", [102, 200, 201]))
        tasks_ = self.run_tool("list_tasks", host="demo-pve", limit=5)
        self.assertEqual(tasks_[0]["what"], "VM 201 (ubuntu-desktop) — Start")
        self.assertIn("TASK OK", self.run_tool("task_log", host="demo-pve", upid=tasks_[0]["upid"])["lines"])
        usage = self.run_tool("guest_usage", host="demo-pve", vmid=101, timeframe="day")
        self.assertGreater(usage["points"], 0)
        self.assertIsNotNone(usage["cpu_percent"])
        media = self.run_tool("list_install_media", host="demo-pve")
        self.assertTrue(media["isos"] and media["container_templates"] and media["bridges"])
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("guest_details", host="demo-pve", vmid=999)

    def test_power(self):
        self.assertEqual(self.words("guest_power", host="demo-pve", vmid=100, action="stop", reason="r")[0],
                         "Stop Container 100 (pihole)")
        self.assertEqual(self.run_tool("guest_power", host="demo-pve", vmid=102, action="start", reason="r")["status"],
                         "done")
        self.assertEqual(self.status(102), "running")
        self.run_tool("bulk_power", host="demo-pve", action="shutdown", vmids=[100, 102], timeout_s=60, reason="r")
        self.assertEqual((self.status(100), self.status(102), self.cluster.last_bulk["timeout"]),
                         ("stopped", "stopped", "60"))
        self.run_tool("wake_host", host="demo-pve", reason="r")
        self.assertEqual(self.woken, [DEMO_HOSTS[0].mac])
        no_mac = Host(id="demo-pve", name="Home", address="192.0.2.80", token_id="root@pam!controller",
                      token_secret="secret", fingerprint="DEMO")
        with self.assertRaises(connector_tools.ToolError):
            connector_tools.TOOLS["wake_host"].run(self.ctx(no_mac), {"host": "demo-pve", "reason": "r"})

    def test_changes(self):
        what, lines = self.words("edit_guest", host="demo-pve", vmid=100, reason="r",
                                 changes={"memory_mib": 1024, "boot_order": 2, "tags": ["dns"]})
        self.assertEqual(what, "Edit Container 100 (pihole)")
        self.assertIn("Memory (MiB): 512 → 1024", lines)
        self.run_tool("edit_guest", host="demo-pve", vmid=100, reason="r",
                      changes={"memory_mib": 1024, "boot_order": 2, "tags": ["dns"], "notes": "DNS"})
        cfg = self.pve.guest_config("pve", "lxc", 100)
        self.assertEqual((cfg["memory"], cfg["startup"], cfg["tags"], cfg["description"]),
                         (1024, "order=2", "dns", "DNS"))
        same = self.run_tool("edit_guest", host="demo-pve", vmid=100, reason="r", changes={"memory_mib": 1024})
        self.assertEqual(same["changed"], [])
        for changes in ({"swap_mib": 512}, {"colour": "red"}, {"tags": ["no spaces"]}, {}):
            with self.assertRaises(connector_tools.ToolError):
                self.run_tool("edit_guest", host="demo-pve", vmid=201, reason="r", changes=changes)
        self.run_tool("grow_disk", host="demo-pve", vmid=100, disk="rootfs", add_gb=2, reason="r")
        self.assertEqual(self.cluster.guests[100]["disk_gb"], 6)
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("take_snapshot", host="demo-pve", vmid=100, name="1 bad", reason="r")
        self.run_tool("take_snapshot", host="demo-pve", vmid=100, name="before_update", reason="r")
        self.assertIn("before_update", [s["name"] for s in self.pve.snapshots("pve", "lxc", 100)])
        self.assertEqual(self.run_tool("backup_now", host="demo-pve", vmid=100, reason="r")["status"], "done")
        self.assertEqual(len(self.pve.backups("pve", 100)), 1)
        iso = self.pve.isos("pve")[0]["volid"]
        made = self.run_tool("create_vm", host="demo-pve", name="web", iso=iso, start=True, reason="r")
        self.assertEqual((self.cluster.guests[made["vmid"]]["name"], self.status(made["vmid"])), ("web", "running"))
        template = self.pve.templates("pve")[0]["volid"]
        ct = self.run_tool("create_container", host="demo-pve", hostname="db", template=template, ip="10.0.0.5/24",
                           gateway="10.0.0.1", reason="r")
        self.assertIn("ip=10.0.0.5/24", self.pve.guest_config("pve", "lxc", ct["vmid"])["net0"])
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("create_container", host="demo-pve", hostname="db2", template=template, ip="10.0.0.5",
                          reason="r")  # no prefix
        copy = self.run_tool("clone_vm", host="demo-pve", vmid=201, new_name="ubuntu-2", reason="r")
        self.assertEqual(self.cluster.guests[copy["new_vmid"]]["name"], "ubuntu-2")
        got = self.run_tool("download_iso", host="demo-pve", url="https://example.org/debian-13.iso", reason="r")
        self.assertEqual(got["file"], "local:iso/debian-13.iso")
        backup = self.pve.backups("pve", 101)[1]["volid"]
        tool = connector_tools.TOOLS["restore_backup"]
        self.assertEqual((tool.kind_of({"replace": True}), tool.kind_of({})), ("destroy", "change"))
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("restore_backup", host="demo-pve", vmid=101, volid=backup, replace=True, reason="r")
        new = self.run_tool("restore_backup", host="demo-pve", vmid=101, volid=backup, reason="r")
        self.assertIn(new["vmid"], self.cluster.guests)

    def test_storages_in_a_set_order_disks_on_the_host_first(self):
        """Proxmox lists storages in no set order (the user's New VM offered local-lvm, then nas, 15/10): sorted by
        name — and for VM and container disks the host's own storage before a network share."""
        self.cluster.network_share = True  # (listed first by the fake, as on the user's host)
        names = lambda content=None: [s["storage"] for s in self.pve.storages("pve", content=content)]  # noqa: E731
        self.assertEqual(names("images"), ["local-lvm", "nas"])
        self.assertEqual(names("rootdir"), ["local-lvm", "nas"])
        self.assertEqual(names("backup"), ["local", "nas"])  # by name: as before the NAS came
        self.assertEqual(names("iso"), ["local", "nas"])
        self.assertEqual(names(), ["local", "local-lvm", "nas"])
        iso = self.pve.isos("pve")[0]["volid"]
        template = self.pve.templates("pve")[0]["volid"]
        self.assertIn("local-lvm:", " ".join(self.words("create_vm", host="demo-pve", name="web", iso=iso, reason="r")[1]))
        self.assertIn("disk local-lvm:", " ".join(self.words("create_container", host="demo-pve", hostname="db",
                                                             template=template, reason="r")[1]))
        made = self.run_tool("create_vm", host="demo-pve", name="web", iso=iso, reason="r")  # (not on the NAS)
        self.assertIn(made["vmid"], self.cluster.guests)
        self.assertEqual(storage_order({"storage": "x", "type": "nfs"}, "images")[0], True)  # no "shared": by type

    def test_host_command_over_the_apps_key(self):
        """A command on the host itself, as root, over the SSH key the user set up in the app — none without it, and
        none when the host's key is no longer the confirmed one; the window shows the command as it will run."""
        import dataclasses
        T = connector_tools
        tool = T.TOOLS["host_command"]
        self.assertEqual((tool.kind, claude_policy.DEFAULTS["host_commands"]), ("host_commands", "off"))
        args = T.check(tool, {"host": "demo-pve", "command": "command -v cloudflared", "reason": "r"})
        with self.assertRaises(T.ToolError) as caught:
            tool.words(self.ctx(), args)  # no SSH set up: refused before any window
        self.assertIn("Console → Connect by SSH", str(caught.exception))
        host = dataclasses.replace(DEMO_HOSTS[0], extra={"ssh": {"user": "root", "port": 2222, "key": True}})
        ctx = T.Context(host=host, pve=self.pve, admin=self.pve)
        with mock.patch.object(T.ssh, "trusted_host_key", return_value=""):
            with self.assertRaises(T.ToolError) as caught:
                tool.run(ctx, args)
        self.assertIn("no longer the one the user confirmed", str(caught.exception))
        with mock.patch.object(T.ssh, "trusted_host_key", return_value="ssh-ed25519 AAAA"), \
                mock.patch.object(T.ssh, "run_command", return_value=(1, "x" * 30000, "")) as run:
            what, details = tool.words(ctx, args)
            out = tool.run(ctx, args)
            with self.assertRaises(T.ToolError):
                tool.run(ctx, dict(args, command="   "))
        self.assertEqual(details[0], "command -v cloudflared")  # as it will run
        self.assertIn("as root", what)
        run.assert_called_once_with(host.hostname, 2222, "root", "command -v cloudflared", timeout=60)
        self.assertEqual(out["exit_code"], 1)  # a command's own failure is an answer, not an error
        self.assertTrue(out["output_shortened"])
        self.assertIn("characters left out", out["stdout"])
        self.assertLess(len(out["stdout"]), T.HOST_OUTPUT_MAX + 100)
        with mock.patch.object(T.ssh, "trusted_host_key", return_value="k"), \
                mock.patch.object(T.ssh, "run_command", side_effect=T.ssh.SshError("The host did not answer.")):
            with self.assertRaises(T.ToolError):
                tool.run(ctx, args)
        # a host saved before this switch existed starts with it Off; it lends Claude's token nothing
        saved = {"claude": {"hosts": {"h": {"read": "on", "commands": "ask"}}}}
        self.assertEqual(claude_policy.host_switches(saved, "h")["host_commands"], "off")
        self.assertEqual(claude_policy.privileges({"host_commands": "on"}), [])

    def test_task_done_with_warnings_is_done(self):
        """Proxmox ends a task that did its job, with warnings, "WARNINGS: <n>" (the user's Windows VM, 17/10: it
        started, with a word about its firmware and its drivers): done — with what the warnings say — not a failure.
        A real failure is still one."""
        warn = ["EFI disk without 'ms-cert=2023k' option", "ide0: version 0.1.285 of the VirtIO drivers is known to"]
        self.cluster.warn_next = list(warn)
        out = self.run_tool("guest_power", host="demo-pve", vmid=200, action="start", reason="r")
        self.assertEqual(out["status"], "done")
        self.assertEqual(out["warnings"], [f"WARN: {w}" for w in warn])
        self.assertIn("warnings: 2", out["note"])
        self.assertEqual(self.status(200), "running")
        self.cluster.warn_next = ["something"]
        upid = self.pve.guest_action("pve", "qemu", 200, "shutdown")
        self.assertEqual(self.pve.wait_task("pve", upid)["exitstatus"], "WARNINGS: 1")  # no PveError
        bad = self.cluster.long_task("qmstart", 200, ["starting"])
        self.cluster.finish_task(bad, "start failed: QEMU exited with code 1")
        with self.assertRaises(PveError):
            self.pve.wait_task("pve", bad)
        with self.assertRaises(connector_tools.ToolError):
            connector_tools.finish(self.ctx(), "pve", bad)

    def test_container_root_password_typed_by_the_user(self):
        """A lost root password (the user's container 200, 17/10): a new one the user types in the app's window goes
        into the container with pct exec … chpasswd over the app's SSH key — on its input, never on a command line,
        and never back to Claude. Refused before any window for a VM, a stopped container, or no SSH."""
        import dataclasses
        T = connector_tools
        tool = T.TOOLS["set_container_root_password"]
        self.assertEqual((tool.kind, tool.secret_min, tool.repeat_secret({})), ("host_commands", 5, True))
        self.assertIn("container 100", tool.secret_prompt({"vmid": 100}))
        args = T.check(tool, {"host": "demo-pve", "vmid": 100, "reason": "r"})
        with self.assertRaises(T.ToolError) as caught:
            tool.words(self.ctx(), args)  # no SSH set up
        self.assertIn("Console → Connect by SSH", str(caught.exception))
        host = dataclasses.replace(DEMO_HOSTS[0], extra={"ssh": {"user": "root", "port": 22, "key": True}})
        ctx = T.Context(host=host, pve=self.pve, admin=self.pve)
        with mock.patch.object(T.ssh, "trusted_host_key", return_value="ssh-ed25519 AAAA"), \
                mock.patch.object(T.ssh, "run_command", return_value=(0, "", "")) as run:
            for vmid, says in ((200, "is a VM"), (102, "must be running")):  # a VM; a stopped container
                with self.assertRaises(T.ToolError) as caught:
                    tool.words(ctx, dict(args, vmid=vmid))
                self.assertIn(says, str(caught.exception))
            what, details = tool.words(ctx, args)
            ctx.secret = "n3w pa$$:wörd 'x"
            out = tool.run(ctx, args)
            ctx.secret = ""
            with self.assertRaises(T.ToolError):
                tool.run(ctx, args)  # no password: nothing run
        self.assertEqual(what, "Set the root password of Container 100 (pihole)")
        self.assertTrue(details[0].startswith("pct exec 100 -- chpasswd"))
        run.assert_called_once()
        (address, port, user, script), kw = run.call_args
        self.assertEqual((address, port, user, kw["input"]), (host.hostname, 22, "root", "root:n3w pa$$:wörd 'x\n"))
        self.assertTrue(script.endswith("pct exec 100 -- chpasswd"))
        self.assertNotIn("n3w", script)  # the password is not on the command line
        self.assertNotIn("n3w", json.dumps(out, ensure_ascii=False))  # nor in what Claude is told
        self.assertIn("PermitRootLogin", out["ssh"])
        with mock.patch.object(T.ssh, "trusted_host_key", return_value="k"), \
                mock.patch.object(T.ssh, "run_command",
                                  return_value=(1, "", "chpasswd: (user root) bad 'secret9' rejected\n")):
            ctx.secret = "secret9"
            with self.assertRaises(T.ToolError) as caught:
                tool.run(ctx, args)
        self.assertIn("not changed", str(caught.exception))
        self.assertNotIn("secret9", str(caught.exception))  # even if a program echoed it

    @unittest.skipUnless(os.name == "posix", "the line runs on the Proxmox host: a POSIX shell")
    def test_container_password_script_on_the_right_node_only(self):
        """The line run on the host, with a pretend pct and uname: on the container's node the password reaches
        chpasswd on its input; on another node of a cluster nothing runs, and the reason is said plainly."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        for name, body in (("uname", 'echo "$FAKE_NODE.example.lan"'),
                           ("pct", f'echo "$*" > {tmp}/args; cat > {tmp}/stdin')):
            with open(os.path.join(tmp, name), "w") as f:
                f.write(f"#!/bin/sh\n{body}\n")
            os.chmod(os.path.join(tmp, name), 0o700)
        script = connector_tools.chpasswd_script(100, "pve")

        def run(node):
            env = {**os.environ, "PATH": f"{tmp}:{os.environ['PATH']}", "FAKE_NODE": node}
            return subprocess.run(["sh", "-c", script], input="root:n3w pa$$\n", env=env, capture_output=True,
                                  text=True)

        done = run("pve")
        self.assertEqual(done.returncode, 0, done.stderr)
        with open(os.path.join(tmp, "args")) as f:
            self.assertEqual(f.read(), "exec 100 -- chpasswd\n")
        with open(os.path.join(tmp, "stdin")) as f:
            self.assertEqual(f.read(), "root:n3w pa$$\n")
        os.remove(os.path.join(tmp, "args"))
        done = run("pve2")
        self.assertEqual(done.returncode, 3)
        self.assertIn("Container 100 is on node pve, but the app's SSH reaches node pve2.", done.stderr)
        self.assertFalse(os.path.exists(os.path.join(tmp, "args")))  # pct never ran

    def test_switch_table_is_the_code_and_the_docs_follow_it(self):
        """Which switch opens what, for anyone who downloads the app (the user's wish, 17/10): made from the tools
        themselves — every tool under its switch — and docs/claude-access.md is that table, word for word."""
        table = connector_tools.access_table()
        self.assertEqual([r["key"] for r in table], list(claude_policy.KEYS))
        self.assertEqual({t["name"] for r in table for t in r["tools"]}, set(connector_tools.TOOLS))
        where = lambda name: [r["key"] for r in table if any(t["name"] == name for t in r["tools"])]  # noqa: E731
        self.assertEqual(where("restore_backup"), ["change", "destroy"])
        self.assertEqual(where("host_command"), ["host_commands"])
        self.assertEqual(where("set_container_root_password"), ["host_commands"])  # it goes over SSH, as root
        notes = {t["name"]: t["notes"] for r in table for t in r["tools"]}
        self.assertIn("starting it also needs Power not Off", notes["create_vm"])
        self.assertIn("asks you for a password", notes["console_type_password"])
        self.assertIn("asks you for a password", notes["set_container_root_password"])
        self.assertIn("This app only", table[-1]["enforced"])
        doc = Path(__file__).resolve().parent.parent / "docs" / "claude-access.md"
        self.assertEqual(doc.read_text(encoding="utf-8"), connector_tools.access_markdown(),
                         "docs/claude-access.md is behind the code: run tools/claude_access_doc.py")

    def test_delete_takes_its_backups_but_not_the_protected(self):
        c = self.cluster
        for hours, protected in ((3, False), (2, True), (1, False)):
            c.backups.append(c._backup_entry(c.guests[102], "local", time.time() - hours * 3600, "test-box", protected))
        _, lines = self.words("delete_guest", host="demo-pve", vmid=102, reason="r")
        self.assertIn("With all its disks and snapshots, for good.", lines)
        self.assertTrue(any(ln.startswith("And its 2 backup(s), ") for ln in lines))
        self.assertIn("Its 1 protected backup(s) stay.", lines)
        out = self.run_tool("delete_guest", host="demo-pve", vmid=102, reason="r")
        self.assertNotIn(102, c.guests)
        left = self.pve.backups("pve", 102)
        self.assertEqual((out["backups_deleted"], out["backups_kept_protected"]), (2, [left[0]["volid"]]))
        self.assertNotIn("backups_failed", out)
        self.assertEqual(len(self.pve.backups("pve", 101)), 2)  # another guest's stay

    def test_delete_can_keep_the_backups(self):
        c = self.cluster
        c.backups.append(c._backup_entry(c.guests[102], "local", time.time() - 3600, "test-box", False))
        _, lines = self.words("delete_guest", host="demo-pve", vmid=102, keep_backups=True, reason="r")
        self.assertIn("Its backups are kept.", lines)
        out = self.run_tool("delete_guest", host="demo-pve", vmid=102, keep_backups=True, reason="r")
        self.assertEqual((out["status"], out["backups"]), ("done", "kept, as asked"))
        self.assertEqual(len(self.pve.backups("pve", 102)), 1)
        self.assertEqual(len(self.run_tool("list_backups", host="demo-pve", vmid=102)), 1)  # the guest is gone
        self.assertEqual(self.run_tool("list_backups", host="demo-pve", vmid=999), [])
        _, lines = self.words("delete_guest", host="demo-pve", vmid=200, reason="r")
        self.assertIn("It has no backups.", lines)

    def test_a_deleted_guest_comes_back_from_its_backup(self):
        c = self.cluster
        c.backups.append(c._backup_entry(c.guests[200], "local", time.time() - 60, "windows-11", False))
        volid = c.backups[-1]["volid"]
        self.run_tool("delete_guest", host="demo-pve", vmid=200, keep_backups=True, reason="r")
        self.assertNotIn(200, c.guests)
        self.assertEqual(connector_tools.TOOLS["restore_backup"].kind_of({}), "change")
        what, lines = self.words("restore_backup", host="demo-pve", vmid=200, volid=volid, reason="r")[:2]
        self.assertEqual(what, "Bring back VM 200 (windows-11), deleted since, from its backup")
        self.assertIn("As 200, with its old network addresses", lines[1])
        with self.assertRaises(connector_tools.ToolError):  # nothing to restore over
            self.run_tool("restore_backup", host="demo-pve", vmid=200, volid=volid, replace=True, reason="r")
        with self.assertRaises(connector_tools.ToolError):  # another guest's backup under this ID
            self.run_tool("restore_backup", host="demo-pve", vmid=200, volid=self.pve.backups("pve", 101)[0]["volid"],
                          reason="r")
        out = self.run_tool("restore_backup", host="demo-pve", vmid=200, volid=volid, reason="r")
        self.assertEqual((out["vmid"], out["status"], out["network_addresses"]), (200, "done", "its old ones (MAC)"))
        self.assertEqual(c.guests[200]["name"], "windows-11")
        self.assertNotIn("unique", c.restored_with)  # old MAC addresses
        self.assertEqual(c.restored_with["vmid"], "200")
        # its old ID taken meanwhile: the next free one
        self.run_tool("delete_guest", host="demo-pve", vmid=200, keep_backups=True, reason="r")
        c.guests[200] = {**c.guests[201], "vmid": 200, "name": "someone-else", "status": "stopped"}
        out = self.run_tool("restore_backup", host="demo-pve", vmid=200, volid=volid, reason="r")
        self.assertNotEqual(out["vmid"], 200)
        self.assertEqual(c.guests[out["vmid"]]["name"], "windows-11")

    def test_destroying(self):
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("delete_guest", host="demo-pve", vmid=100, reason="r")  # running
        self.run_tool("delete_guest", host="demo-pve", vmid=102, reason="r")
        self.assertNotIn(102, self.cluster.guests)
        self.run_tool("rollback_snapshot", host="demo-pve", vmid=101, snapshot="before-upgrade", reason="r")
        self.run_tool("delete_snapshot", host="demo-pve", vmid=101, snapshot="before-upgrade", reason="r")
        self.assertEqual(self.pve.snapshots("pve", "lxc", 101), [])
        protected = next(b for b in self.pve.backups("pve", 101) if b["protected"])
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("delete_backup", host="demo-pve", volid=protected["volid"], reason="r")
        other = next(b for b in self.pve.backups("pve", 101) if not b["protected"])
        self.run_tool("delete_backup", host="demo-pve", volid=other["volid"], reason="r")
        self.assertEqual(len(self.pve.backups("pve", 101)), 1)
        upid = self.cluster.long_task("vzdump", 101, ["INFO: starting"])
        self.run_tool("stop_task", host="demo-pve", upid=upid, reason="r")
        self.assertEqual(self.cluster.tasks[upid], "interrupted by signal")
        self.assertEqual(self.run_tool("host_power", host="demo-pve", action="reboot", reason="r")["sent"], "reboot")

    def test_cloud_images_and_passwords(self):
        what, _ = self.words("get_cloud_image", host="demo-pve", release="26.04", reason="r")
        self.assertEqual(what, "Download Ubuntu 26.04 Server (cloud image, 865 MB) onto Home server (demo)")
        got = self.run_tool("get_cloud_image", host="demo-pve", release="26.04", reason="r")
        image = "local:import/ubuntu-26.04-server-cloudimg-amd64.qcow2"
        self.assertEqual(got["image"], image)
        self.assertEqual(self.run_tool("get_cloud_image", host="demo-pve", release="26.04", reason="r")["status"],
                         "already on the host")  # downloaded once
        self.assertIn(image, self.run_tool("list_install_media", host="demo-pve")["cloud_images"])
        tool = connector_tools.TOOLS["create_cloud_vm"]
        self.assertEqual(tool.secret_prompt({"name": "web", "username": "nikos"}),
                         "Password for the user 'nikos' in the new VM web")
        made = self.run_tool("create_cloud_vm", secret="my pass", host="demo-pve", name="web", image=image,
                             ssh_public_key="ssh-ed25519 AAAA me@pc", reason="r")
        vmid = made["vmid"]
        self.assertNotIn("my pass", json.dumps(made))  # never handed back to Claude
        self.assertEqual(self.cluster.secrets[vmid], "my pass")  # it reached Proxmox
        cfg = self.pve.guest_config("pve", "qemu", vmid)
        self.assertEqual((cfg["cipassword"], cfg["ciuser"], cfg["ide2"], cfg["ipconfig0"]),
                         ("**********", "user", "local-lvm:cloudinit", "ip=dhcp"))
        self.assertEqual(cfg["sshkeys"], "ssh-ed25519%20AAAA%20me%40pc")  # URL-encoded, as Proxmox wants
        self.assertIn(f"import-from={image}", cfg["scsi0"])
        self.assertEqual((self.cluster.guests[vmid]["disk_gb"], self.status(vmid)), (20, "running"))
        self.assertNotIn("tablet", cfg)  # the server edition: the default display, which keeps Proxmox's tablet
        desk = self.run_tool("create_cloud_vm", secret="x", host="demo-pve", name="desk", image=image,
                             edition="desktop", start=False, reason="r")
        dcfg = self.pve.guest_config("pve", "qemu", desk["vmid"])
        self.assertEqual((dcfg["vga"], dcfg["memory"], self.status(desk["vmid"])), ("qxl", 4096, "stopped"))
        self.assertEqual(str(dcfg["tablet"]), "1")  # SPICE would leave it out
        self.assertIn("installs Ubuntu Desktop", " ".join(desk["next_steps"]))  # by itself, from the setup disc
        self.assertNotIn("ciuser", dcfg)  # the app's own cloud-init disc instead of Proxmox's drive
        self.assertRegex(dcfg["ide2"], r"^local:iso/pvc-setup-\d+-[0-9a-f]{6}\.iso,media=cdrom$")
        for bad in ({"image": "local:import/nope.qcow2"}, {"image": image, "username": "Root!"}):
            with self.assertRaises(connector_tools.ToolError):
                self.run_tool("create_cloud_vm", secret="x", host="demo-pve", name="w2", reason="r", **bad)
        template = self.pve.templates("pve")[0]["volid"]
        ct = self.run_tool("create_container", secret="rootpw1", host="demo-pve", hostname="db", template=template,
                           reason="r")
        self.assertEqual(self.cluster.secrets[ct["vmid"]], "rootpw1")
        self.assertNotIn("rootpw1", json.dumps(ct))
        self.assertEqual(connector_tools.TOOLS["create_container"].secret_min, 5)  # Proxmox's own rule
        with self.assertRaises(PveError):
            self.run_tool("create_container", secret="abc", host="demo-pve", hostname="db2", template=template,
                          reason="r")

    def run_with(self, tool_name, /, secret="", kinds=None, **args):
        """run_tool, with the discs the app would keep (ctx.remember) and chosen switches not Off."""
        tool = connector_tools.TOOLS[tool_name]
        ctx = self.ctx()
        ctx.secret, kept = secret, []
        ctx.remember = kept.append
        if kinds is not None:
            ctx.kinds = frozenset(kinds)
        return tool.run(ctx, connector_tools.check(tool, args)), kept

    def test_windows_that_installs_itself(self):
        iso, virtio = "local:iso/Win11_25H2_Greek_x64.iso", "local:iso/virtio-win.iso"
        self.cluster.isos += [iso, virtio]
        args = dict(host="demo-pve", name="win-desk", iso=iso, profile="win11", virtio_iso=virtio,
                    windows_user="nikos", remote_desktop=True, dark_theme=True, start=True, reason="r")
        tool = connector_tools.TOOLS["create_vm"]
        self.assertEqual(tool.secret_prompt(args), "Password for the Windows user 'nikos' in the new VM win-desk")
        self.assertEqual(tool.secret_prompt({"name": "x"}), "")  # no Windows setup: no password asked
        self.assertEqual(tool.also_of(args), ("power", "console"))  # the start, and Enter at the installer's question
        what, lines = self.words("create_vm", **args)
        self.assertIn("Windows installs itself: Windows 11 Pro, el-GR, user 'nikos'", " ".join(lines))
        self.assertIn("Remote Desktop on, dark theme", " ".join(lines))
        watched = []
        with mock.patch.object(setupdisc, "answer_boot_prompt", lambda pve, node, vmid: watched.append(vmid)):
            out, kept = self.run_with("create_vm", secret="Win-Pass-77", **args)
            for t in [t for t in threading.enumerate() if t.name.startswith("boot-prompt-")]:
                t.join(5)
        vmid = out["vmid"]
        self.assertNotIn("Win-Pass-77", json.dumps(out))
        cfg = self.pve.guest_config("pve", "qemu", vmid)
        disc = cfg["ide3"].split(",")[0]
        self.assertTrue(setupdisc.is_setup_disc(disc))
        self.assertEqual(kept, [{**kept[0], "host": "demo-pve", "vmid": vmid, "volid": disc, "drive": "ide3",
                                 "agent": True}])
        _, files = read_iso(self.cluster.files[disc.split("/")[1]], joliet=True)
        xml = files["autounattend.xml"].decode()
        self.assertIn("<Name>nikos</Name>", xml)
        self.assertIn(winsetup.hidden("Win-Pass-77", "Password"), xml)
        self.assertIn("<UILanguage>el-GR</UILanguage>", xml)
        self.assertNotIn("Win-Pass-77", xml)
        self.assertEqual(self.status(vmid), "running")
        self.assertEqual(watched, [vmid])  # its screen watched (in the background) for the boot question
        self.assertIn("watches its screen", out["boot_key"])
        # Console Off: not watched, and said so
        with mock.patch.object(setupdisc, "answer_boot_prompt", lambda pve, node, vmid: watched.append(vmid)):
            out, _ = self.run_with("create_vm", secret="pw", kinds=("read", "change", "power"),
                                   **{**args, "name": "win-2"})
        self.assertIn("not pressed", out["boot_key"])
        self.assertEqual(len(watched), 1)
        out = self.run_tool("list_install_media", host="demo-pve")
        self.assertFalse([i for i in out["isos"] if "pvc-setup" in i])  # the answer disc is not one to install from
        for bad, words in (({"iso": virtio}, "VirtIO drivers disc"),
                           ({"profile": "linux"}, "only with the win11 or win10"),
                           ({"windows_user": None, "remote_desktop": True}, "give windows_user too"),
                           ({"edition": "Windows 11 Home"}, "Home"),
                           ({"windows_user": "Guest"}, "Windows' own")):
            a = {k: v for k, v in {**args, "name": "win-3", **bad}.items() if v is not None}
            with self.assertRaises(connector_tools.ToolError) as caught:
                self.run_with("create_vm", secret="pw", **a)
            self.assertIn(words, str(caught.exception))

    def test_desktop_with_remote_desktop(self):
        image = self.run_tool("get_cloud_image", host="demo-pve", release="24.04", reason="r")["image"]
        args = dict(host="demo-pve", name="desk", image=image, edition="desktop", remote_desktop=True,
                    username="nikos", start=False, reason="r")
        _, lines = self.words("create_cloud_vm", **args)
        self.assertIn("Remote Desktop (xrdp", " ".join(lines))
        out, kept = self.run_with("create_cloud_vm", secret="Lnx-Pass-9", **args)
        self.assertNotIn("Lnx-Pass-9", json.dumps(out))
        cfg = self.pve.guest_config("pve", "qemu", out["vmid"])
        disc = cfg["ide2"].split(",")[0]
        self.assertEqual((kept[0]["volid"], kept[0]["drive"], kept[0]["agent"]), (disc, "ide2", True))
        label, files = read_iso(self.cluster.files[disc.split("/")[1]], joliet=True)
        self.assertEqual(label, "cidata")
        data = json.loads(files["user-data"].decode().split("\n", 1)[1])
        self.assertIn("xrdp", data["packages"])
        self.assertEqual(data["password"], cloudseed.sha512_crypt("Lnx-Pass-9", data["password"].split("$")[2]))
        self.assertNotIn(out["vmid"], self.cluster.secrets)  # not through Proxmox's cloud-init this time
        self.assertIn("Remote Desktop: connect to its address, port 3389", " ".join(out["next_steps"]))
        with self.assertRaises(connector_tools.ToolError):
            self.run_with("create_cloud_vm", secret="x", **{**args, "name": "srv", "edition": "server"})

    def test_typing_a_password(self):
        what, lines, picture = self.words("console_type_password", host="demo-pve", vmid=201, reason="login")
        self.assertEqual(what, "Type a password into the console of VM 201 (ubuntu-desktop)")
        self.assertTrue(picture.startswith(b"\x89PNG"))  # the screen, for the user to see where it goes
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("console_type_password", host="demo-pve", vmid=201, reason="r")  # nothing typed by the user
        out = self.run_tool("console_type_password", secret="Ab1", host="demo-pve", vmid=201, reason="r")
        self.assertNotIn("Ab1", json.dumps(out))
        server = self.cluster.consoles[-1]
        self.assertTrue(wait_for(lambda: [k[2] for k in server.keys if k[1]][-1:] == [0xFF0D]))
        self.assertEqual([k[2] for k in server.keys if k[1]],
                         [0xFFE1, ord("A"), ord("b"), ord("1"), 0xFF0D])  # (presses) Shift+A, b, 1, then Enter
        tool = connector_tools.TOOLS["console_type_password"]
        self.assertEqual((tool.repeat_secret({}), tool.repeat_secret({"confirm": True})), (False, True))
        self.assertIn("both fields", tool.secret_prompt({"confirm": True}))
        _, lines, _ = self.words("console_type_password", host="demo-pve", vmid=201, confirm=True, reason="r")
        self.assertIn("presses Tab, and types it again", lines[0])
        out = self.run_tool("console_type_password", secret="x9", host="demo-pve", vmid=201, confirm=True,
                            enter=False, reason="r")
        self.assertIn("Tab, and again", out["typed"])
        server = self.cluster.consoles[-1]
        self.assertTrue(wait_for(lambda: len([k for k in server.keys if k[1]]) >= 5))
        self.assertEqual([k[2] for k in server.keys if k[1]], [ord("x"), ord("9"), 0xFF09, ord("x"), ord("9")])
        before = len(self.cluster.consoles)
        with self.assertRaises(connector_tools.ToolError) as caught:
            self.run_tool("console_type_password", secret="καλημέρα1", host="demo-pve", vmid=201, reason="r")
        self.assertNotIn("καλημέρα", str(caught.exception))  # the password is never repeated back
        self.assertEqual(len(self.cluster.consoles), before)  # nothing was typed: no console was even opened

    def test_password_and_a_click_on_its_confirmation(self):
        tool = connector_tools.TOOLS["console_type_password"]
        self.assertTrue(tool.repeat_secret({"confirm_at": [5, 6]}))
        self.assertIn("both fields", tool.secret_prompt({"confirm_at": [5, 6]}))
        _, lines, picture = self.words("console_type_password", host="demo-pve", vmid=201, confirm_at=[300, 200],
                                       enter=False, reason="r")
        self.assertIn("clicks the second field — the red mark", lines[0])
        self.assertTrue(picture.startswith(b"\x89PNG"))
        out = self.run_tool("console_type_password", secret="k7", host="demo-pve", vmid=201, confirm_at=[300, 200],
                            enter=False, reason="r")
        self.assertIn("a click on the second field", out["typed"])
        typed, clicked, again = self.cluster.consoles[-3:]  # three short visits: type, click, type
        self.assertTrue(wait_for(lambda: len([k for k in again.keys if k[1]]) >= 2))
        self.assertEqual([k[2] for k in typed.keys if k[1]], [ord("k"), ord("7")])
        self.assertIn((1, 300, 200), clicked.pointer)
        self.assertEqual([k[2] for k in again.keys if k[1]], [ord("k"), ord("7")])
        before = len(self.cluster.consoles)
        for bad in ([5000, 10], [1], [1, -1], ["1", 2]):
            with self.assertRaises(connector_tools.ToolError):  # refused before anything is typed
                self.words("console_type_password", host="demo-pve", vmid=201, confirm_at=bad, reason="r")
        self.assertEqual([c.keys for c in self.cluster.consoles[before:]], [[]] * (len(self.cluster.consoles) - before))
        with self.assertRaises(connector_tools.ToolError):
            self.words("console_type_password", host="demo-pve", vmid=201, confirm=True, confirm_at=[1, 1],
                       reason="r")

    def test_console_click(self):
        out = self.run_tool("console_click", host="demo-pve", vmid=201, x=5, y=6, reason="r")
        self.assertEqual((out["done"], out["at_screen_pixel"]), ("clicked", [5, 6]))
        server = self.cluster.consoles[-1]
        self.assertTrue(wait_for(lambda: len(server.pointer) >= 3))
        before = len(self.cluster.consoles)
        what, lines, picture = self.words("console_click", host="demo-pve", vmid=201, x=5, y=6, double=True,
                                          reason="r")
        self.assertEqual((what, picture), ("Double-click on the screen of VM 201 (ubuntu-desktop)", None))
        self.assertEqual(len(self.cluster.consoles), before)  # no window to show it: no picture taken
        tool = connector_tools.TOOLS["console_click"]
        ctx = self.ctx()
        ctx.showing = True
        what, lines, picture = tool.words(ctx, connector_tools.check(
            tool, {"host": "demo-pve", "vmid": 201, "x": 5, "y": 6, "scroll": 3, "reason": "r"}))
        self.assertEqual(what, "Scroll up 3 on the screen of VM 201 (ubuntu-desktop)")
        self.assertTrue(picture.startswith(b"\x89PNG"))
        self.assertIn("red mark", lines[0])
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("console_click", host="demo-pve", vmid=201, x=5000, y=6, reason="r")  # off the screen
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("console_click", host="demo-pve", vmid=102, x=5, y=6, reason="r")  # not running
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("console_click", host="demo-pve", vmid=201, x=5, y=6, button="thumb", reason="r")

    def test_clicks_need_an_absolute_pointer(self):
        """23/10, VM 103 (Windows 11, SPICE display): console_click said "clicked" and nothing happened — Proxmox
        leaves the USB tablet out with SPICE, Windows then has only the relative PS/2 mouse, and a click sent to a
        point lands wherever the pointer already is. Now: the tablet comes with every VM the app makes, edit_guest
        adds it to one that lacks it, and a click that cannot land is refused, saying why, before anything is done."""
        iso = self.pve.isos("pve")[0]["volid"]
        made = self.run_tool("create_vm", host="demo-pve", name="win", iso=iso, profile="win11", start=True,
                             reason="r")
        vmid = made["vmid"]
        cfg = self.pve.guest_config("pve", "qemu", vmid)
        self.assertEqual((cfg["vga"], str(cfg["tablet"])), ("qxl", "1"))  # SPICE, and the tablet said outright
        self.assertEqual(connector_tools.pointer_state(self.pve.monitor("pve", vmid, "info mice")),
                         ("absolute", "QEMU HID Tablet (absolute)"))
        self.assertEqual(self.run_tool("console_click", host="demo-pve", vmid=vmid, x=5, y=6, reason="r")["done"],
                         "clicked")
        self.assertNotIn("note", self.run_tool("console_click", host="demo-pve", vmid=vmid, x=5, y=6, reason="r"))

        self.cluster.guests[vmid]["cfg"].pop("tablet")  # as VM 103, made before: SPICE and no tablet
        before = len(self.cluster.consoles)
        for refused in (lambda: self.words("console_click", host="demo-pve", vmid=vmid, x=5, y=6, reason="r"),
                        lambda: self.run_tool("console_click", host="demo-pve", vmid=vmid, x=5, y=6, reason="r")):
            with self.assertRaises(connector_tools.ToolError) as caught:
                refused()
            for words in ("no absolute pointer", "QEMU PS/2 Mouse", "Nothing was clicked", '"tablet": true'):
                self.assertIn(words, str(caught.exception))
        for refused in (lambda: self.words("console_type_password", host="demo-pve", vmid=vmid, confirm_at=[9, 9],
                                           reason="r"),
                        lambda: self.run_tool("console_type_password", secret="k7", host="demo-pve", vmid=vmid,
                                              confirm_at=[9, 9], reason="r")):
            with self.assertRaises(connector_tools.ToolError) as caught:
                refused()
            self.assertIn("Nothing was typed", str(caught.exception))
        self.assertEqual(len(self.cluster.consoles), before)  # refused before a console was even opened
        self.run_tool("console_type_password", secret="k7", host="demo-pve", vmid=vmid, reason="r")  # keys: fine

        what, lines = self.words("edit_guest", host="demo-pve", vmid=vmid, changes={"tablet": True}, reason="r")
        self.assertIn("USB tablet: off → on", lines)
        self.assertTrue(any("plugged in at once where USB hotplug is on" in line for line in lines))
        out = self.run_tool("edit_guest", host="demo-pve", vmid=vmid, changes={"tablet": True}, reason="r")
        self.assertEqual((out["changed"], out["tablet"]), (["tablet"], "plugged in now"))
        self.assertEqual(self.run_tool("console_click", host="demo-pve", vmid=vmid, x=5, y=6, reason="r")["done"],
                         "clicked")
        self.assertEqual(self.run_tool("edit_guest", host="demo-pve", vmid=vmid, changes={"tablet": True},
                                       reason="r")["changed"], [])  # it has it: nothing to change

        self.pve.update_config("pve", "qemu", vmid, {"hotplug": "network,disk", "tablet": 0})  # no USB hotplug
        self.pve.guest_action("pve", "qemu", vmid, "reboot")
        out = self.run_tool("edit_guest", host="demo-pve", vmid=vmid, changes={"tablet": True}, reason="r")
        self.assertIn("waits for the VM's next start", out["tablet"])
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("console_click", host="demo-pve", vmid=vmid, x=5, y=6, reason="r")  # not in until then
        self.pve.guest_action("pve", "qemu", vmid, "reboot")
        self.assertEqual(self.run_tool("console_click", host="demo-pve", vmid=vmid, x=5, y=6, reason="r")["done"],
                         "clicked")

        self.assertNotIn("tablet", self.pve.guest_config("pve", "qemu", 201))  # Linux, SPICE, no tablet …
        self.assertEqual(connector_tools.pointer_state(self.pve.monitor("pve", 201, "info mice")),
                         ("absolute", "vmmouse (absolute)"))  # (as measured on Ubuntu VMs, 23/10)
        self.assertEqual(connector_tools.pointer_state("* Mouse #2: QEMU PS/2 Mouse"),
                         ("relative", "QEMU PS/2 Mouse"))  # VM 103's answer, word for word
        self.run_tool("console_click", host="demo-pve", vmid=201, x=5, y=6, reason="r")  # … QEMU's vmmouse: fine
        out = self.run_tool("console_click", host="demo-pve", vmid=100, x=5, y=6, reason="r")  # a container's console
        self.assertEqual((out["done"], "note" in out), ("clicked", False))  # (a terminal: no pointer to check)
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("edit_guest", host="demo-pve", vmid=100, changes={"tablet": True}, reason="r")  # container

        def no_monitor(*_a):
            raise PveError("Permission check failed (/vms/201, Sys.Audit)", 403)
        self.pve.monitor = no_monitor  # (an older Proxmox, or no right to read it): clicked, and said so
        out = self.run_tool("console_click", host="demo-pve", vmid=201, x=5, y=6, reason="r")
        self.assertEqual(out["done"], "clicked")
        self.assertIn("could not be checked (Permission check failed", out["note"])

    def test_file_tools(self):
        """Claude's Files: list a guest's folder, send the user's files into it, receive its files — each path shown
        whole in the approval window, nothing replaced unless asked, nothing done without an agent that answers."""
        made = []

        class FakeFiles:
            os_name = "linux"

            def __init__(self, pve, node, vmid, os_name, address):
                made.append(("open", vmid, os_name, address))

            def home(self):
                return "/home"

            def list(self, folder):
                return folder, [guestfiles.Entry("docs", True, 0, 0), guestfiles.Entry("a.txt", False, 3, 1700000000)]

            def send(self, paths, dest, progress, cancel):
                made.append(("send", [p.name for p in paths], dest))
                return "network"

            def receive(self, folder, names, dest, progress, cancel, total=None):
                progress(42, None, "proxmox")
                made.append(("receive", folder, names, str(dest)))
                return "proxmox"

        local = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, local, True)
        (local / "a.txt").write_text("abc")
        (local / "b.bin").write_bytes(b"x" * 2048)
        self.assertEqual({connector_tools.TOOLS[t].kind for t in ("list_guest_files", "send_files", "receive_files")},
                         {"files"})
        self.assertEqual((claude_policy.DEFAULTS["files"], claude_policy.PRIVILEGES["files"]),
                         ("off", ("VM.GuestAgent.Unrestricted",)))
        with mock.patch.object(connector_tools.guestfiles, "VmFiles", FakeFiles), \
                mock.patch.object(connector_tools.guestfiles, "address_towards", lambda host, port: "192.0.2.5"):
            out = self.run_tool("list_guest_files", host="demo-pve", vmid=201, reason="r")
            self.assertEqual((out["folder"], [e["name"] for e in out["entries"]]), ("/home", ["docs", "a.txt"]))
            self.assertEqual(out["entries"][1]["size"], 3)
            self.assertNotIn("size", out["entries"][0])
            self.assertEqual(made[0], ("open", 201, "linux", "192.0.2.5"))
            what, lines = self.words("send_files", host="demo-pve", vmid=201, paths=[str(local / "b.bin")],
                                     folder="/home/user", reason="r")
            self.assertEqual(what, "Copy 1 item from this computer into VM 201 (ubuntu-desktop)")
            self.assertEqual(lines, [str(local / "b.bin"), "Into: /home/user  (2.0 KiB)", "Nothing there is replaced."])
            with self.assertRaises(connector_tools.ToolError) as caught:
                self.run_tool("send_files", host="demo-pve", vmid=201, paths=[str(local / "a.txt")], folder="/home",
                              reason="r")
            self.assertIn("Already in /home: a.txt", str(caught.exception))
            out = self.run_tool("send_files", host="demo-pve", vmid=201, paths=[str(local / "a.txt")], folder="/home",
                                replace=True, reason="r")
            self.assertEqual((out["way"], made[-1]), ("network", ("send", ["a.txt"], "/home")))
            for bad in (["relative/a.txt"], [str(local / "nope")], []):
                with self.assertRaises(connector_tools.ToolError):
                    self.words("send_files", host="demo-pve", vmid=201, paths=bad, folder="/home", reason="r")
            with self.assertRaises(connector_tools.ToolError) as caught:  # refused before the user is asked
                self.words("receive_files", host="demo-pve", vmid=201, folder="/home", names=["a.txt"], to=str(local),
                           reason="r")
            self.assertIn("replace: true", str(caught.exception))
            what, lines = self.words("receive_files", host="demo-pve", vmid=201, folder="/home", names=["c.txt"],
                                     to=str(local), reason="r")
            self.assertEqual(lines, ["From: /home", "• c.txt", f"Into: {local}", "Nothing there is replaced."])
            out = self.run_tool("receive_files", host="demo-pve", vmid=201, folder="/home", names=["c.txt"],
                                to=str(local), reason="r")
            self.assertEqual((out["bytes"], out["way"], made[-1]), (42, "proxmox", ("receive", "/home", ["c.txt"],
                                                                                    str(local))))
            for names in (["../etc"], ["a/b"], [""]):
                with self.assertRaises(connector_tools.ToolError):
                    self.words("receive_files", host="demo-pve", vmid=201, folder="/home", names=names, to=str(local),
                               reason="r")
            with self.assertRaises(connector_tools.ToolError):
                self.words("receive_files", host="demo-pve", vmid=201, folder="/home", names=["x"], to="relative",
                           reason="r")
            self.cluster.guests[201]["agent_down"] = True
            with self.assertRaises(connector_tools.ToolError) as caught:
                self.run_tool("list_guest_files", host="demo-pve", vmid=201, reason="r")
            self.assertIn("Install Guest Agent", str(caught.exception))
            with self.assertRaises(connector_tools.ToolError) as caught:  # a container: over the host's SSH key
                self.run_tool("list_guest_files", host="demo-pve", vmid=100, reason="r")
            self.assertIn("SSH with this app's key is not set up", str(caught.exception))

    def test_console_and_commands(self):
        picture = self.run_tool("console_screenshot", host="demo-pve", vmid=201, reason="r")
        self.assertTrue(isinstance(picture, connector_tools.Image) and picture.png.startswith(b"\x89PNG"))
        self.assertIn("720×400", picture.text)
        self.assertEqual(self.run_tool("console_send", host="demo-pve", vmid=201, text="ls", keys=["enter"],
                                       reason="r")["keys_pressed"], 3)
        for vmid in (102, 200):  # stopped
            with self.assertRaises(connector_tools.ToolError):
                self.run_tool("console_screenshot", host="demo-pve", vmid=vmid, reason="r")
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("console_send", host="demo-pve", vmid=201, keys=["warp"], reason="r")
        out = self.run_tool("run_command", host="demo-pve", vmid=201, command=["uname", "-a"], reason="r")
        self.assertEqual(out["exit_code"], 0)
        self.assertIn("ubuntu-desktop", out["stdout"])
        self.assertEqual(self.run_tool("run_command", host="demo-pve", vmid=201, command=["cat"], input="hello",
                                       reason="r")["stdout"], "hello")
        self.assertEqual(self.run_tool("run_command", host="demo-pve", vmid=201, command=["false"],
                                       reason="r")["exit_code"], 1)
        with self.assertRaises(connector_tools.ToolError):
            self.run_tool("run_command", host="demo-pve", vmid=100, command=["ls"], reason="r")  # a container


class FakeRegistry:
    """Enough of winreg for autostart: keys of HKEY_CURRENT_USER as dicts of values."""
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ = "HKCU", 2, 1

    class Key:
        def __init__(self, values):
            self.values = values

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def __init__(self):
        self.keys: dict[str, dict] = {}

    def OpenKey(self, root, path, reserved=0, access=0):
        if path not in self.keys:
            raise FileNotFoundError(path)
        return self.Key(self.keys[path])

    def CreateKey(self, root, path):
        return self.Key(self.keys.setdefault(path, {}))

    def QueryValueEx(self, key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], self.REG_SZ

    def SetValueEx(self, key, name, reserved, kind, value):
        key.values[name] = value

    def DeleteValue(self, key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        del key.values[name]


class WindowsAutostartTest(unittest.TestCase):
    """Windows: a value under HKCU\\…\\Run, what Settings → Apps → Startup lists — and Windows' own switch there
    (StartupApproved) is part of the answer."""

    def test_run_value_and_windows_own_switch(self):
        fake = FakeRegistry()
        off, on = b"\x03" + bytes(11), b"\x02" + bytes(11)
        with mock.patch.multiple(autostart, WINDOWS=True, registry=fake):
            self.assertFalse(autostart.is_enabled())
            autostart.set_enabled(True)
            self.assertTrue(autostart.is_enabled())
            command = fake.keys[autostart.RUN_KEY]["Proxmox Controller"]
            self.assertTrue(command.endswith(f' -I "{autostart.ROOT / "bin" / "launch.py"}"'))  # the source tree
            fake.keys.setdefault(autostart.APPROVED_KEY, {})["Proxmox Controller"] = off  # off in Windows' list
            self.assertFalse(autostart.is_enabled())
            fake.keys[autostart.APPROVED_KEY]["Proxmox Controller"] = on
            self.assertTrue(autostart.is_enabled())
            fake.keys[autostart.APPROVED_KEY]["Proxmox Controller"] = off
            autostart.set_enabled(True)  # turned on here: on there too
            self.assertNotIn("Proxmox Controller", fake.keys[autostart.APPROVED_KEY])
            self.assertTrue(autostart.is_enabled())
            autostart.set_enabled(False)
            self.assertFalse(autostart.is_enabled())
            self.assertNotIn("Proxmox Controller", fake.keys[autostart.RUN_KEY])
            autostart.set_enabled(False)  # nothing left to remove: no error
            exe = "C:\\Program Files\\Proxmox Controller\\Proxmox Controller.exe"
            with mock.patch.object(autostart.sys, "frozen", True, create=True), \
                    mock.patch.object(autostart.sys, "executable", exe):
                autostart.set_enabled(True)
            self.assertEqual(fake.keys[autostart.RUN_KEY]["Proxmox Controller"], f'"{exe}"')  # the installed app

    @unittest.skipUnless(autostart.WINDOWS, "the real registry")
    def test_real_registry(self):
        import winreg
        name = "Proxmox Controller test " + os.urandom(4).hex()  # never the real entry
        with mock.patch.object(autostart, "VALUE", name):
            try:
                autostart.set_enabled(True)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, autostart.RUN_KEY) as key:
                    self.assertEqual(winreg.QueryValueEx(key, name)[0], autostart.windows_command())
                self.assertTrue(autostart.is_enabled())
            finally:
                autostart.set_enabled(False)
            self.assertFalse(autostart.is_enabled())


class WindowsPackagingTest(unittest.TestCase):
    """packaging/windows: the build's own helpers, and its names agreeing with the code that uses them."""

    def setUp(self):
        import importlib.util
        here = Path(__file__).resolve().parent.parent / "packaging" / "windows"
        spec = importlib.util.spec_from_file_location("windows_build", here / "build.py")
        self.build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.build)
        self.iss_bytes = (here / "installer.iss").read_bytes()
        self.iss = self.iss_bytes.decode("utf-8-sig")
        self.spec = (here / "proxmox-controller.spec").read_text(encoding="utf-8")

    def test_icon_file(self):
        data = self.build.ico_bytes([(16, b"P16"), (256, b"P256xx")])
        self.assertEqual(struct.unpack("<HHH", data[:6]), (0, 1, 2))  # an icon file of two images
        first, second = (struct.unpack("<BBBBHHII", data[6 + 16 * i:22 + 16 * i]) for i in range(2))
        self.assertEqual((first[0], first[6], first[7]), (16, 3, 38))  # 16×16, its PNG's length and place
        self.assertEqual((second[0], second[6], second[7]), (0, 6, 41))  # 0 stands for 256
        self.assertEqual(data[38:41] + data[41:], b"P16P256xx")

    def test_version_resource(self):
        self.assertEqual(self.build.version_tuple("0.1.0"), (0, 1, 0, 0))
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = Path(tmp) / "v.txt"
        self.build.version_file(path)
        text = path.read_text(encoding="utf-8")
        self.assertIn("StringStruct('ProductName', 'Proxmox Controller')", text)
        self.assertIn(f"StringStruct('ProductVersion', '{self.build.VERSION}')", text)
        compile(text, "version_info.txt", "eval")  # PyInstaller reads it as a Python expression

    def test_names_agree(self):
        from proxmox_controller import APP_ID, APP_NAME
        from proxmox_controller.core import claude_connect
        self.assertIn(f'#define BridgeExe "{claude_connect.MCP_EXE}"', self.iss)  # what Claude is told to start
        self.assertIn(f'name="{claude_connect.MCP_EXE[:-4]}", console=True', self.spec)  # what PyInstaller makes
        self.assertIn(f'#define AppExe "{APP_NAME}.exe"', self.iss)
        self.assertIn(f'name="{APP_NAME}", console=False', self.spec)
        self.assertIn(f'#define AppIdName "{APP_ID}"', self.iss)  # the shortcut's ID is the app's own
        self.assertIn('AppUserModelID: "{#AppIdName}"', self.iss)
        self.assertIn("AppId={{CD154B40-5EEA-477B-B826-A0F95650C4E8}", self.iss)  # never changes: upgrades replace

    def test_signature_in_the_wizard(self):
        self.assertIn("BeveledLabel=HOME LAB · by the mechanic", self.iss)  # the user's signature, on every page
        self.assertTrue(self.iss_bytes.startswith(b"\xef\xbb\xbf"))  # UTF-8 with a BOM, or Inno reads the · wrong


class UninstallTest(unittest.TestCase):
    """What the Windows uninstaller has the app tidy before its files go."""

    def test_tidies_what_points_at_the_program(self):
        from proxmox_controller.core import claude_connect, uninstall
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        config, data = os.path.join(home, "config"), os.path.join(home, "data")
        env = {"XDG_CONFIG_HOME": config, "APPDATA": config, "XDG_DATA_HOME": data, "LOCALAPPDATA": data,
               "CLAUDE_CONFIG_DIR": home}
        code = Path(home) / ".claude.json"
        code.write_text(json.dumps({"mcpServers": {"proxmox-controller": {"command": "x"}}, "keep": 1}))
        removed = []

        def claude(args):  # Claude Code's own `claude mcp remove`, which edits its file
            removed.append(args[1:])
            code.write_text(json.dumps({"mcpServers": {}, "keep": 1}))
            return ""

        with mock.patch.dict(os.environ, env), mock.patch.multiple(autostart, WINDOWS=True, registry=FakeRegistry()), \
                mock.patch.object(claude_connect, "claude_cli", lambda: "claude"), \
                mock.patch.object(claude_connect, "_run", claude):
            store.save_settings(dict(store.SETTINGS_DEFAULTS))
            autostart.set_enabled(True)
            claude_connect.connect_desktop()
            desktop = claude_connect.desktop_config()
            desktop.write_text(json.dumps({**json.loads(desktop.read_text()), "preferences": {"keep": True}}))
            self.assertEqual(uninstall.cleanup(), ["start with the computer", "Claude Desktop's connector",
                                                   "Claude Code's connector"])
            self.assertFalse(autostart.is_enabled() or claude_connect.desktop_connected())
            self.assertEqual(removed, [["mcp", "remove", "--scope", "user", "proxmox-controller"]])
            self.assertEqual(json.loads(desktop.read_text())["preferences"], {"keep": True})  # the rest stays
            self.assertTrue(store.config_dir().exists())  # the hosts and settings are the user's: kept
            self.assertEqual(uninstall.cleanup(), [])  # nothing left to tidy
            self.assertEqual(uninstall.cleanup(remove_data=True), ["hosts, token secrets and settings"])
            self.assertFalse(store.config_dir().exists())


@unittest.skipIf(autostart.WINDOWS, "Linux: ~/.config/autostart")
class AutostartTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()  # never the real ~/.config/autostart
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name, "APPDATA": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_entry_on_and_off(self):
        path = autostart.entry_path()
        self.assertEqual(path, Path(self.tmp.name) / "autostart" / "store.themechanic.ProxmoxController.desktop")
        self.assertFalse(autostart.is_enabled())
        autostart.set_enabled(True)
        self.assertTrue(autostart.is_enabled())
        text = path.read_text()
        launcher = autostart.ROOT / "bin" / "proxmox-controller"
        self.assertIn(f'Exec="{launcher}"\n', text)  # quoted: the folder's name has a space
        self.assertTrue(os.access(launcher, os.X_OK))
        self.assertFalse(path.with_suffix(".tmp").exists())
        validator = shutil.which("desktop-file-validate")
        if validator:
            done = subprocess.run([validator, str(path)], capture_output=True, text=True)
            self.assertEqual((done.returncode, done.stdout.strip()), (0, ""))
        path.write_text(text + "Hidden=true\n")  # turned off in GNOME's Startup Applications
        self.assertFalse(autostart.is_enabled())
        autostart.set_enabled(False)
        autostart.set_enabled(False)  # already gone: no error
        self.assertFalse(path.exists())


class ConsoleProtocolTest(unittest.TestCase):
    def test_des_and_vnc_password(self):
        self.assertEqual(encrypt_block(bytes.fromhex("133457799BBCDFF1"), bytes.fromhex("0123456789ABCDEF")).hex(),
                         "85e813540f0ab405")  # the FIPS 46 example
        # checked against OpenSSL: des-ecb with the bit-reversed key of "secret12"
        self.assertEqual(vnc_response("secret12", bytes(range(16))).hex(), "adcd997f8e16fee575e973f93c2b62b4")

    def pair(self, server_password, client_password, ext_keys=True):
        a, b = socket.socketpair()
        srv = FakeVncServer(WebSocket(b, client=False), server_password, 64, 48, "t", ext_keys=ext_keys).start()
        client = RfbClient(WebSocket(a), client_password)
        self.addCleanup(client.ws.close)  # also when an assertion fails half-way
        return client, srv

    @staticmethod
    def wait_keys(srv, n):
        end = time.monotonic() + 5
        while len(srv.keys) < n and time.monotonic() < end:
            time.sleep(0.02)

    def test_session(self):
        client, srv = self.pair("pw123456", "pw123456")
        self.assertEqual(client.handshake(), (64, 48, "t"))
        first = client.next_update()
        self.assertEqual([op[0] for op in first], ["raw", "raw", "cursor"])
        self.assertEqual(len(first[0][5]), 64 * 48 * 4)
        self.assertEqual(set(first[0][5][3::4]), {255})  # the server sent 0 there, like QEMU: made opaque
        cursor = [op for op in first if op[0] == "cursor"]
        self.assertEqual(cursor[0][1:5], (0, 0, 8, 8))  # the guest's pointer: hot spot, size
        argb = cursor[0][5]
        self.assertEqual((argb[3], argb[7], argb[8 * 4 + 3], argb[8 * 4 + 7]), (255, 0, 255, 255))  # mask → alpha
        self.assertEqual(argb[4:8], b"\0\0\0\0")  # outside the mask: fully transparent
        client.pointer(1, 10, 20)
        client.ctrl_alt_del()  # changes nothing on the pretend screen: wait for the keys to arrive instead
        self.wait_keys(srv, 6)
        self.assertEqual(srv.pointer, [(1, 10, 20)])
        self.assertEqual([k[3] for k in srv.keys], [0x1D, 0x38, 0xD3, 0xD3, 0x38, 0x1D])
        self.assertEqual([k[1] for k in srv.keys], [True, True, True, False, False, False])

    def test_wrong_password_and_key_symbols(self):
        client, _ = self.pair("pw123456", "nope")
        with self.assertRaises(RfbError):
            client.handshake()
        client, srv = self.pair("pw123456", "pw123456", ext_keys=False)
        client.handshake()
        client.next_update()
        client.key(True, 0x41, 0x1E)  # no physical codes offered: the symbol goes
        client.key(False, 0x41, 0x1E)
        self.wait_keys(srv, 2)  # the screen changes on the press; the release follows a moment later
        self.assertEqual(srv.keys[:2], [("sym", True, 0x41), ("sym", False, 0x41)])

    def test_key_codes(self):
        self.assertEqual([qnum_from_evdev(c) for c in (1, 30, 88, 103, 111, 125, 200)], [1, 30, 88, 0xC8, 0xD3, 0xDB, 0])
        self.assertEqual([qnum_from_windows(c) for c in (0x1E, 0x148, 0xE053)], [0x1E, 0xC8, 0xD3])


class BackupJobWordsTest(unittest.TestCase):
    def test_schedules(self):
        for text, preset, words in (("03:00", "daily", "Every day at 03:00"),
                                    ("mon..fri 21:30", "weekdays", "Monday to Friday at 21:30"),
                                    ("sat,sun 02:00", "weekend", "Saturday and Sunday at 02:00"),
                                    ("sun 4:05", "weekly", "Sundays at 04:05"),
                                    ("mon,wed,fri 22:00", "custom", "mon,wed,fri 22:00")):
            self.assertEqual(jobs.parse_schedule(text)["preset"], preset, text)
            self.assertEqual(jobs.describe_schedule(text), words)
        self.assertEqual(jobs.schedule_value("weekly", 4, 5, "sun"), "sun 04:05")
        self.assertEqual(jobs.schedule_value("custom", 0, 0, custom=" */6:00 "), "*/6:00")

    def test_keep_and_guests(self):
        self.assertEqual(jobs.parse_keep("keep-daily=7,keep-weekly=4"), {"keep-daily": 7, "keep-weekly": 4})
        self.assertEqual(jobs.parse_keep({"keep-last": "3"}), {"keep-last": 3})
        self.assertEqual(jobs.keep_value({"keep-monthly": 6, "keep-last": 2, "keep-daily": 0}),
                         "keep-last=2,keep-monthly=6")
        self.assertEqual(jobs.describe_keep("keep-daily=7,keep-weekly=4"), "7 daily, 4 weekly")
        self.assertEqual(jobs.describe_keep(""), "storage's rule")
        listed, everyone = {"vmid": "100,101"}, {"all": 1, "exclude": "102"}
        self.assertEqual([jobs.covers(listed, v) for v in (100, 102)], [True, False])
        self.assertEqual([jobs.covers(everyone, v) for v in (100, 102)], [True, False])
        names = {100: "pihole", 101: "nextcloud", 102: "test-box"}
        self.assertEqual(jobs.describe_guests(listed, names), "pihole, nextcloud")
        self.assertEqual(jobs.describe_guests(everyone, names), "All except test-box")


class TaskWordsTest(unittest.TestCase):
    GUESTS = {113: {"vmid": 113, "type": "qemu", "name": "TestVm"}, 100: {"vmid": 100, "type": "lxc", "name": "pihole"}}

    def test_what_a_task_did(self):
        self.assertEqual(tasks.describe({"type": "qmstart", "id": "113"}, self.GUESTS), "VM 113 (TestVm) — Start")
        self.assertEqual(tasks.describe({"type": "vzshutdown", "id": "100"}, self.GUESTS),
                         "Container 100 (pihole) — Shut down")
        self.assertEqual(tasks.describe({"type": "qmdestroy", "id": "120"}, self.GUESTS), "VM 120 — Destroy")  # gone
        self.assertEqual(tasks.describe({"type": "vzdump", "id": "120"}, self.GUESTS), "Guest 120 — Backup")
        self.assertEqual(tasks.describe({"type": "startall", "id": ""}, self.GUESTS), "Bulk start")
        self.assertEqual(tasks.describe({"type": "newkind", "id": ""}, self.GUESTS), "newkind")

    def test_state_and_times(self):
        now = time.mktime((2026, 10, 14, 12, 0, 0, 0, 0, -1))
        ended = {"starttime": int(now) - 380, "endtime": int(now) - 0, "status": "OK"}
        self.assertEqual((tasks.running(ended), tasks.ok(ended), tasks.outcome(ended)), (False, True, "OK"))
        self.assertEqual(tasks.took(ended, now), "6 min 20 s")
        self.assertEqual(tasks.started(ended, now), "11:53:40")  # today: the time alone
        running = {"starttime": int(now) - 3725, "status": "RUNNING"}  # as Proxmox lists one that has not ended
        self.assertEqual((tasks.running(running), tasks.outcome(running)), (True, "Running"))
        self.assertEqual(tasks.took(running, now), "1 h 02 min")
        failed = {"starttime": int(now) - 86400 * 2, "endtime": int(now) - 86400 * 2 + 4,
                  "status": "command 'apt-get update' failed: exit code 100"}
        self.assertFalse(tasks.ok(failed))
        self.assertEqual(tasks.outcome(failed), failed["status"])
        self.assertEqual((tasks.failed(failed), tasks.warned(failed)), (True, False))
        warned = dict(ended, status="WARNINGS: 2")  # done, with warnings: Proxmox's own words for it
        self.assertEqual((tasks.ok(warned), tasks.warned(warned), tasks.failed(warned)), (False, True, False))
        self.assertEqual((tasks.failed(ended), tasks.failed(running), tasks.warned(running)), (False, False, False))
        self.assertEqual([tasks.done(s) for s in ("OK", "WARNINGS: 2", "WARNINGS: 12", "WARNINGS:", "", "TASK ERROR",
                                                  "unexpected status")], [True, True, True, False, False, False, False])
        self.assertEqual(tasks.started(failed, now), "Oct 12 12:00")  # another day: English month, whatever the locale


class StartupOrderTest(unittest.TestCase):
    def test_reading_and_writing(self):
        self.assertEqual(startup.parse("order=2,up=30,down=120"), {"order": 2, "up": 30, "down": 120})
        self.assertEqual(startup.parse("3"), {"order": 3, "up": None, "down": None})  # the short form
        self.assertEqual(startup.parse(""), {"order": None, "up": None, "down": None})
        self.assertEqual(startup.value(2, 30, 0), "order=2,up=30")
        self.assertEqual(startup.value(0, 0, 0), "")
        self.assertEqual(startup.describe("order=2,up=30"), "order 2, then waits 30 s")

    def test_changes(self):
        cfg = {"startup": "up=30,order=2"}
        self.assertEqual(startup.change(cfg, 2, 30, 0), {})  # same, written differently: nothing to send
        self.assertEqual(startup.change(cfg, 1, 30, 0), {"startup": "order=1,up=30"})
        self.assertEqual(startup.change(cfg, 0, 0, 0), {"delete": "startup"})
        self.assertEqual(startup.change({}, 0, 0, 0), {})


class VmHardwareTest(unittest.TestCase):
    cfg = {"usb0": "host=0781:5581,usb3=1", "usb1": "spice", "usb3": "host=046d:c52b", "vga": "qxl,memory=32",
           "audio0": "device=AC97,driver=none", "name": "x"}

    def test_reading(self):
        self.assertEqual(vmhw.display_of(self.cfg), "qxl")
        self.assertEqual(vmhw.display_of({}), "std")
        self.assertEqual(vmhw.sound_of(self.cfg), ("AC97", "none"))
        self.assertIsNone(vmhw.sound_of({}))
        self.assertEqual(vmhw.usb_slots(self.cfg), {0: "host=0781:5581,usb3=1", 1: "spice", 3: "host=046d:c52b"})
        self.assertEqual([vmhw.usb_host(v) for v in ("host=0781:5581,usb3=1", "spice", "host=1-2")],
                         ["0781:5581", "spice", "1-2"])

    def test_usb_changes_keep_slots(self):
        wanted = vmhw.wanted_usb(["0781:5581"], 2, {"0781:5581"})  # keep SanDisk, two SPICE ports, drop Logitech
        self.assertEqual(vmhw.usb_changes(self.cfg, wanted), {"usb2": "spice", "delete": "usb3"})
        self.assertEqual(vmhw.usb_changes(self.cfg, []), {"delete": "usb0,usb1,usb3"})
        self.assertEqual(vmhw.usb_changes({}, ["host=046d:c52b"]), {"usb0": "host=046d:c52b"})
        self.assertEqual(vmhw.usb_changes(self.cfg, ["host=0781:5581,usb3=1", "spice", "host=046d:c52b"]), {})
        with self.assertRaises(ValueError):
            vmhw.usb_changes({}, ["spice"] * 6, limit=5)

    def test_devices_and_merging(self):
        hub = {"class": 9, "vendid": "05e3", "prodid": "0610"}
        root = {"class": 0, "vendid": "1d6b", "prodid": "0003"}
        stick = {"class": 0, "vendid": "0781", "prodid": "5581", "manufacturer": "SanDisk", "product": "Ultra",
                 "speed": "5000"}
        self.assertEqual([vmhw.is_hub(d) for d in (hub, root, stick)], [True, True, False])
        self.assertEqual(vmhw.usb_label(stick), "SanDisk Ultra  (0781:5581)")
        self.assertTrue(vmhw.is_fast(stick))
        self.assertFalse(vmhw.is_fast({"speed": "480"}))
        self.assertEqual(vmhw.merge({"delete": "description", "name": "a"}, {"usb5": "spice", "delete": "usb3"}),
                         {"name": "a", "usb5": "spice", "delete": "description,usb3"})


class GuestConfigTest(unittest.TestCase):
    def test_macs_from_vm_and_container_configs(self):
        vm = {"net0": "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1", "net1": "e1000=bc:24:11:00:00:01,bridge=vmbr1",
              "name": "box", "scsi0": "local-lvm:vm-106-disk-0,size=100G"}
        self.assertEqual(guest_macs(vm), ["bc:24:11:aa:bb:cc", "bc:24:11:00:00:01"])
        ct = {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:12:34:56,ip=dhcp,type=veth"}
        self.assertEqual(guest_macs(ct), ["bc:24:11:12:34:56"])
        self.assertEqual(guest_macs({"net0": "name=eth0,bridge=vmbr0,ip=dhcp"}), [])

    def test_agent_switch(self):
        for value, on in (("1", True), ("0", False), ("enabled=1,fstrim_cloned_disks=1", True),
                          ("0,fstrim_cloned_disks=1", False), (1, True)):
            self.assertIs(agent_enabled({"agent": value}), on, value)
        self.assertFalse(agent_enabled({}))


class NetinfoTest(unittest.TestCase):
    def test_ips_for_macs_in_every_table_format(self):
        tables = {
            "ip neigh": ["192.168.1.106 dev enp5s0 lladdr bc:24:11:aa:bb:cc STALE",
                         "fe80::1 dev enp5s0 lladdr bc:24:11:aa:bb:cc router REACHABLE",
                         "192.168.1.9 dev enp5s0 FAILED"],
            "arp -an": ["?  192.168.1.106  at bc:24:11:aa:bb:cc [ether] on enp5s0"],
            "/proc/net/arp": ["192.168.1.106    0x1         0x2         bc:24:11:aa:bb:cc     *        enp5s0"],
            "windows": ["  192.168.1.106         bc-24-11-aa-bb-cc     dynamic"],
        }
        for name, lines in tables.items():
            self.assertEqual(netinfo.ips_for_macs(["BC:24:11:AA:BB:CC"], lines), ["192.168.1.106"], name)
        self.assertEqual(netinfo.ips_for_macs(["bc:24:11:00:00:00"], tables["ip neigh"]), [])
        self.assertEqual(netinfo.ips_for_macs([], tables["ip neigh"]), [])

    def test_linux_and_windows_tables(self):
        linux = ["192.168.1.80 dev enp5s0 lladdr 3c:ec:ef:6e:a7:96 REACHABLE",
                 "192.168.1.8 dev enp5s0 lladdr aa:bb:cc:dd:ee:ff STALE"]
        windows = ["  192.168.1.80          3c-ec-ef-6e-a7-96     dynamic"]
        for lines in (linux, windows):
            with mock.patch.object(netinfo, "_neighbour_lines", return_value=lines), \
                    mock.patch.object(netinfo, "resolve", return_value="192.168.1.80"):
                self.assertEqual(netinfo.mac_for("pve"), "3c:ec:ef:6e:a7:96")
        with mock.patch.object(netinfo, "_neighbour_lines", return_value=linux), \
                mock.patch.object(netinfo, "resolve", return_value="192.168.1.99"):
            self.assertIsNone(netinfo.mac_for("other"))


if __name__ == "__main__":
    unittest.main()


class SshTest(unittest.TestCase):
    """The host's shell and upgrade over ssh: the app's own key and known hosts, the key added and removed through
    Proxmox's link, the password given once to ssh — all here without a network or a window."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        config = os.path.join(self.tmp, "config")
        patch = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config, "APPDATA": config})  # (Windows: APPDATA)
        patch.start()
        self.addCleanup(patch.stop)

    def test_key_and_fingerprint(self):
        line = sshmod.ensure_key()
        self.assertTrue(line.startswith("ssh-ed25519 ") and "proxmox-controller@" in line)
        if os.name == "posix":  # (Windows: ssh-keygen gives the file to the user, Administrators and SYSTEM alone)
            self.assertEqual(stat.S_IMODE(os.stat(sshmod.key_path()).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(sshmod.ssh_dir()).st_mode), 0o700)
        self.assertEqual(sshmod.ensure_key(), line)  # made once
        shown = subprocess.run(["ssh-keygen", "-lf", str(sshmod.key_path()) + ".pub"], capture_output=True,
                               text=True).stdout.split()[1]
        self.assertEqual(sshmod.fingerprint(line), shown)  # as ssh-keygen and ssh show it

    def test_known_hosts(self):
        self.assertEqual(sshmod.trusted_host_key("192.0.2.80"), "")
        sshmod.trust_host_key("192.0.2.80", 22, "ssh-ed25519 AAAAone")
        sshmod.trust_host_key("192.0.2.80", 2222, "ssh-ed25519 AAAAtwo")
        sshmod.trust_host_key("192.0.2.80", 22, "ssh-ed25519 AAAAnew")  # replaces the first
        self.assertEqual(sshmod.trusted_host_key("192.0.2.80"), "ssh-ed25519 AAAAnew")
        self.assertEqual(sshmod.trusted_host_key("192.0.2.80", 2222), "ssh-ed25519 AAAAtwo")
        self.assertEqual(sshmod.known_hosts_path().read_text().count("192.0.2.80 "), 1)

    def test_scan_prefers_ed25519(self):
        out = ("# 192.0.2.80:22 SSH-2.0-OpenSSH_10.0\n192.0.2.80 ssh-rsa AAAArsa\n"
               "192.0.2.80 ssh-ed25519 AAAAed\n192.0.2.80 ecdsa-sha2-nistp256 AAAAec\n")
        with mock.patch.object(sshmod.subprocess, "run", return_value=mock.Mock(stdout=out, stderr="")):
            self.assertEqual(sshmod.scan_host_key("192.0.2.80"), "ssh-ed25519 AAAAed")
        with mock.patch.object(sshmod.subprocess, "run", return_value=mock.Mock(stdout="", stderr="timeout")):
            with self.assertRaises(sshmod.SshError):
                sshmod.scan_host_key("192.0.2.81")

    def test_ssh_command(self):
        argv = sshmod.ssh_argv("192.0.2.80", 22, "root", True, ["pveupgrade", "--shell"])
        self.assertEqual(argv[:2], ["ssh", "-t"])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn(f'UserKnownHostsFile="{sshmod.known_hosts_path()}"', argv)  # its own, never ~/.ssh
        self.assertEqual(argv[argv.index("-i") + 1], str(sshmod.key_path()))
        self.assertEqual(argv[-3:], ["root@192.0.2.80", "pveupgrade", "--shell"])
        bare = sshmod.ssh_argv("192.0.2.80", 2222, "root", False)
        self.assertNotIn("-i", bare)  # no key: ssh asks for the password in the terminal
        self.assertEqual(bare[bare.index("-p") + 1], "2222")

    @unittest.skipUnless(os.name == "posix", "a POSIX shell script")
    def test_key_added_and_removed_through_proxmox_link(self):
        home, priv = os.path.join(self.tmp, "root"), os.path.join(self.tmp, "etc-pve-priv")
        os.makedirs(os.path.join(home, ".ssh"))
        os.makedirs(priv)
        target = os.path.join(priv, "authorized_keys")
        with open(target, "w") as f:
            f.write("ssh-rsa AAAAclusternode root@pve\n")
        link = os.path.join(home, ".ssh", "authorized_keys")
        os.symlink(target, link)  # as Proxmox has it
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOurKeyBody proxmox-controller@box"

        def run(script):
            subprocess.run(["sh", "-c", script], env={**os.environ, "HOME": home}, check=True)

        run(sshmod.install_key_script(line))
        run(sshmod.install_key_script(line))  # twice: still once
        with open(target) as f:
            self.assertEqual(f.read().splitlines(), ["ssh-rsa AAAAclusternode root@pve", line])
        self.assertTrue(os.path.islink(link))
        run(sshmod.remove_key_script(line))
        self.assertTrue(os.path.islink(link))  # still the link: not replaced by a plain file
        with open(target) as f:
            self.assertEqual(f.read().splitlines(), ["ssh-rsa AAAAclusternode root@pve"])  # the cluster's key stays
        os.remove(link)
        run(sshmod.remove_key_script(line))  # nothing there: nothing done

    @unittest.skipUnless(os.name == "posix", "a POSIX shell script")
    def test_command_with_the_key_any_exit_code(self):
        """host_command's way in: the command's own exit code and output come back as they are; only ssh itself
        failing (it exits 255) raises, and a command that runs too long is cut off here."""
        path = os.path.join(self.tmp, "fake-ssh-cmd")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n"
                    "for last; do :; done\n"  # (the last argument: the command line)
                    'case "$last" in\n'
                    '  fail) echo "not found" >&2; exit 1;;\n'
                    '  down) echo "ssh: connect to host 192.0.2.80 port 22: Connection refused" >&2; exit 255;;\n'
                    "  slow) sleep 5;;\n"
                    '  *) echo "args: $*";;\n'
                    "esac\n")
        os.chmod(path, 0o700)
        code, out, err = sshmod.run_command("192.0.2.80", 2222, "root", "systemctl is-active cloudflared", ssh=path)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("BatchMode=yes", out)  # never a password prompt
        self.assertIn(f"-i {sshmod.key_path()} -o IdentitiesOnly=yes", out)  # the app's key, alone
        self.assertIn("-p 2222", out)
        self.assertTrue(out.strip().endswith("root@192.0.2.80 systemctl is-active cloudflared"))
        self.assertEqual(sshmod.run_command("192.0.2.80", 22, "root", "fail", ssh=path), (1, "", "not found\n"))
        with self.assertRaises(sshmod.SshError) as caught:
            sshmod.run_command("192.0.2.80", 22, "root", "down", ssh=path)
        self.assertIn("Connection refused", str(caught.exception))
        with self.assertRaises(sshmod.SshError) as caught:
            sshmod.run_command("192.0.2.80", 22, "root", "slow", ssh=path, timeout=1)
        self.assertIn("did not finish within 1 s", str(caught.exception))

    @unittest.skipUnless(os.name == "posix", "a POSIX shell script")
    def test_command_input_goes_to_its_standard_input(self):
        """A password for a command (a container's new root password) goes on ssh's standard input — not among its
        arguments, where ps would show it; without input, standard input is empty (no ssh waiting on the terminal)."""
        path = os.path.join(self.tmp, "fake-ssh-stdin")
        with open(path, "w") as f:
            f.write('#!/bin/sh\nprintf "args: %s\\n" "$*"; printf "in: "; cat\n')
        os.chmod(path, 0o700)
        code, out, _ = sshmod.run_command("192.0.2.80", 22, "root", "pct exec 100 -- chpasswd", ssh=path,
                                          input="root:n3w pa$$\n")
        self.assertEqual(code, 0)
        args, given = out.split("\nin: ")
        self.assertEqual(given, "root:n3w pa$$\n")
        self.assertNotIn("n3w", args)
        self.assertTrue(sshmod.run_command("192.0.2.80", 22, "root", "true", ssh=path)[1].endswith("in: "))

    def fake_ssh(self, expected_password):
        """An 'ssh' that asks SSH_ASKPASS for the password, as the real one does, and says what it was given. (The
        expected one comes through the environment: written into the script, the shell would expand its '$'.)"""
        path = os.path.join(self.tmp, "fake-ssh")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n"
                    'got=$("$SSH_ASKPASS")\n'
                    'if [ "$got" != "$FAKE_EXPECTED" ]; then echo "Permission denied (password)." >&2; exit 255; fi\n'
                    'echo "args: $*"\n')
        os.chmod(path, 0o700)
        patch = mock.patch.dict(os.environ, {"FAKE_EXPECTED": expected_password})
        patch.start()
        self.addCleanup(patch.stop)
        return path

    @unittest.skipUnless(os.name == "posix", "a POSIX shell script")
    def test_password_given_once_to_ssh(self):
        fake = self.fake_ssh("s3cr$t 'x")
        out = sshmod.run_with_password("192.0.2.80", 22, "root", "s3cr$t 'x", "echo hi", ssh=fake)
        self.assertIn("PubkeyAuthentication=no", out)  # only the password is tried: one failed login at most
        self.assertIn("NumberOfPasswordPrompts=1", out)
        self.assertTrue(out.strip().endswith("root@192.0.2.80 echo hi"))
        self.assertNotIn("s3cr", sshmod._askpass_helper().read_text())  # never written down
        with self.assertRaises(sshmod.SshError) as caught:
            sshmod.run_with_password("192.0.2.80", 22, "root", "wrong", "true", ssh=fake)
        self.assertIn("did not accept the password", str(caught.exception))

    @unittest.skipUnless(os.name == "posix", "a POSIX shell script")
    def test_terminal(self):
        inner = ["ssh", "-t", "root@192.0.2.80"]
        argv = sshmod.terminal_argv(inner, "Proxmox Console — Home", which=lambda p: p == "ptyxis")
        self.assertEqual(argv[:6], ["ptyxis", "-T", "Proxmox Console — Home", "--", "sh", "-c"])  # not «sh» on top
        self.assertEqual(argv[-4:], ["Proxmox Console — Home", *inner])
        self.assertIn(sshmod.CLOSE_PROMPT, argv[6])  # what ssh said stays on the screen
        konsole = sshmod.terminal_argv(inner, "T", which=lambda p: p == "konsole")
        self.assertEqual(konsole[:2], ["konsole", "-e"])  # no title option: the escape sequence titles it
        # the wrapper itself, run here without a window: the title first, then the command, then the wait for Enter
        out = subprocess.run(argv[argv.index("--") + 1:-3] + ["echo", "connected"], input=b"\n",
                             capture_output=True).stdout
        self.assertTrue(out.startswith("\x1b]0;Proxmox Console — Home\x07connected\n".encode()))
        with self.assertRaises(sshmod.SshError):
            sshmod.terminal_argv(inner, which=lambda p: None)


class WindowsSshTest(unittest.TestCase):
    """Windows: cmd.exe runs the .cmd files the app writes (ssh's askpass, the console window) — each argument quoted
    for it — and Windows' OpenSSH runs askpass.cmd for the password (measured with 9.5p2)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        config = os.path.join(self.tmp, "config")
        patch = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config, "APPDATA": config})
        patch.start()
        self.addCleanup(patch.stop)

    def test_cmd_line(self):
        self.assertEqual(sshmod.cmd_line(["ssh", "-o", 'UserKnownHostsFile="C:\\Users\\Jo Doe\\kh"', "a&b", "50%",
                                          "C:\\dir\\"]),
                         '"ssh" "-o" "UserKnownHostsFile=\\"C:\\Users\\Jo Doe\\kh\\"" "a&b" "50%%" "C:\\dir\\\\"')

    def test_console_script_and_window(self):
        script = sshmod.windows_console_script(["ssh", "-t", "root@192.0.2.80"], "Proxmox Console — Σπίτι & co")
        self.assertEqual(script.splitlines(), ["@echo off", "chcp 65001 >nul", "title Proxmox Console — Σπίτι   co",
                                               '"ssh" "-t" "root@192.0.2.80"', "echo.",
                                               f'set /p "_={sshmod.CLOSE_PROMPT}"'])
        self.assertTrue(script.endswith("\r\n"))
        with mock.patch.object(sshmod, "WINDOWS", True), \
                mock.patch.object(sshmod.subprocess, "CREATE_NEW_CONSOLE", 16, create=True), \
                mock.patch.object(sshmod.subprocess, "Popen") as popen:
            sshmod.open_terminal(["ssh", "-t", "root@192.0.2.80"], "Proxmox Console — Home")
        path = sshmod.ssh_dir() / "console.cmd"
        self.assertEqual(popen.call_args.args[0], ["cmd.exe", "/c", str(path)])
        self.assertEqual(popen.call_args.kwargs["creationflags"], 16)  # a console window of its own
        self.assertEqual(path.read_bytes().decode("utf-8"),  # (the bytes: \r\n once, never \r\r\n)
                         sshmod.windows_console_script(["ssh", "-t", "root@192.0.2.80"], "Proxmox Console — Home"))

    def test_askpass_cmd(self):
        from proxmox_controller.core import claude_connect
        with mock.patch.object(sshmod, "WINDOWS", True):
            path = sshmod._askpass_helper()
        self.assertEqual(path.name, "askpass.cmd")
        text = path.read_bytes().decode("utf-8")
        self.assertEqual(text, "@" + sshmod.cmd_line([*claude_connect.bridge_command(), "--askpass"]) + "\r\n")
        self.assertEqual(sshmod.askpass_answer({"PROXMOX_CONTROLLER_SSH_SECRET": "s3cr$t & ^%"}), "s3cr$t & ^%\n")

    def test_console_programs_get_no_window(self):
        """Started from an app that has windows only, a console program gets a console window of its own on Windows:
        ssh, ssh-keyscan, ssh-keygen, arp and claude are all asked to start without one."""
        from proxmox_controller.core import claude_connect, netinfo, procs
        flags = []

        def run(argv, **kw):
            flags.append((os.path.basename(argv[0]), kw.get("creationflags")))
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(procs, "WINDOWS", True), \
                mock.patch.object(procs.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True), \
                mock.patch.object(subprocess, "run", run):
            sshmod.run_command("192.0.2.80", 22, "root", "true")
            sshmod.run_with_key("192.0.2.80", 22, "root", "true")
            sshmod.run_with_password("192.0.2.80", 22, "root", "pw", "true")
            with self.assertRaises(sshmod.SshError):
                sshmod.scan_host_key("192.0.2.80")  # (nothing found: said so)
            with self.assertRaises(sshmod.SshError):
                sshmod.ensure_key()  # (no key file made by the pretend ssh-keygen)
            netinfo._neighbour_lines()
            claude_connect._run(["claude", "mcp", "list"])
        names = {name for name, _ in flags}
        self.assertLessEqual({"ssh", "ssh-keyscan", "ssh-keygen", "claude"}, names)
        self.assertTrue(names & {"arp", "ip"})  # (the neighbour table: arp on Windows, ip first on Linux)
        self.assertTrue(all(f == 0x08000000 for _, f in flags), flags)
        with mock.patch.object(procs, "WINDOWS", False):
            self.assertEqual(procs.hidden(), {})  # nothing on Linux

    @unittest.skipUnless(os.name == "nt", "Windows' cmd.exe")
    def test_password_through_askpass_cmd(self):
        """A pretend ssh that asks SSH_ASKPASS for the password as Windows' OpenSSH does — through askpass.cmd and the
        app's own --askpass — with every character cmd would read as its own."""
        fake_py = os.path.join(self.tmp, "fake_ssh.py")
        with open(fake_py, "w", encoding="utf-8") as fh:
            fh.write("import os, subprocess, sys\n"
                     "got = subprocess.run([os.environ['SSH_ASKPASS'], \"user@h's password: \"], capture_output=True,"
                     " text=True).stdout.rstrip('\\r\\n')\n"
                     "if got != os.environ['FAKE_EXPECTED']:\n"
                     "    sys.stderr.write('Permission denied (password).\\n'); sys.exit(255)\n"
                     "print('args: ' + ' '.join(sys.argv[1:]))\n")
        fake = os.path.join(self.tmp, "ssh.cmd")
        with open(fake, "w") as fh:
            fh.write(f'@"{sys.executable}" -I "{fake_py}" %*\r\n')
        password = "s3cr$t 'x & ^% \"q\" | <>"
        with mock.patch.dict(os.environ, {"FAKE_EXPECTED": password}):
            out = sshmod.run_with_password("192.0.2.80", 22, "root", password, "echo hi", ssh=fake, timeout=60)
            self.assertIn("PubkeyAuthentication=no", out)
            self.assertTrue(out.strip().endswith("root@192.0.2.80 echo hi"))
            with self.assertRaises(sshmod.SshError) as caught:
                sshmod.run_with_password("192.0.2.80", 22, "root", "wrong", "true", ssh=fake, timeout=60)
        self.assertIn("did not accept the password", str(caught.exception))
        self.assertNotIn("s3cr", (sshmod.ssh_dir() / "askpass.cmd").read_text(encoding="utf-8"))  # never written


class AptTest(unittest.TestCase):
    """The host's package sources: what refused a check, and the switch to the free No-Subscription repositories."""

    REAL_LOG = [  # the user's host, 15/10/2026 (Proxmox VE 9.1.1, no subscription)
        "starting apt-get update", "Hit:1 http://deb.debian.org/debian trixie InRelease",
        "Get:5 https://pkgs.tailscale.com/stable/debian trixie InRelease",
        "Err:8 https://enterprise.proxmox.com/debian/ceph-squid trixie InRelease",
        "  401  Unauthorized [IP: 45.144.208.36 443]",
        "Err:9 https://enterprise.proxmox.com/debian/pve trixie InRelease",
        "  401  Unauthorized [IP: 45.144.208.36 443]", "Reading package lists...",
        "E: Failed to fetch https://enterprise.proxmox.com/debian/pve/dists/trixie/InRelease  401  Unauthorized",
        "TASK ERROR: command 'apt-get update' failed: exit code 100"]

    def test_what_refused(self):
        got = apt.refused(self.REAL_LOG)
        self.assertEqual([(f["host"], f["reason"]) for f in got], [("enterprise.proxmox.com", "401 Unauthorized")] * 2)
        self.assertTrue(apt.only_enterprise(got))
        self.assertEqual(apt.explain(got), "enterprise.proxmox.com (401 Unauthorized — it needs a Proxmox subscription)")
        other = apt.refused(["Err:3 http://deb.example.org/debian trixie InRelease", "  Could not resolve 'deb.example.org'"])
        self.assertFalse(apt.only_enterprise(other))
        self.assertEqual(apt.explain(other), "deb.example.org (Could not resolve 'deb.example.org')")
        self.assertEqual(apt.refused(["Hit:1 http://deb.debian.org/debian trixie InRelease"]), [])

    def test_switch_to_no_subscription(self):
        DemoPve._clusters.clear()
        pve = DemoPve(DEMO_HOSTS[0])
        info = pve.apt_repositories("pve")
        self.assertEqual(apt.describe(info), ["Proxmox: Enterprise on", "Ceph: Enterprise on"])
        self.assertEqual([s[:2] for s in apt.plan_no_subscription(info)],
                         [("add", "no-subscription"), ("disable", "/etc/apt/sources.list.d/pve-enterprise.sources"),
                          ("add", "ceph-squid-no-subscription"), ("disable", "/etc/apt/sources.list.d/ceph.sources")])
        self.assertEqual(len(pve.apt_updates("pve")), 1)  # Proxmox's own updates never show
        done = apt.switch_to_no_subscription(pve, "pve")
        self.assertEqual(len(done), 4)
        after = pve.apt_repositories("pve")
        self.assertEqual(apt.describe(after), ["Proxmox: Enterprise off, No-Subscription on",
                                               "Ceph: Enterprise off, No-Subscription on"])
        # Ceph's free one went first in its file: the enterprise one moved to index 1, and that is the one switched off
        ceph = next(f for f in after["files"] if f["path"].endswith("ceph.sources"))["repositories"]
        self.assertEqual([(r["URIs"][0].split("/")[2], r["Enabled"]) for r in ceph],
                         [("download.proxmox.com", 1), ("enterprise.proxmox.com", 0)])
        self.assertEqual(apt.plan_no_subscription(after), [])  # done: nothing more to change
        self.assertEqual(apt.switch_to_no_subscription(pve, "pve"), [])
        self.assertEqual(len(pve.apt_updates("pve")), 3)
        pve.wait_task("pve", pve.apt_refresh("pve"), timeout=5)  # the check now passes

    def test_never_leaves_a_product_without_a_source(self):
        info = {"files": [{"path": "/etc/apt/sources.list.d/ceph.sources", "repositories": [
                    {"URIs": ["https://enterprise.proxmox.com/debian/ceph-squid"], "Enabled": 1}]}],
                "standard-repos": [{"handle": "ceph-squid-enterprise", "status": 1}]}  # no free one offered
        self.assertEqual(apt.plan_no_subscription(info), [])


class SoundsTest(unittest.TestCase):
    """The sound when Claude asks: plain tones made here, played by the system — never by these tests."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patch = mock.patch.object(store, "data_dir", lambda: self.tmp)
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_sounds(self):
        import wave
        for name, seconds in (("double-beep", 0.31), ("beep", 0.22), ("bell", 1.6)):
            w = wave.open(io.BytesIO(sounds.wav_bytes(name)))
            self.assertEqual((w.getnchannels(), w.getsampwidth(), w.getframerate()), (1, 2, 44100))
            self.assertAlmostEqual(w.getnframes() / 44100, seconds, places=2)
            frames = struct.unpack(f"<{w.getnframes()}h", w.readframes(w.getnframes()))
            self.assertLessEqual(max(abs(f) for f in frames), 16384)  # half the scale: firm, not harsh
            self.assertGreater(max(abs(f) for f in frames), 16000)
            self.assertLess(max(abs(f) for f in frames[:10] + frames[-10:]), 2500)  # soft start and end: no click
        self.assertEqual([n for n, _ in sounds.SOUNDS], ["double-beep", "beep", "bell"])
        with self.assertRaises(ValueError):
            sounds.samples("siren")

    def test_written_once_and_played_by_the_system(self):
        found = {"aplay", "paplay"}
        self.assertEqual(sounds.player(lambda c: c in found), ["paplay"])  # in this order: PipeWire, Pulse, ALSA
        self.assertEqual(sounds.player(lambda c: c == "aplay"), ["aplay", "-q"])
        self.assertIsNone(sounds.player(lambda c: False))
        started = []

        class Proc:
            def __init__(self, cmd, **kw):
                started.append((cmd, kw))

            def wait(self):
                return 0
        with mock.patch.object(sounds.sys, "platform", "linux"), \
                mock.patch.object(sounds, "player", lambda: ["pw-play"]), \
                mock.patch.object(sounds.subprocess, "Popen", Proc):
            self.assertTrue(sounds.play("bell"))
        path = self.tmp / "sounds" / "bell.wav"
        self.assertEqual(started[0][0], ["pw-play", str(path)])
        self.assertEqual(started[0][1]["stdout"], subprocess.DEVNULL)
        self.assertEqual(path.read_bytes(), sounds.wav_bytes("bell"))
        path.write_bytes(b"kept")  # written once: not again on each play
        self.assertEqual(sounds.path_of("bell").read_bytes(), b"kept")
        with mock.patch.object(sounds.sys, "platform", "linux"), mock.patch.object(sounds, "player", lambda: None), \
                mock.patch.object(sounds.subprocess, "Popen", Proc):
            self.assertFalse(sounds.play("beep"))  # nothing here can play it: said, not hidden
        self.assertEqual(len(started), 1)

    def test_windows_plays_it_with_winsound(self):
        played = []
        fake = type(sys)("winsound")
        fake.SND_FILENAME, fake.SND_ASYNC, fake.SND_NODEFAULT = 0x20000, 0x1, 0x2
        fake.PlaySound = lambda path, flags: played.append((path, flags))
        with mock.patch.object(sounds.sys, "platform", "win32"), mock.patch.dict(sys.modules, {"winsound": fake}):
            self.assertTrue(sounds.play("double-beep"))
        self.assertEqual(played, [(str(self.tmp / "sounds" / "double-beep.wav"), 0x20003)])  # without waiting

    def test_the_choice(self):
        self.assertIsNone(sounds.chosen({}))
        self.assertIsNone(sounds.chosen({"claude": {"sound": "bell"}}))  # off unless the box is ticked
        self.assertEqual(sounds.chosen({"claude": {"sound_on": True}}), "double-beep")
        self.assertEqual(sounds.chosen({"claude": {"sound_on": True, "sound": "bell"}}), "bell")
        self.assertEqual(sounds.chosen({"claude": {"sound_on": True, "sound": "siren"}}), "double-beep")


class LocalAgent:
    """Stands in for Proxmox's guest-agent calls: the guest's commands run on this computer (for the Linux side —
    sh, tar, curl, base64 — on temporary folders), its file calls on the local disk. `unreachable`: the guest cannot
    reach this computer (its curl goes to a closed port)."""

    def __init__(self, unreachable=False):
        import itertools
        self.procs, self.ids, self.unreachable, self.started = {}, itertools.count(100), unreachable, []

    def agent_exec(self, node, vmid, argv, input_data=""):
        if self.unreachable:
            argv = ["http://127.0.0.1:9/x" if a.startswith("http://") else a for a in argv]
        self.started.append(argv)
        pid = next(self.ids)
        self.procs[pid] = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return pid

    def agent_exec_status(self, node, vmid, pid):
        p = self.procs[pid]
        if p.poll() is None:
            return {"exited": 0}
        out, err = p.communicate()
        return {"exited": 1, "exitcode": p.returncode, "out-data": out, "err-data": err}

    def agent_file_write(self, node, vmid, path, content_b64):
        Path(path).write_bytes(base64.b64decode(content_b64))

    def agent_file_read(self, node, vmid, path, offset=0, count=16 << 20):
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(count)


@unittest.skipIf(sys.platform.startswith("win") or not all(shutil.which(c) for c in ("sh", "tar", "curl", "base64")),
                 "the Linux guest's side runs here")
class GuestFilesLinuxTest(unittest.TestCase):
    """Files to and from a Linux VM, its side run for real: over the network (this computer's channel, the guest's
    curl) and through Proxmox (the agent's file calls) — names in Greek, folders whole, contents byte for byte."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.pc, self.vm = self.root / "pc", self.root / "vm"
        (self.pc / "φάκελος" / "μέσα").mkdir(parents=True)
        (self.pc / "φάκελος" / "μέσα" / "σημειώσεις.txt").write_text("γεια σου κόσμε\n", encoding="utf-8")
        (self.pc / "setup.bin").write_bytes(os.urandom(2 * 1024 * 1024 + 7))
        self.vm.mkdir()
        (self.vm / "υπάρχον.md").write_text("ήδη εδώ", encoding="utf-8")
        self.progress = []

    def files(self, unreachable=False):
        self.agent = LocalAgent(unreachable)
        return guestfiles.VmFiles(self.agent, "pve", 112, "linux", "127.0.0.1")

    def note(self, done, total, how):
        self.progress.append((done, total, how))

    def test_round_trip_both_ways(self):
        for unreachable, way in ((False, "network"), (True, "proxmox")):
            for p in list(self.vm.iterdir()):
                if p.name != "υπάρχον.md":
                    shutil.rmtree(p) if p.is_dir() else p.unlink()
            files = self.files(unreachable)
            self.progress.clear()
            self.assertEqual(files.send([self.pc / "φάκελος", self.pc / "setup.bin"], str(self.vm), self.note,
                                        threading.Event()), way)
            self.assertEqual((self.vm / "φάκελος" / "μέσα" / "σημειώσεις.txt").read_text(encoding="utf-8"),
                             "γεια σου κόσμε\n")
            self.assertEqual((self.vm / "setup.bin").read_bytes(), (self.pc / "setup.bin").read_bytes())
            self.assertEqual({h for _d, _t, h in self.progress}, {way})
            self.assertEqual(self.progress[-1][0], self.progress[-1][1] if way == "proxmox" else self.progress[-1][0])
            folder, entries = files.list(str(self.vm))
            self.assertEqual(folder, str(self.vm))
            self.assertEqual([(e.name, e.is_dir) for e in entries],
                             [("φάκελος", True), ("setup.bin", False), ("υπάρχον.md", False)])  # folders first
            self.assertEqual(entries[1].size, 2 * 1024 * 1024 + 7)
            back = self.root / f"back-{way}"
            back.mkdir()
            self.assertEqual(files.receive(str(self.vm), ["φάκελος", "setup.bin", "υπάρχον.md"], back, self.note,
                                           threading.Event()), way)
            self.assertEqual((back / "setup.bin").read_bytes(), (self.pc / "setup.bin").read_bytes())
            self.assertEqual((back / "υπάρχον.md").read_text(encoding="utf-8"), "ήδη εδώ")
            self.assertTrue((back / "φάκελος" / "μέσα" / "σημειώσεις.txt").exists())
        self.assertEqual([p for p in os.listdir("/tmp") if p.startswith("pcx-")], [])  # Proxmox's way cleans up
        for argv in self.agent.started:  # the agent is never given anything but ASCII (it stalls on other text)
            self.assertTrue(all(ord(c) < 128 for a in argv for c in a), argv)

    def test_falls_back_at_once_when_the_guest_cannot_reach_this_computer(self):
        t0 = time.monotonic()
        self.assertEqual(self.files(True).send([self.pc / "setup.bin"], str(self.vm), self.note, threading.Event()),
                         "proxmox")
        self.assertLess(time.monotonic() - t0, guestfiles.CONNECT_WAIT_S)  # as soon as curl gave up

    def test_a_folder_that_is_not_there(self):
        files = self.files()
        with self.assertRaises(guestfiles.GuestError):
            files.list(str(self.root / "nope"))
        with self.assertRaises(guestfiles.GuestError):
            files.send([self.pc / "setup.bin"], str(self.root / "nope"), self.note, threading.Event())

    def test_cancel(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(guestfiles.Cancelled):
            self.files(True).send([self.pc / "setup.bin"], str(self.vm), self.note, cancel)
        self.assertEqual([p for p in os.listdir("/tmp") if p.startswith("pcx-")], [])

    def test_container_over_a_pipe(self):
        ct = guestfiles.ContainerFiles("pve", 22, "root", 105)
        ct._argv = lambda inner: inner  # (what `pct exec` would run inside, run here)
        self.assertEqual(ct.send([self.pc / "φάκελος"], str(self.vm), self.note, threading.Event()), "ssh")
        self.assertTrue((self.vm / "φάκελος" / "μέσα" / "σημειώσεις.txt").exists())
        self.assertEqual([e.name for e in ct.list(str(self.vm))[1]], ["φάκελος", "υπάρχον.md"])
        back = self.root / "back"
        back.mkdir()
        self.assertEqual(ct.receive(str(self.vm), ["φάκελος"], back, self.note, threading.Event()), "ssh")
        self.assertEqual((back / "φάκελος" / "μέσα" / "σημειώσεις.txt").read_text(encoding="utf-8"),
                         "γεια σου κόσμε\n")
        argv = guestfiles.ContainerFiles("pve", 2222, "root", 105)._argv(["sh", "-c", "it's"])
        self.assertEqual(argv[-1], "pct exec 105 -- 'sh' '-c' 'it'\\''s'")  # one line for the host's shell
        self.assertIn("BatchMode=yes", argv)


class GuestFilesTest(unittest.TestCase):
    def test_paths_and_listing(self):
        self.assertEqual(guestfiles.os_of({"ostype": "win11"}), "windows")
        self.assertEqual(guestfiles.os_of({"ostype": "l26"}), "linux")
        self.assertEqual(guestfiles.join("windows", "C:\\Users", "user"), "C:\\Users\\user")
        self.assertEqual(guestfiles.parent("windows", "C:\\Users\\user"), "C:\\Users")
        self.assertEqual(guestfiles.parent("windows", "C:\\"), "")  # above a drive: the drives
        self.assertEqual(guestfiles.parent("linux", "/home/user/"), "/home")
        self.assertEqual(guestfiles.parent("linux", "/"), "/")
        b = guestfiles.b64
        out = "PWD " + b("C:\\Users\\user") + "\r\n" + f"F 12 1700000000 {b('σημειώσεις.txt')}\r\n" + \
              f"D 0 1700000000 {b('Desktop')}\r\n"
        folder, entries = guestfiles.parse_listing(out, "windows")
        self.assertEqual(folder, "C:\\Users\\user")
        self.assertEqual([(e.name, e.is_dir, e.size) for e in entries], [("Desktop", True, 0),
                                                                        ("σημειώσεις.txt", False, 12)])
        drives = guestfiles.parse_listing("PWD \r\n" + f"D 0 0 {b('C:' + chr(92))}\r\n", "windows")
        self.assertEqual((drives[0], [e.name for e in drives[1]]), ("", ["C:\\"]))
        with self.assertRaises(guestfiles.GuestError):
            guestfiles.parse_listing("ERR No such folder\n", "linux")

    def test_scripts_stay_ascii_and_are_filled(self):
        for name in ("LINUX_LIST", "LINUX_SEND_NET", "LINUX_RECV_NET", "LINUX_JOIN", "LINUX_PACK", "WINDOWS_LIST",
                     "WINDOWS_SEND_NET", "WINDOWS_RECV_NET", "WINDOWS_JOIN", "WINDOWS_PACK"):
            self.assertTrue(all(ord(c) < 128 for c in getattr(guestfiles, name)), name)
        sent = []
        agent = mock.Mock()
        agent.agent_exec.side_effect = lambda node, vmid, argv, input_data="": sent.append(argv) or 7
        agent.agent_exec_status.return_value = {"exited": 1, "exitcode": 0,
                                                "out-data": "PWD " + guestfiles.b64("C:\\Χρήστης") + "\n"}
        win = guestfiles.VmFiles(agent, "pve", 103, "windows", "192.0.2.5")
        self.assertEqual(win.list("C:\\Χρήστης")[0], "C:\\Χρήστης")
        script = sent[-1][-1]
        self.assertEqual(sent[-1][:2], ["powershell", "-NoProfile"])
        self.assertIn(guestfiles.b64("C:\\Χρήστης"), script)  # the folder only as base64
        self.assertNotIn("{path}", script)
        self.assertTrue(all(ord(c) < 128 for c in script))

    def test_channel(self):
        import http.client
        got = []
        channel = guestfiles.Channel("127.0.0.1", source=lambda out: out.write(b"x" * 100000),
                                     sink=lambda body: got.append(body.read()))
        self.addCleanup(channel.close)
        conn = http.client.HTTPConnection("127.0.0.1", channel.port, timeout=10)
        conn.request("GET", "/wrong/get")
        self.assertEqual(conn.getresponse().status, 404)  # only the secret path
        conn = http.client.HTTPConnection("127.0.0.1", channel.port, timeout=10)
        conn.request("GET", f"/{channel.secret}/get")
        self.assertEqual(len(conn.getresponse().read()), 100000)
        conn = http.client.HTTPConnection("127.0.0.1", channel.port, timeout=10)
        conn.putrequest("PUT", f"/{channel.secret}/put")
        conn.putheader("Transfer-Encoding", "chunked")  # as curl -T - sends it
        conn.endheaders()
        for part in (b"hello ", b"chunked ", b"world"):
            conn.send(b"%x\r\n%s\r\n" % (len(part), part))
        conn.send(b"0\r\n\r\n")
        self.assertEqual(conn.getresponse().status, 200)
        self.assertEqual(got, [b"hello chunked world"])
        self.assertTrue(channel.reached.is_set() and channel.done.is_set())

    def test_zip_keeps_greek_names_and_nothing_lands_outside(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "src" / "φάκελος").mkdir(parents=True)
        (root / "src" / "φάκελος" / "αρχείο.txt").write_text("ναι", encoding="utf-8")
        with open(root / "a.zip", "wb") as f:
            guestfiles.write_zip([root / "src" / "φάκελος"], f)
        (root / "out").mkdir()
        guestfiles.extract_zip(root / "a.zip", root / "out")
        self.assertEqual((root / "out" / "φάκελος" / "αρχείο.txt").read_text(encoding="utf-8"), "ναι")
        import zipfile
        with zipfile.ZipFile(root / "evil.zip", "w") as z:
            z.writestr("../outside.txt", "no")
        guestfiles.extract_zip(root / "evil.zip", root / "out")
        self.assertFalse((root / "outside.txt").exists())
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            info = tarfile.TarInfo("../outside.txt")
            info.size = 2
            t.addfile(info, io.BytesIO(b"no"))
        buf.seek(0)
        with self.assertRaises(tarfile.TarError):  # a guest's archive cannot write outside the chosen folder
            guestfiles.extract_tar(buf, root / "out")
        self.assertFalse((root / "outside.txt").exists())



DATA = Path(__file__).resolve().parent / "data"


def screen_of(name: str) -> tuple[int, int, bytes]:
    """A saved console picture (the app's own PNG: RGB, no filters) as the console sends it: width, height, BGRA."""
    png = (DATA / name).read_bytes()
    w, h = struct.unpack(">II", png[16:24])
    data, pos = b"", 8
    while pos < len(png):
        n = struct.unpack(">I", png[pos:pos + 4])[0]
        if png[pos + 4:pos + 8] == b"IDAT":
            data += png[pos + 8:pos + 8 + n]
        pos += 12 + n
    raw, stride, out = zlib.decompress(data), w * 3 + 1, bytearray(w * h * 4)
    for y in range(h):
        row = raw[y * stride + 1:(y + 1) * stride]
        out[y * w * 4:(y + 1) * w * 4:4], out[y * w * 4 + 1:(y + 1) * w * 4:4] = row[2::3], row[1::3]
        out[y * w * 4 + 2:(y + 1) * w * 4:4] = row[0::3]
    return w, h, bytes(out)


class ScreenVnc(FakeVncServer):
    """The pretend console showing a given screen, and another one whenever show() is called."""

    def __init__(self, ws, password, screen_, after_enter=None):
        w, h, self.image = screen_
        self.after_enter = after_enter  # what the guest shows once Enter reaches it
        super().__init__(ws, password, width=w, height=h)

    def show(self, screen_):
        _, _, self.image = screen_
        with self.lock:
            self.dirty = [None]
        self._flush()

    def _full_screen(self):
        self._send(struct.pack(">BxH", 0, 1) + struct.pack(">HHHHi", 0, 0, self.width, self.height, 0) + self.image)

    def _typed(self, down, keysym):
        if down and keysym == 0xFF0D and self.after_enter is not None:
            self.show(self.after_enter)

    def _flush(self):
        with self.lock:
            if not (self.wants_update and self.dirty):
                return
            self.dirty, self.wants_update = [], False
        self._full_screen()


def read_iso(image: bytes, joliet: bool) -> tuple[str, dict[str, bytes]]:
    """The volume name and the root folder's files of an ISO image, read as a CD reader would (the primary tree's
    names or the Joliet tree's)."""
    sector = isofs.SECTOR
    desc = image[(17 if joliet else 16) * sector:][:sector]
    assert desc[1:6] == b"CD001" and desc[0] == (2 if joliet else 1)
    if joliet:
        assert desc[88:91] == b"%/E"
    label = desc[40:72].decode("utf-16-be" if joliet else "ascii").strip()
    root = desc[156:190]
    at, size = struct.unpack("<I", root[2:6])[0], struct.unpack("<I", root[10:14])[0]
    folder, files, pos = image[at * sector:at * sector + size], {}, 0
    while pos < len(folder):
        length = folder[pos]
        if length == 0:  # the rest of this sector is empty: records never cross into the next one
            pos = (pos // sector + 1) * sector
            continue
        rec = folder[pos:pos + length]
        ident = rec[33:33 + rec[32]]
        if ident not in (b"\x00", b"\x01"):
            extent, data_len = struct.unpack("<I", rec[2:6])[0], struct.unpack("<I", rec[10:14])[0]
            name = ident.decode("utf-16-be") if joliet else ident.decode("ascii")
            files[name] = image[extent * sector:extent * sector + data_len]
        pos += length
    return label, files


class IsoFsTest(unittest.TestCase):
    """The setup disc's ISO image: both trees readable, the real names in the Joliet one."""

    FILES = {"autounattend.xml": b"<unattend/>", "user-data": b"#cloud-config\n{}", "meta-data": b"",
             "big.bin": bytes(range(256)) * 41}

    def test_both_trees(self):
        image = isofs.make_iso(self.FILES, "cidata", when=0)
        self.assertEqual(len(image) % isofs.SECTOR, 0)
        label, files = read_iso(image, joliet=True)
        self.assertEqual((label, files), ("cidata", self.FILES))  # the real names (what Windows and Linux read)
        label, files = read_iso(image, joliet=False)
        self.assertEqual(label, "CIDATA")
        self.assertEqual(sorted(files), ["AUTOUNAT.XML;1", "BIG.BIN;1", "META_DAT.;1", "USER_DAT.;1"])
        self.assertEqual(files["BIG.BIN;1"], self.FILES["big.bin"])

    def test_a_folder_longer_than_a_sector(self):
        many = {f"file-number-{n:03d}-with-a-long-name.txt": str(n).encode() for n in range(60)}
        _, files = read_iso(isofs.make_iso(many, "many"), joliet=True)
        self.assertEqual(files, many)
        _, short = read_iso(isofs.make_iso(many, "many"), joliet=False)
        self.assertEqual(len(set(short)), 60)  # 8.3 names, each one different

    def test_names_are_checked(self):
        for files, label in (({"a b.txt": b""}, "x"), ({"ok.txt": b""}, "bad label"), ({"δ.txt": b""}, "x")):
            with self.assertRaises(ValueError):
                isofs.make_iso(files, label)
        self.assertEqual(isofs.short_names(["user-data", "user-data.x", "USER_DAT"]),
                         ["USER_DAT.", "USER_DAT.X", "USER_D_2."])

    @unittest.skipUnless(shutil.which("xorriso"), "xorriso is not installed")
    def test_xorriso_reads_it(self):
        """Another program's reader (libisofs), as a check on the format itself."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "seed.iso")
            Path(path).write_bytes(isofs.make_iso(self.FILES, "cidata"))
            listing = subprocess.run(["xorriso", "-indev", path, "-ls", "/"], capture_output=True, text=True).stdout
            self.assertEqual(sorted(re.findall(r"'([^']+)'", listing)), sorted(self.FILES))
            out = os.path.join(d, "out")
            subprocess.run(["xorriso", "-osirrox", "on", "-indev", path, "-extract", "/", out],
                           capture_output=True, check=True)
            for name, data in self.FILES.items():
                self.assertEqual(Path(out, name).read_bytes(), data)
            if shutil.which("blkid"):  # how cloud-init finds its disc
                found = subprocess.run(["blkid", "-p", "-o", "export", path], capture_output=True, text=True).stdout
                self.assertIn("LABEL=cidata", found)


class WinSetupTest(unittest.TestCase):
    NS = {"u": "urn:schemas-microsoft-com:unattend"}

    def xml(self, **kw):
        import xml.etree.ElementTree as ET
        args = {"user": "nikos", "password": "S3cret-Pässword", "computer": "win-1", "edition": "Windows 11 Pro",
                "uefi": True, **kw}
        text = winsetup.answer_file(**args)
        return text, ET.fromstring(text)

    def component(self, root, setting, name):
        for s in root.findall("u:settings", self.NS):
            if s.get("pass") == setting:
                for c in s.findall("u:component", self.NS):
                    if c.get("name") == name:
                        return c
        return None

    def test_answer_file(self):
        text, root = self.xml(remote_desktop=True, dark=True)
        self.assertNotIn("S3cret", text)  # only Windows' hidden form
        shell = self.component(root, "oobeSystem", "Microsoft-Windows-Shell-Setup")
        account = shell.find("u:UserAccounts/u:LocalAccounts/u:LocalAccount", self.NS)
        self.assertEqual(account.find("u:Name", self.NS).text, "nikos")
        self.assertEqual(account.find("u:Group", self.NS).text, "Administrators")
        hidden = account.find("u:Password/u:Value", self.NS).text
        self.assertEqual(base64.b64decode(hidden).decode("utf-16-le"), "S3cret-PässwordPassword")
        self.assertEqual(shell.find("u:AutoLogon/u:LogonCount", self.NS).text, "1")
        self.assertEqual(shell.find("u:OOBE/u:ProtectYourPC", self.NS).text, "3")
        self.assertIsNone(shell.find("u:UserAccounts/u:AdministratorPassword", self.NS))  # not a server
        setup = self.component(root, "windowsPE", "Microsoft-Windows-Setup")
        self.assertEqual(setup.find(".//u:MetaData/u:Value", self.NS).text, "Windows 11 Pro")
        self.assertEqual(setup.find(".//u:InstallTo/u:PartitionID", self.NS).text, "3")  # EFI, MSR, Windows
        kinds = [p.find("u:Type", self.NS).text for p in setup.findall(".//u:CreatePartition", self.NS)]
        self.assertEqual(kinds, ["EFI", "MSR", "Primary"])
        paths = [p.text for p in self.component(root, "windowsPE", "Microsoft-Windows-PnpCustomizationsWinPE")
                 .findall(".//u:Path", self.NS)]
        self.assertIn("E:\\vioscsi\\w11\\amd64", paths)
        self.assertIn("D:\\NetKVM\\w11\\amd64", paths)
        self.assertEqual(self.component(root, "specialize", "Microsoft-Windows-Shell-Setup")
                         .find("u:ComputerName", self.NS).text, "win-1")
        commands = [c.find("u:CommandLine", self.NS).text for c in shell.findall(".//u:SynchronousCommand", self.NS)]
        self.assertIn("fDenyTSConnections -Value 0", commands[0])
        self.assertIn(winsetup.RDP_FIREWALL_GROUP, commands[0])  # the firewall group in any language
        self.assertTrue(any("AppsUseLightTheme" in c for c in commands))
        self.assertIn("virtio-win-guest-tools.exe", commands[-1])  # last: the agent answering means ready
        orders = [int(c.find("u:Order", self.NS).text) for c in shell.findall(".//u:SynchronousCommand", self.NS)]
        self.assertEqual(orders, list(range(1, len(orders) + 1)))

    def test_bios_server_and_no_virtio(self):
        text, root = self.xml(uefi=False, virtio=False, edition="Windows Server 2022 Standard (Desktop Experience)")
        setup = self.component(root, "windowsPE", "Microsoft-Windows-Setup")
        self.assertEqual([p.find("u:Type", self.NS).text for p in setup.findall(".//u:CreatePartition", self.NS)],
                         ["Primary", "Primary"])
        self.assertEqual(setup.find(".//u:ModifyPartition/u:Active", self.NS).text, "true")
        self.assertEqual(setup.find(".//u:InstallTo/u:PartitionID", self.NS).text, "2")
        self.assertIsNone(self.component(root, "windowsPE", "Microsoft-Windows-PnpCustomizationsWinPE"))
        shell = self.component(root, "oobeSystem", "Microsoft-Windows-Shell-Setup")
        admin = shell.find("u:UserAccounts/u:AdministratorPassword/u:Value", self.NS).text
        self.assertEqual(base64.b64decode(admin).decode("utf-16-le"), "S3cret-PässwordAdministratorPassword")
        self.assertIsNone(shell.find("u:FirstLogonCommands", self.NS))  # no tools without the VirtIO disc
        self.assertIn("2k22", winsetup.driver_folder("Windows Server 2022 Standard (Desktop Experience)"))
        self.assertEqual(winsetup.driver_folder("Windows 10 Pro"), "w10")

    def test_checks(self):
        ok = ("user", "pw", False, "Windows 11 Pro")
        self.assertEqual(winsetup.check_user(*ok), "")
        self.assertEqual(winsetup.check_user("user", "", False, "Windows 11 Pro"), "")  # no password: allowed
        for args, words in ((("user", "", True, "Windows 11 Pro"), "Remote Desktop needs a password"),
                            (("user", "pw", True, "Windows 11 Home"), "Home"),
                            (("Administrator", "pw", False, "Windows 11 Pro"), "Windows' own"),
                            (("bad/name", "pw", False, "Windows 11 Pro"), "user name"),
                            (("user", "", False, "Windows Server 2025 Standard"), "Administrator")):
            self.assertIn(words, winsetup.check_user(*args))
        with self.assertRaises(ValueError):
            winsetup.answer_file(user="user", password="", computer="x", edition="Windows 11 Pro", uefi=True,
                                 remote_desktop=True)

    def test_names(self):
        for volid, lang in (("local:iso/Win11_25H2_English_x64.iso", "en-US"),
                            ("local:iso/Win11_25H2_EnglishInternational_x64.iso", "en-GB"),
                            ("nas:iso/Win11_24H2_Greek_x64v2.iso", "el-GR"),
                            ("local:iso/26100.1742_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_de-de.iso", "de-DE"),
                            ("local:iso/windows.iso", "en-US")):
            self.assertEqual(winsetup.language_of_iso(volid), lang, volid)
        self.assertEqual(winsetup.computer_name("my-windows-vm-number-one.lan"), "my-windows-vm-n")
        self.assertEqual(winsetup.computer_name("1234"), "*")
        self.assertEqual(winsetup.default_edition("win10"), "Windows 10 Pro")


class CloudSeedTest(unittest.TestCase):
    def test_sha512_crypt(self):
        # Ulrich Drepper's own examples (the SHA-crypt specification)
        self.assertEqual(cloudseed.sha512_crypt("Hello world!", "saltstring"),
                         "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEd"
                         "FCoEOfaS35inz1")
        self.assertEqual(cloudseed.sha512_crypt("Hello world!", "saltstringsaltstring", rounds=10000),
                         "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZe"
                         "HBy/YTBmSK6H9qs/y3RnOaw5v.")
        made = cloudseed.sha512_crypt("pw")
        salt = made.split("$")[2]
        self.assertEqual((len(salt), cloudseed.sha512_crypt("pw", salt)), (16, made))

    @unittest.skipUnless(shutil.which("openssl"), "openssl is not installed")
    def test_sha512_crypt_as_openssl(self):
        for pw in ("a", "Καλημέρα κόσμε!", "x" * 65, "x" * 200, "p@ss w0rd$\\"):
            theirs = subprocess.run(["openssl", "passwd", "-6", "-salt", "AbC.def/123", "-stdin"], input=pw.encode(),
                                    capture_output=True).stdout.decode().strip()
            self.assertEqual(cloudseed.sha512_crypt(pw, "AbC.def/123"), theirs)

    def config(self, **kw):
        text = cloudseed.user_data(**{"vm_name": "desk.lan", "user": "nikos", "password": "Pw-1234",
                                      "ssh_keys": ["ssh-ed25519 AAAA me@pc", ""], **kw})
        self.assertTrue(text.startswith("#cloud-config\n"))
        self.assertNotIn("Pw-1234", text)
        return json.loads(text.split("\n", 1)[1])  # (JSON: YAML too, for cloud-init)

    def test_desktop_with_remote_desktop(self):
        cfg = self.config(remote_desktop=True)
        self.assertEqual((cfg["user"], cfg["users"], cfg["hostname"], cfg["fqdn"]),
                         ("nikos", ["default"], "desk", "desk.lan"))
        salt = cfg["password"].split("$")[2]
        self.assertEqual(cfg["password"], cloudseed.sha512_crypt("Pw-1234", salt))
        self.assertEqual(cfg["ssh_authorized_keys"], ["ssh-ed25519 AAAA me@pc"])
        for pkg in ("qemu-guest-agent", "ubuntu-desktop-minimal", "xrdp", "xorgxrdp", "xfce4"):
            self.assertIn(pkg, cfg["packages"])
        self.assertIn(["update-alternatives", "--set", "x-session-manager", "/usr/bin/xfce4-session"], cfg["runcmd"])
        self.assertIn(["systemctl", "enable", "--now", "xrdp"], cfg["runcmd"])
        self.assertEqual(cfg["runcmd"][0], ["systemctl", "start", "qemu-guest-agent"])
        self.assertEqual(cfg["power_state"]["mode"], "reboot")
        self.assertTrue(cfg["package_upgrade"])  # the image on the host ages: the VM starts up to date
        self.assertIn("color-manager", cfg["write_files"][0]["content"])

    def test_without_remote_desktop(self):
        cfg = self.config()
        self.assertNotIn("xrdp", cfg["packages"])
        self.assertNotIn("write_files", cfg)
        self.assertNotIn("power_state", self.config(desktop=False))
        with self.assertRaises(ValueError):
            cloudseed.user_data(vm_name="d", user="u", password="", ssh_keys=[], remote_desktop=True)
        one, two = (json.loads(cloudseed.meta_data("desk.lan", 120)) for _ in range(2))
        self.assertNotEqual(one["instance-id"], two["instance-id"])
        self.assertEqual(one["local-hostname"], "desk")


class SetupDiscTest(unittest.TestCase):
    def setUp(self):
        DemoPve._clusters.clear()
        self.pve = DemoPve(DEMO_HOSTS[0])
        self.cluster = self.pve.cluster

    def vm_with_disc(self, vmid=150, agent=True, status="running", uptime=600):
        volid = setupdisc.upload(self.pve, "pve", "local", vmid, {"autounattend.xml": b"<x/>"}, "autounattend")
        self.pve.create_vm("pve", {"vmid": vmid, "name": f"vm{vmid}", "scsi0": "local-lvm:8",
                                   "ide3": f"{volid},media=cdrom", "agent": "1" if agent else "0"})
        g = self.cluster.guests[vmid]
        g.update(status=status, uptime=uptime)
        return setupdisc.entry("demo-pve", "pve", vmid, volid, "ide3", agent)

    def test_upload(self):
        volid = setupdisc.upload(self.pve, "pve", "local", 150, {"user-data": b"x", "meta-data": b""}, "cidata")
        self.assertRegex(volid, r"^local:iso/pvc-setup-150-[0-9a-f]{6}\.iso$")
        self.assertTrue(setupdisc.is_setup_disc(volid))
        self.assertFalse(setupdisc.is_setup_disc("local:iso/virtio-win.iso"))
        label, files = read_iso(self.cluster.files[volid.split("/")[1]], joliet=True)
        self.assertEqual((label, files), ("cidata", {"user-data": b"x", "meta-data": b""}))
        self.assertEqual(setupdisc.free_slot({"ide2": "x", "ide3": "y"}), "ide1")

    def test_tidy(self):
        ready = self.vm_with_disc(150)                                  # the agent answers: set up
        stopped = self.vm_with_disc(151, status="stopped")              # not started yet: it still needs the disc
        silent = self.vm_with_disc(152)                                 # the agent does not answer yet
        self.cluster.guests[152]["agent_down"] = True
        young = self.vm_with_disc(153, agent=False, uptime=60)          # no agent will tell; started a minute ago
        old = self.vm_with_disc(154, agent=False, uptime=setupdisc.READY_UPTIME_S)
        given_up = self.vm_with_disc(155, uptime=setupdisc.AGENT_GIVE_UP_S)
        self.cluster.guests[155]["agent_down"] = True
        gone = self.vm_with_disc(156)
        del self.cluster.guests[156]
        entries = [ready, stopped, silent, young, old, given_up, gone]
        taken, said = setupdisc.tidy(self.pve, entries, self.pve.guests())
        self.assertEqual(taken, {ready["volid"], old["volid"], given_up["volid"], gone["volid"]})
        for e in (ready, old, given_up, gone):
            self.assertNotIn(e["volid"], self.cluster.isos)  # the file is deleted
        for e in (stopped, silent, young):
            self.assertIn(e["volid"], self.cluster.isos)
        self.assertEqual(self.pve.guest_config("pve", "qemu", 150)["ide3"], "none,media=cdrom")  # the drive emptied
        self.assertIn("VM 150 (vm150): setup finished", said[0])
        self.assertTrue(any("VM 156 is gone" in t for t in said))
        self.assertEqual(setupdisc.tidy(self.pve, [ready], self.pve.guests())[0], {ready["volid"]})  # gone already

    def test_the_boot_question_is_recognised(self):
        """On the real screens of the user's first test (VM 102, 24/10): only the question itself."""
        self.assertTrue(setupdisc.boot_prompt_on(*screen_of("boot-prompt.png")))
        for name in ("boot-logo.png", "boot-menu.png", "boot-too-late.png"):  # the firmware's logo, menu, messages
            self.assertFalse(setupdisc.boot_prompt_on(*screen_of(name)), name)
        self.assertFalse(setupdisc.boot_prompt_on(1280, 800, bytes(1280 * 800 * 4)))  # black
        self.assertFalse(setupdisc.boot_prompt_on(0, 0, b""))

    def test_enter_when_the_question_shows(self):
        """One console kept open: Enter only while the question is on the screen, then done."""
        logo, prompt = screen_of("boot-logo.png"), screen_of("boot-prompt.png")
        servers = []

        def open_console():
            mine, theirs = socket.socketpair()
            srv = ScreenVnc(WebSocket(theirs, client=False), "pw", logo, after_enter=logo).start()
            servers.append(srv)
            return WebSocket(mine), "pw"

        threading.Timer(0.4, lambda: servers[0].show(prompt)).start()  # the logo first, then the question
        self.assertTrue(screen.answer_prompt(open_console, setupdisc.boot_prompt_on, timeout=10))
        downs = [k for k in servers[0].keys if k[1]]
        self.assertTrue(downs and all(k[2] == 0xFF0D for k in downs))  # Enter, and nothing else
        # it never comes: no key at all, and False when the time is up
        servers.clear()
        self.assertFalse(screen.answer_prompt(open_console, setupdisc.boot_prompt_on, timeout=1.0, quiet=0.3))
        self.assertTrue(servers and not any(s.keys for s in servers))
