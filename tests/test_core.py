"""The Qt-free core: Wake-on-LAN, address and fingerprint handling, the API client against a local HTTPS
server that answers like Proxmox, settings storage and MAC discovery. No real Proxmox is touched."""

import base64
import io
import json
import os
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
                                     mcp, netinfo, screen, spice, startup, store, tasks, vault, vmhw, wol)
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
                         ["on", "ask", "ask", "off", "off", "off", "off", "off"])  # the user's chosen defaults
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
        self.assertIn("ubuntu-desktop-minimal", " ".join(desk["next_steps"]))
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
