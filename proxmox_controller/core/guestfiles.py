"""Files inside a guest, and copies between this computer and it (Files…, and Claude's send_file / receive_file).

Whatever is chosen — files and folders alike — travels as one archive, names and times kept: a tar stream to and from
Linux, a zip to and from Windows (its tar.exe mangles names outside the ANSI code page; .NET's zip keeps them). Three
ways, the first that works:

- VM, over the network: the app opens a channel for that one copy (a port of its own on this computer's address, a
  secret path, shut when done) and the VM's own curl fetches or uploads it, started through the QEMU guest agent.
  Measured 23/10/2026 (Windows 11, Ubuntu): 40–110 MB/s.
- VM, through Proxmox: the guest agent's file-read (16 MiB a call) and file-write (45 KiB a call). About 1 MB/s down;
  up much slower on Linux. Used when the VM cannot reach this computer.
- Container: the app's SSH to the host and `pct exec`, the archive on SSH's own pipe.

What goes to the agent stays ASCII — it stalls on other characters (measured 21/10) — so names and folders travel
base64-encoded, and the guest's answers come back the same way. On Linux the guest's agent runs as root: what arrives
is given to the owner of the folder it lands in."""

from __future__ import annotations

import base64
import io
import os
import posixpath
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from typing import Callable, Iterable

from . import procs, ssh

PART = 45 * 1024           # file-write takes 60 KiB of base64: 45 KiB of data
READ = 16 * 1024 * 1024    # file-read gives at most 16 MiB a call
CONNECT_WAIT_S = 8.0       # how long the guest has to reach the channel before Proxmox's way is taken
TEMP = {"linux": "/tmp", "windows": r"C:\Windows\Temp"}

Progress = Callable[[int, "int | None", str], None]  # (bytes so far, total or None, "network" | "proxmox" | "ssh")


class Cancelled(Exception):
    pass


class GuestError(Exception):
    """Something the user is told as it is."""


@dataclass
class Entry:
    name: str
    is_dir: bool
    size: int
    mtime: int


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def unb64(text: str) -> str:
    return base64.b64decode(text).decode("utf-8", errors="replace")


def os_of(cfg: dict) -> str:
    """'windows' or 'linux', from the VM's ostype (win10, win11, l26, other…)."""
    return "windows" if str(cfg.get("ostype", "")).startswith("win") else "linux"


def join(os_name: str, folder: str, name: str) -> str:
    if os_name == "windows":
        return str(PureWindowsPath(folder or "") / name) if folder else name
    return posixpath.join(folder or "/", name)


def parent(os_name: str, folder: str) -> str:
    """One folder up; Windows above a drive's root: '' (the list of drives)."""
    if os_name == "windows":
        p = PureWindowsPath(folder)
        return "" if p == PureWindowsPath(p.anchor) or not folder else str(p.parent)
    return posixpath.dirname(folder.rstrip("/")) or "/"


# -- what the guest runs ------------------------------------------------------------------------------

LINUX_LIST = r"""
p=$(printf %s "$1" | base64 -d) || exit 3
[ -n "$p" ] || p=/
cd -- "$p" 2>/dev/null || { echo "ERR No such folder"; exit 4; }
printf 'PWD %s\n' "$(pwd | tr -d '\n' | base64 | tr -d '\n')"
if find . -maxdepth 0 -printf '' 2>/dev/null; then
  find . -mindepth 1 -maxdepth 1 -printf '%Y %s %T@ %f\0' 2>/dev/null
else
  for f in .* *; do
    case "$f" in .|..) continue;; esac
    [ -e "$f" ] || [ -L "$f" ] || continue
    if [ -d "$f" ]; then t=d; s=0; else t=f; s=$(stat -c %s -- "$f" 2>/dev/null || echo 0); fi
    printf '%s %s %s %s\0' "$t" "$s" "$(stat -c %Y -- "$f" 2>/dev/null || echo 0)" "$f"
  done
fi | base64 | tr -d '\n' | sed 's/^/LIST /'
echo
"""

WINDOWS_LIST = r"""
$ErrorActionPreference = 'Stop'
function E([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{path}'))
if (-not $p) {
  'PWD '
  Get-PSDrive -PSProvider FileSystem | ForEach-Object { 'D 0 0 ' + (E $_.Root) }
  exit 0
}
try { $i = Get-Item -LiteralPath $p -Force } catch { 'ERR No such folder'; exit 4 }
'PWD ' + (E $i.FullName)
$epoch = [datetime]'1970-01-01'
Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | ForEach-Object {
  if ($_.PSIsContainer) { $t = 'D'; $s = 0 } else { $t = 'F'; $s = $_.Length }
  $m = [int64](($_.LastWriteTimeUtc - $epoch).TotalSeconds)
  "$t $s $m " + (E $_.Name)
}
"""


def parse_listing(out: str, os_name: str) -> tuple[str, list[Entry]]:
    """The guest's answer to *_LIST: (the folder's full path, its entries — folders first, then by name)."""
    folder, entries = "", []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("ERR "):
            raise GuestError(line[4:])
        if line.startswith("PWD"):
            folder = unb64(line[4:]) if len(line) > 4 else ""
        elif line.startswith("LIST "):  # Linux: NUL-separated "type size mtime name"
            for rec in base64.b64decode(line[5:]).split(b"\0"):
                if not rec:
                    continue
                t, size, mtime, name = rec.decode("utf-8", errors="replace").split(" ", 3)
                entries.append(Entry(name, t == "d", int(size) if t != "d" else 0, int(float(mtime))))
        elif os_name == "windows" and line[:2] in ("D ", "F "):
            t, size, mtime, name = line.split(" ", 3)
            entries.append(Entry(unb64(name), t == "D", int(size), int(mtime)))
    entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
    return folder, entries


def _ps(script: str) -> list[str]:
    return ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]


def _names_b64(names: Iterable[str]) -> str:
    return base64.b64encode("\0".join(names).encode("utf-8")).decode("ascii")


# Linux, over the network: the archive comes on curl's pipe into tar; what came is given to the folder's owner.
# (Expect: — curl would wait a second for a "100 Continue" the channel does not send.)
LINUX_SEND_NET = r"""
cd -- "$(printf %s "$1" | base64 -d)" || { echo "ERR No such folder"; exit 4; }
o=$(stat -c %u:%g .)
curl -fsS --connect-timeout 5 "$3" | tar -x --no-same-owner -f - || exit 5
printf %s "$2" | base64 -d | xargs -0 -r chown -R "$o" -- 2>/dev/null
exit 0
"""
LINUX_RECV_NET = r"""
cd -- "$(printf %s "$1" | base64 -d)" || { echo "ERR No such folder"; exit 4; }
printf %s "$2" | base64 -d | tar -c --null -T - -f - | curl -fsS --connect-timeout 5 -H 'Expect:' -T - "$3" || exit 5
"""
# Linux, through Proxmox: the parts written by file-write, joined into tar; and the archive packed for file-read
LINUX_JOIN = r"""
d="$1"; cd -- "$(printf %s "$2" | base64 -d)" || { rm -rf -- "$d"; echo "ERR No such folder"; exit 4; }
o=$(stat -c %u:%g .)
cat "$d"/p* | tar -x --no-same-owner -f - ; s=$?
rm -rf -- "$d"
printf %s "$3" | base64 -d | xargs -0 -r chown -R "$o" -- 2>/dev/null
exit $s
"""
LINUX_PACK = r"""
cd -- "$(printf %s "$1" | base64 -d)" || { echo "ERR No such folder"; exit 4; }
printf %s "$2" | base64 -d | tar -c --null -T - -f "$3" && stat -c %s -- "$3"
"""

# Windows: zip in and out with .NET; curl.exe for the network
_WIN_HEAD = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function D([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
function Unzip([string]$zip, [string]$dest) {
  $root = [IO.Path]::GetFullPath($dest).TrimEnd('\') + '\'
  $z = [IO.Compression.ZipFile]::OpenRead($zip)
  try {
    foreach ($e in $z.Entries) {
      $t = [IO.Path]::GetFullPath((Join-Path $dest $e.FullName))
      if (-not $t.StartsWith($root)) { continue }
      if ($e.FullName.EndsWith('/')) { New-Item -ItemType Directory -Force -Path $t | Out-Null; continue }
      New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($t)) | Out-Null
      [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $t, $true)
      try { (Get-Item -LiteralPath $t).LastWriteTime = $e.LastWriteTime.DateTime } catch {}
    }
  } finally { $z.Dispose() }
}
function Zip([string]$folder, [string[]]$names, [string]$zip) {
  if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
  $z = [IO.Compression.ZipFile]::Open($zip, 'Create')
  try {
    foreach ($n in $names) {
      $p = Join-Path $folder $n
      if (Test-Path -LiteralPath $p -PathType Container) {
        $base = (Get-Item -LiteralPath $folder).FullName.TrimEnd('\').Length + 1
        Get-ChildItem -LiteralPath $p -Recurse -Force | ForEach-Object {
          $rel = $_.FullName.Substring($base).Replace('\', '/')
          if ($_.PSIsContainer) { [void]$z.CreateEntry($rel + '/') }
          else { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z, $_.FullName, $rel) }
        }
        [void]$z.CreateEntry($n.Replace('\', '/') + '/')
      } else { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z, $p, $n) }
    }
  } finally { $z.Dispose() }
}
"""
WINDOWS_SEND_NET = _WIN_HEAD + r"""
$dest = D '{dest}'
if (-not (Test-Path -LiteralPath $dest -PathType Container)) { 'ERR No such folder'; exit 4 }
$zip = Join-Path $env:windir ('Temp\pcx-{tag}.zip')
& curl.exe -fsS --connect-timeout 5 -o $zip '{url}'
if ($LASTEXITCODE -ne 0) { "CURL $LASTEXITCODE"; exit 5 }
try { Unzip $zip $dest } finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
"""
WINDOWS_RECV_NET = _WIN_HEAD + r"""
$folder = D '{folder}'
$names = (D '{names}') -split [char]0
$zip = Join-Path $env:windir ('Temp\pcx-{tag}.zip')
try {
  Zip $folder $names $zip
  & curl.exe -fsS --connect-timeout 5 -H 'Expect:' -T $zip '{url}'
  if ($LASTEXITCODE -ne 0) { "CURL $LASTEXITCODE"; exit 5 }
} finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
"""
WINDOWS_JOIN = _WIN_HEAD + r"""
$dir = '{parts}'
$dest = D '{dest}'
$zip = $dir + '.zip'
try {
  $out = [IO.File]::Create($zip)
  try { Get-ChildItem -LiteralPath $dir | Sort-Object Name | ForEach-Object { $b = [IO.File]::ReadAllBytes($_.FullName); $out.Write($b, 0, $b.Length) } }
  finally { $out.Dispose() }
  Unzip $zip $dest
} finally {
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
}
"""
WINDOWS_PACK = _WIN_HEAD + r"""
$folder = D '{folder}'
$names = (D '{names}') -split [char]0
Zip $folder $names '{zip}'
(Get-Item -LiteralPath '{zip}').Length
"""


# -- the archive on this computer -----------------------------------------------------------------------

def total_size(paths: Iterable[Path]) -> int:
    n = 0
    for p in paths:
        if p.is_dir():
            for root, _dirs, files in os.walk(p):
                for f in files:
                    try:
                        n += (Path(root) / f).stat().st_size
                    except OSError:
                        pass
        elif p.exists():
            n += p.stat().st_size
    return n


def write_tar(paths: list[Path], out) -> None:
    """A tar stream of the chosen files and folders (each under its own name) into `out`."""
    with tarfile.open(fileobj=out, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for p in paths:
            tar.add(str(p), arcname=p.name)


def write_zip(paths: list[Path], out) -> None:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for p in paths:
            if p.is_dir():
                z.write(p, p.name + "/")
                for root, dirs, files in os.walk(p):
                    for d in dirs:
                        full = Path(root) / d
                        z.write(full, str(full.relative_to(p.parent)).replace(os.sep, "/") + "/")
                    for f in files:
                        full = Path(root) / f
                        z.write(full, str(full.relative_to(p.parent)).replace(os.sep, "/"))
            else:
                z.write(p, p.name)


def extract_tar(stream, dest: Path) -> None:
    """A tar stream into `dest` — nothing outside it, no devices or links out (Python's 'data' filter)."""
    with tarfile.open(fileobj=stream, mode="r|") as tar:
        for member in tar:
            tar.extract(member, dest, filter="data")


def extract_zip(path: Path, dest: Path) -> None:
    root = dest.resolve()
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if root != target and root not in target.parents:
                continue  # a name that would land outside the chosen folder
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            when = time.mktime(info.date_time + (0, 0, -1))
            os.utime(target, (when, when))


# -- the channel on this computer ---------------------------------------------------------------------

class Channel:
    """One copy's door on this computer: GET /<secret>/get serves `source` (a function writing the archive into a
    file object), PUT /<secret>/put hands the upload to `sink` (a function reading a file object). Any other path:
    404. Counts the bytes for the progress; shut by close()."""

    def __init__(self, address: str, source=None, sink=None, on_bytes: Callable[[int], None] | None = None):
        self.secret = secrets.token_urlsafe(24)
        self.source, self.sink = source, sink
        self.reached = threading.Event()   # the guest came
        self.done = threading.Event()      # the copy went through, or failed
        self.error: BaseException | None = None
        self.on_bytes = on_bytes or (lambda n: None)
        channel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_GET(self):
                if self.path != f"/{channel.secret}/get" or channel.source is None:
                    self.send_error(404)
                    return
                channel.reached.set()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    channel.source(_Counting(self.wfile, channel.on_bytes))
                except BaseException as e:  # noqa: BLE001 — told to the waiting side
                    channel.error = e
                finally:
                    channel.done.set()

            def do_PUT(self):
                if self.path != f"/{channel.secret}/put" or channel.sink is None:
                    self.send_error(404)
                    return
                channel.reached.set()
                body = _Body(self.rfile, self.headers, channel.on_bytes)
                try:
                    channel.sink(body)
                    body.drain()
                    self.send_response(200)
                except BaseException as e:  # noqa: BLE001
                    channel.error = e
                    self.send_response(500)
                finally:
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    channel.done.set()

        self.server = ThreadingHTTPServer((address, 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.address = address
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, verb: str) -> str:
        return f"http://{self.address}:{self.port}/{self.secret}/{verb}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Counting(io.RawIOBase):
    def __init__(self, raw, on_bytes):
        self.raw, self.on_bytes = raw, on_bytes

    def writable(self):
        return True

    def write(self, b):
        self.raw.write(b)
        self.on_bytes(len(b))
        return len(b)


class _Body(io.RawIOBase):
    """A request's body, plain or chunked (curl -T - sends chunked), as a file to read."""

    def __init__(self, rfile, headers, on_bytes):
        self.rfile, self.on_bytes = rfile, on_bytes
        self.chunked = "chunked" in headers.get("Transfer-Encoding", "").lower()
        self.left = int(headers.get("Content-Length", 0) or 0)
        self.chunk_left, self.eof = 0, False

    def readable(self):
        return True

    def readinto(self, buf):
        if self.eof:
            return 0
        if self.chunked:
            if self.chunk_left == 0:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    self.eof = True
                    return 0
                self.chunk_left = size
            n = self.rfile.readinto(memoryview(buf)[:min(len(buf), self.chunk_left)])
            self.chunk_left -= n
            if self.chunk_left == 0:
                self.rfile.readline()  # the CRLF after a chunk
        else:
            if self.left <= 0:
                self.eof = True
                return 0
            n = self.rfile.readinto(memoryview(buf)[:min(len(buf), self.left)])
            self.left -= n
        if n:
            self.on_bytes(n)
        else:
            self.eof = True
        return n

    def drain(self):
        while self.read(1 << 20):
            pass


def address_towards(host: str, port: int = 8006) -> str:
    """This computer's own address on the way to the Proxmox host — the one its VMs most likely reach it on."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, port))
        return s.getsockname()[0]


# -- a VM, through its QEMU guest agent ----------------------------------------------------------------

class VmFiles:
    """Folders and copies of one running VM with a working guest agent. `pve` is the client to use (the user's token
    in the window; Claude's, with Files lent, for Claude's tools)."""

    def __init__(self, pve, node: str, vmid: int, os_name: str, address: str):
        self.pve, self.node, self.vmid, self.os_name, self.address = pve, node, int(vmid), os_name, address

    # -- the agent
    def start(self, argv: list[str]) -> int:
        return self.pve.agent_exec(self.node, self.vmid, argv)

    def wait(self, pid: int, cancel: threading.Event | None = None, timeout: float | None = None) -> dict:
        end = None if timeout is None else time.monotonic() + timeout
        while True:
            st = self.pve.agent_exec_status(self.node, self.vmid, pid)
            if st.get("exited"):
                return st
            if cancel is not None and cancel.is_set():
                self.kill(pid)
                raise Cancelled()
            if end is not None and time.monotonic() > end:
                return st
            time.sleep(0.3)

    def run(self, argv: list[str], timeout: float = 60) -> tuple[int, str, str]:
        st = self.wait(self.start(argv), timeout=timeout)
        if not st.get("exited"):
            raise GuestError("The VM did not answer in time.")
        return int(st.get("exitcode", 0)), st.get("out-data", ""), st.get("err-data", "")

    def kill(self, pid: int) -> None:
        try:
            self.start(["taskkill", "/T", "/F", "/PID", str(pid)] if self.os_name == "windows"
                       else ["sh", "-c", f"pkill -P {int(pid)}; kill {int(pid)}"])
        except Exception:  # the process may have ended meanwhile
            pass

    # -- folders
    def home(self) -> str:
        return r"C:\Users" if self.os_name == "windows" else "/home"

    def list(self, folder: str) -> tuple[str, list[Entry]]:
        if self.os_name == "windows":
            argv = _ps(WINDOWS_LIST.replace("{path}", b64(folder)))
        else:
            argv = ["sh", "-c", LINUX_LIST, "sh", b64(folder)]
        code, out, err = self.run(argv, timeout=60)
        if code not in (0,) and "ERR " not in out:
            raise GuestError((err or out).strip()[:300] or f"The listing failed ({code}).")
        return parse_listing(out, self.os_name)

    # -- copies
    def send(self, paths: list[Path], dest: str, progress: Progress, cancel: threading.Event) -> str:
        """The chosen files and folders of this computer into the VM's folder `dest`. Returns the way it went."""
        total = total_size(paths)
        done = [0]

        def counted(n: int) -> None:
            done[0] += n
            progress(done[0], total, "network")

        writer = write_zip if self.os_name == "windows" else write_tar
        channel = Channel(self.address, source=lambda out: writer(paths, out), on_bytes=counted)
        try:
            tag = secrets.token_hex(6)
            if self.os_name == "windows":
                argv = _ps(WINDOWS_SEND_NET.replace("{dest}", b64(dest)).replace("{tag}", tag)
                           .replace("{url}", channel.url("get")))
            else:
                argv = ["sh", "-c", LINUX_SEND_NET, "sh", b64(dest), _names_b64(p.name for p in paths),
                        channel.url("get")]
            pid = self.start(argv)
            reached, st = self._reached(pid, channel, cancel, CONNECT_WAIT_S)
            if reached:
                st = st or self.wait(pid, cancel)
                if channel.error is not None:
                    raise GuestError(f"Sending failed: {channel.error}")
                _check(st, "Copying into the VM failed")
                return "network"
            self.kill(pid)
        finally:
            channel.close()
        return self._send_through_proxmox(paths, dest, writer, progress, cancel)

    def _reached(self, pid: int, channel: Channel, cancel: threading.Event,
                 wait_s: float | None) -> tuple[bool, dict | None]:
        """Whether the guest's curl came to the channel — False as soon as it gave up (it cannot reach this
        computer), or after `wait_s` (None: as long as the guest's command runs — Windows zips before it connects).
        With it, the command's end as already told, if it came while looking: the guest agent tells an ended process
        once and then forgets it — asked again, "PID … does not exist" (a small file, 26/10: copied whole while the
        app was still looking, then that error though all had gone well)."""
        deadline = None if wait_s is None else time.monotonic() + wait_s
        while not channel.reached.is_set():
            if cancel.is_set():
                self.kill(pid)
                raise Cancelled()
            st = self.pve.agent_exec_status(self.node, self.vmid, pid)
            if st.get("exited"):
                return channel.reached.is_set(), st
            if deadline is not None and time.monotonic() > deadline:
                return False, None
            time.sleep(0.2)
        return True, None

    def receive(self, folder: str, names: list[str], dest: Path, progress: Progress, cancel: threading.Event,
                total: int | None = None) -> str:
        """The VM's files and folders `names` in `folder` into this computer's folder `dest`."""
        done = [0]

        def counted(n: int) -> None:
            done[0] += n
            progress(done[0], total, "network")

        if self.os_name == "windows":
            def sink(body):  # a zip is read from its end: kept whole first
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as z:
                    shutil.copyfileobj(body, z, 1 << 20)
                try:
                    extract_zip(Path(z.name), dest)
                finally:
                    os.unlink(z.name)
        else:
            def sink(body):
                extract_tar(io.BufferedReader(body, 1 << 20), dest)

        channel = Channel(self.address, sink=sink, on_bytes=counted)
        try:
            tag = secrets.token_hex(6)
            if self.os_name == "windows":
                argv = _ps(WINDOWS_RECV_NET.replace("{folder}", b64(folder)).replace("{names}", _names_b64(names))
                           .replace("{tag}", tag).replace("{url}", channel.url("put")))
            else:
                argv = ["sh", "-c", LINUX_RECV_NET, "sh", b64(folder), _names_b64(names), channel.url("put")]
            pid = self.start(argv)
            reached, st = self._reached(pid, channel, cancel, None if self.os_name == "windows" else CONNECT_WAIT_S)
            if reached:
                st = st or self.wait(pid, cancel)
                channel.done.wait(30)
                if channel.error is not None:
                    raise GuestError(f"Receiving failed: {channel.error}")
                _check(st, "Copying from the VM failed")
                return "network"
            self.kill(pid)
        finally:
            channel.close()
        return self._receive_through_proxmox(folder, names, dest, progress, cancel)

    # -- through Proxmox (slow, but needs nothing between the VM and this computer)
    def _send_through_proxmox(self, paths, dest, writer, progress, cancel) -> str:
        with tempfile.TemporaryFile() as archive:
            writer(paths, archive)
            size = archive.tell()
            archive.seek(0)
            parts = join(self.os_name, TEMP[self.os_name], f"pcx-{secrets.token_hex(6)}")
            self._mkdir(parts)
            n, sent = 0, 0
            while True:
                if cancel.is_set():
                    self._remove(parts)
                    raise Cancelled()
                data = archive.read(PART)
                if not data:
                    break
                n += 1
                self.pve.agent_file_write(self.node, self.vmid, join(self.os_name, parts, f"p{n:07d}"),
                                          base64.b64encode(data).decode("ascii"))
                sent += len(data)
                progress(sent, size, "proxmox")
        if self.os_name == "windows":
            argv = _ps(WINDOWS_JOIN.replace("{parts}", parts).replace("{dest}", b64(dest)))
        else:
            argv = ["sh", "-c", LINUX_JOIN, "sh", parts, b64(dest), _names_b64(p.name for p in paths)]
        code, out, err = self.run(argv, timeout=600)
        if code != 0:
            raise GuestError((out + err).strip()[:300] or f"Unpacking in the VM failed ({code}).")
        return "proxmox"

    def _receive_through_proxmox(self, folder, names, dest, progress, cancel) -> str:
        archive_path = join(self.os_name, TEMP[self.os_name], f"pcx-{secrets.token_hex(6)}" +
                            (".zip" if self.os_name == "windows" else ".tar"))
        if self.os_name == "windows":
            argv = _ps(WINDOWS_PACK.replace("{folder}", b64(folder)).replace("{names}", _names_b64(names))
                       .replace("{zip}", archive_path))
        else:
            argv = ["sh", "-c", LINUX_PACK, "sh", b64(folder), _names_b64(names), archive_path]
        code, out, err = self.run(argv, timeout=600)
        if code != 0:
            raise GuestError((out + err).strip()[:300] or f"Packing in the VM failed ({code}).")
        size = int(out.strip().splitlines()[-1])
        try:
            with tempfile.NamedTemporaryFile(delete=False) as local:
                offset = 0
                while offset < size:
                    if cancel.is_set():
                        raise Cancelled()
                    chunk = self.pve.agent_file_read(self.node, self.vmid, archive_path, offset, READ)
                    if not chunk:
                        break
                    local.write(chunk)
                    offset += len(chunk)
                    progress(offset, size, "proxmox")
            if self.os_name == "windows":
                extract_zip(Path(local.name), dest)
            else:
                with open(local.name, "rb") as f:
                    extract_tar(f, dest)
        finally:
            try:
                os.unlink(local.name)
            except (OSError, UnboundLocalError):
                pass
            self._remove(archive_path)
        return "proxmox"

    def _mkdir(self, path: str) -> None:
        if self.os_name == "windows":
            self.run(["cmd", "/c", "mkdir", path])
        else:
            self.run(["mkdir", "-p", path])

    def _remove(self, path: str) -> None:
        try:
            if self.os_name == "windows":
                self.run(["cmd", "/c", "rmdir", "/s", "/q", path] if not path.endswith(".zip")
                         else ["cmd", "/c", "del", "/f", "/q", path])
            else:
                self.run(["rm", "-rf", "--", path])
        except Exception:
            pass


def _check(st: dict, what: str) -> None:
    code = int(st.get("exitcode", 0) or 0)
    if code:
        detail = (st.get("out-data", "") + st.get("err-data", "")).strip()
        if detail.startswith("ERR "):
            detail = detail[4:]
        raise GuestError(f"{what}: {detail[:300] or f'exit code {code}'}")


# -- a container, through the host's SSH --------------------------------------------------------------

class ContainerFiles:
    """Folders and copies of a running container: `pct exec` on the host over the app's SSH key, the archive on SSH's
    own pipe (no copy left on the host)."""

    os_name = "linux"

    def __init__(self, host: str, port: int, user: str, vmid: int, ssh_cmd: str = "ssh"):
        self.host, self.port, self.user, self.vmid, self.ssh_cmd = host, port, user, int(vmid), ssh_cmd

    def _argv(self, inner: list[str]) -> list[str]:
        script = f"pct exec {self.vmid} -- " + " ".join(_sh_quote(a) for a in inner)
        argv = ssh.ssh_argv(self.host, self.port, self.user, True, tty=False)
        argv[0] = self.ssh_cmd
        argv[1:1] = ["-o", "BatchMode=yes"]
        return argv + [script]

    def home(self) -> str:
        return "/root"

    def list(self, folder: str) -> tuple[str, list[Entry]]:
        done = subprocess.run(self._argv(["sh", "-c", LINUX_LIST, "sh", b64(folder)]), capture_output=True,
                              text=True, errors="replace", timeout=60, stdin=subprocess.DEVNULL, **procs.hidden())
        if done.returncode == 255:
            raise GuestError(done.stderr.strip()[:300] or "SSH to the host failed.")
        return parse_listing(done.stdout, "linux")

    def send(self, paths: list[Path], dest: str, progress: Progress, cancel: threading.Event) -> str:
        total = total_size(paths)
        script = ('cd -- "$(printf %s "$1" | base64 -d)" || exit 4; o=$(stat -c %u:%g .); '
                  'tar -x --no-same-owner -f - || exit 5; '
                  'printf %s "$2" | base64 -d | xargs -0 -r chown -R "$o" -- 2>/dev/null; exit 0')
        proc = subprocess.Popen(self._argv(["sh", "-c", script, "sh", b64(dest), _names_b64(p.name for p in paths)]),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **procs.hidden())
        done = [0]

        def counted(n: int) -> None:
            if cancel.is_set():
                raise Cancelled()
            done[0] += n
            progress(done[0], total, "ssh")
        try:
            write_tar(paths, _Counting(proc.stdin, counted))
            proc.stdin.close()
        except (Cancelled, BrokenPipeError) as e:
            proc.kill()
            if isinstance(e, Cancelled):
                raise
        out, err = proc.communicate(timeout=600)
        if proc.returncode:
            raise GuestError((err or out).decode("utf-8", "replace").strip()[:300] or
                             f"Copying into the container failed ({proc.returncode}).")
        return "ssh"

    def receive(self, folder: str, names: list[str], dest: Path, progress: Progress, cancel: threading.Event,
                total: int | None = None) -> str:
        script = 'cd -- "$(printf %s "$1" | base64 -d)" || exit 4; printf %s "$2" | base64 -d | tar -c --null -T - -f -'
        proc = subprocess.Popen(self._argv(["sh", "-c", script, "sh", b64(folder), _names_b64(names)]),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                **procs.hidden())
        done = [0]

        class Reader(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, buf):
                if cancel.is_set():
                    raise Cancelled()
                n = proc.stdout.readinto(buf)
                if n:
                    done[0] += n
                    progress(done[0], total, "ssh")
                return n
        try:
            extract_tar(io.BufferedReader(Reader(), 1 << 20), dest)
        except Cancelled:
            proc.kill()
            raise
        err = proc.stderr.read()
        proc.wait(timeout=60)
        if proc.returncode:
            raise GuestError(err.decode("utf-8", "replace").strip()[:300] or
                             f"Copying from the container failed ({proc.returncode}).")
        return "ssh"


def _sh_quote(arg: str) -> str:
    return "'" + arg.replace("'", "'\\''") + "'"
