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
import re
import secrets
import shutil
import socket
import stat
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


@dataclass
class Props:
    """What a file or folder is (Properties…). Unknown numbers are None, unknown text "", unknown times 0."""
    name: str
    kind: str                  # "file" | "folder" | "link" | "other"
    size: int = 0              # a folder: all the files it holds, at every depth
    files: int = 0             # a folder: the files and folders it holds, at every depth
    folders: int = 0
    mtime: int = 0
    atime: int = 0
    btime: int = 0             # created
    uid: int | None = None
    gid: int | None = None
    mode: int | None = None    # Linux: the permission bits (0o755, 0o4755…)
    owner: str = ""
    group: str = ""
    link: str = ""             # a link: where it points
    attributes: str = ""       # Windows: ReadOnly, Hidden, System…


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


# -- changes in the guest's folders (the right-click menu: Rename, Delete, New Folder) ------------------
# One script for a Linux VM (through the agent) and a container (through pct exec): the operation, the folder, then
# names — all base64 — and whatever goes wrong comes back base64 too ("ERRB …": a name in it may be Greek).

LINUX_OPS = r"""
cd -- "$(printf %s "$2" | base64 -d)" 2>/dev/null || { echo "ERR No such folder"; exit 4; }
fail() { printf 'ERRB %s\n' "$(printf %s "$1" | base64 | tr -d '\n')"; exit 5; }
case "$1" in
  rename)
    a=$(printf %s "$3" | base64 -d); b=$(printf %s "$4" | base64 -d)
    { [ -e "$b" ] || [ -L "$b" ]; } && { echo "ERR That name is taken in this folder"; exit 6; }
    e=$(mv -- "$a" "$b" 2>&1) || fail "$e" ;;
  delete)
    e=$(printf %s "$3" | base64 -d | xargs -0 -r rm -rf -- 2>&1) || fail "$e" ;;
  mkdir)
    n=$(printf %s "$3" | base64 -d)
    { [ -e "$n" ] || [ -L "$n" ]; } && { echo "ERR That name is taken in this folder"; exit 6; }
    o=$(stat -c %u:%g .)
    e=$(mkdir -- "$n" 2>&1) || fail "$e"
    chown "$o" -- "$n" 2>/dev/null ;;
esac
exit 0
"""

WINDOWS_OPS = r"""
$ErrorActionPreference = 'Stop'
function D([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
function E([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
$folder = D '{folder}'
if (-not (Test-Path -LiteralPath $folder -PathType Container)) { 'ERR No such folder'; exit 4 }
try {
  switch ('{op}') {
    'rename' {
      $b = D '{b}'
      if (Test-Path -LiteralPath (Join-Path $folder $b)) { 'ERR That name is taken in this folder'; exit 6 }
      Rename-Item -LiteralPath (Join-Path $folder (D '{a}')) -NewName $b
    }
    'delete' {
      foreach ($n in ((D '{a}') -split [char]0)) { Remove-Item -LiteralPath (Join-Path $folder $n) -Recurse -Force }
    }
    'mkdir' {
      $p = Join-Path $folder (D '{a}')
      if (Test-Path -LiteralPath $p) { 'ERR That name is taken in this folder'; exit 6 }
      New-Item -ItemType Directory -Path $p | Out-Null
    }
  }
} catch { 'ERRB ' + (E $_.Exception.Message); exit 5 }
"""


def local_os() -> str:
    """This computer's own system, for the names its side takes."""
    return "windows" if os.name == "nt" else "linux"


BAD_NAME = {"linux": "/", "windows": '\\/:*?"<>|'}


def check_name(os_name: str, name: str) -> str:
    """"" when `name` will do as a file's or folder's new name in that system, else what is wrong."""
    if not name.strip() or name in (".", ".."):
        return "Give it a name."
    bad = sorted({c for c in name if c in BAD_NAME[os_name] or ord(c) < 32})
    if bad:
        return "A name cannot hold " + " ".join(repr(c) for c in bad) + "."
    if os_name == "windows" and name.rstrip(" .") != name:
        return "Windows does not allow a name ending in a space or a dot."
    return ""


def ops_argv(os_name: str, op: str, folder: str, *names: str) -> list[str]:
    """The guest's command for Rename (old, new), Delete (names…) or New Folder (name) in `folder`."""
    if os_name == "windows":
        a = _names_b64(names) if op == "delete" else b64(names[0])
        b = b64(names[1]) if op == "rename" else ""
        return _ps(WINDOWS_OPS.replace("{folder}", b64(folder)).replace("{op}", op).replace("{a}", a)
                   .replace("{b}", b))
    args = [_names_b64(names)] if op == "delete" else [b64(n) for n in names]
    return ["sh", "-c", LINUX_OPS, "sh", op, b64(folder), *args]


def ops_result(code: int, out: str, err: str, what: str) -> None:
    """Raises GuestError with what the guest said, when an operation failed."""
    if not code:
        return
    for line in out.splitlines():
        if line.startswith("ERRB "):
            raise GuestError(f"{what}: {unb64(line[5:]).strip()[:300]}")
        if line.startswith("ERR "):
            raise GuestError(f"{what}: {line[4:]}")
    raise GuestError(f"{what}: {(err or out).strip()[:300] or f'exit code {code}'}")


# -- what a file or folder is (Properties…) ------------------------------------------------------------
# One line for each name: P name kind size files folders mtime atime btime uid gid mode owner group link attributes —
# the texts base64, "-" where the system does not tell it. A folder's size is that of all its files (BusyBox's find has
# no -printf: there stat tells them). "MISS name": not there (any more).

LINUX_PROPS = r"""
cd -- "$(printf %s "$1" | base64 -d)" 2>/dev/null || { echo "ERR No such folder"; exit 4; }
shift
e() { if [ -n "$1" ]; then printf %s "$1" | base64 | tr -d '\n'; else printf -; fi; }
gnu=; find . -maxdepth 0 -printf '' 2>/dev/null && gnu=1
for a in "$@"; do
  n=$(printf %s "$a" | base64 -d)
  if [ -L "$n" ]; then k=link; elif [ -d "$n" ]; then k=folder; elif [ -f "$n" ]; then k=file
  elif [ -e "$n" ]; then k=other; else echo "MISS $a"; continue; fi
  st() { v=$(stat -c "$1" -- "$n" 2>/dev/null); case "$v" in ''|*[!0-9]*) echo -;; *) echo "$v";; esac; }
  z=$(st %s); f=0; c=0; l=
  if [ "$k" = folder ]; then
    if [ -n "$gnu" ]; then
      z=$(find "./$n" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {printf "%.0f", s}')
    else
      z=$(find "./$n" -type f -exec stat -c %s -- {} + 2>/dev/null | awk '{s+=$1} END {printf "%.0f", s}')
    fi
    f=$(find "./$n" -type f 2>/dev/null | wc -l); c=$(find "./$n" -mindepth 1 -type d 2>/dev/null | wc -l)
  fi
  [ "$k" = link ] && l=$(readlink -- "$n")
  printf 'P %s %s %s %s %s %s %s %s %s %s %s %s %s %s -\n' "$a" "$k" "$z" $f $c "$(st %Y)" "$(st %X)" "$(st %W)" \
    "$(st %u)" "$(st %g)" "$(st %a)" "$(e "$(stat -c %U -- "$n" 2>/dev/null)")" \
    "$(e "$(stat -c %G -- "$n" 2>/dev/null)")" "$(e "$l")"
done
exit 0
"""

WINDOWS_PROPS = r"""
$ErrorActionPreference = 'Stop'
function D([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
function E([string]$s) { if ($s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) } else { '-' } }
$epoch = [datetime]'1970-01-01'
function T($t) { [int64](($t - $epoch).TotalSeconds) }
$folder = D '{folder}'
if (-not (Test-Path -LiteralPath $folder -PathType Container)) { 'ERR No such folder'; exit 4 }
foreach ($n in ((D '{names}') -split [char]0)) {
  try { $i = Get-Item -LiteralPath (Join-Path $folder $n) -Force } catch { 'MISS ' + (E $n); continue }
  [int64]$s = 0; $f = 0; $c = 0; $l = ''
  if ($i.LinkType) { $k = 'link'; $l = [string]($i.Target | Select-Object -First 1) }
  elseif ($i.PSIsContainer) {
    $k = 'folder'
    Get-ChildItem -LiteralPath $i.FullName -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.PSIsContainer) { $c++ } else { $f++; $s += $_.Length }
    }
  } else { $k = 'file'; $s = $i.Length }
  $o = ''; try { $o = (Get-Acl -LiteralPath $i.FullName).Owner } catch {}
  'P ' + (E $n) + " $k $s $f $c " + (T $i.LastWriteTimeUtc) + ' ' + (T $i.LastAccessTimeUtc) + ' ' +
    (T $i.CreationTimeUtc) + ' - - - ' + (E $o) + ' - ' + (E $l) + ' ' + (E ([string]$i.Attributes))
}
"""


def props_argv(os_name: str, folder: str, names: Iterable[str]) -> list[str]:
    names = list(names)
    if os_name == "windows":
        return _ps(WINDOWS_PROPS.replace("{folder}", b64(folder)).replace("{names}", _names_b64(names)))
    return ["sh", "-c", LINUX_PROPS, "sh", b64(folder), *[b64(n) for n in names]]


def parse_props(code: int, out: str, err: str) -> list[Props]:
    """The guest's answer to *_PROPS; GuestError when it failed, or when none of the names is there."""
    got, missing = [], []

    def text(v: str) -> str:
        return "" if v == "-" else unb64(v)

    def num(v: str) -> int | None:
        return int(v) if v.isdigit() else None
    for line in out.splitlines():
        f = line.strip().split(" ")
        if f[0] in ("ERR", "ERRB"):
            ops_result(code or 1, line, err, "Reading the properties failed")
        elif f[0] == "MISS" and len(f) > 1:
            missing.append(text(f[1]))
        elif f[0] == "P" and len(f) >= 16:
            got.append(Props(text(f[1]), f[2], num(f[3]) or 0, num(f[4]) or 0, num(f[5]) or 0, num(f[6]) or 0,
                             num(f[7]) or 0, num(f[8]) or 0, num(f[9]), num(f[10]),
                             int(f[11], 8) if f[11].isdigit() else None, text(f[12]), text(f[13]), text(f[14]),
                             text(f[15])))
    if not got:
        if missing:
            raise GuestError(f"{', '.join(missing)}: not there (any more).")
        ops_result(code or 1, out, err, "Reading the properties failed")
    return got


# -- who may do what (Permissions…, Linux guests): chmod and chown, on what is chosen or with what is inside ---------
# The rights go as chmod's +/- clauses ("u+rw,u-x,…"): only the bits asked for change — never setuid, setgid or the
# sticky bit. `scope`: "self" — what is chosen; "all" — and everything inside; "files" / "folders" — only the files /
# only the folders, what is chosen among them too. Links are never followed (find does not; chown -h changes the
# link itself; chmod would change what it points to, so links are left out).

LINUX_PERMS = r"""
cd -- "$(printf %s "$1" | base64 -d)" 2>/dev/null || { echo "ERR No such folder"; exit 4; }
m=$2; o=$(printf %s "$3" | base64 -d); r=$4; shift 4
fail() { printf 'ERRB %s\n' "$(printf %s "$1" | base64 | tr -d '\n')"; exit 5; }
for a in "$@"; do
  n=$(printf %s "$a" | base64 -d)
  { [ -e "$n" ] || [ -L "$n" ]; } || fail "$n: not there (any more)"
  case "$r" in
    all) t='!'; y=l;; files) t=; y=f;; folders) t=; y=d;; *) t=self;;
  esac
  if [ -n "$m" ]; then
    if [ "$t" = self ]; then [ -L "$n" ] || { e=$(chmod "$m" -- "$n" 2>&1) || fail "$e"; }
    else e=$(find "./$n" $t -type $y -exec chmod "$m" -- {} + 2>&1) || fail "$e"; fi
  fi
  if [ -n "$o" ]; then
    if [ "$t" = self ]; then e=$(chown -h -- "$o" "$n" 2>&1) || fail "$e"
    elif [ "$r" = all ]; then e=$(find "./$n" -exec chown -h -- "$o" {} + 2>&1) || fail "$e"
    else e=$(find "./$n" -type $y -exec chown -h -- "$o" {} + 2>&1) || fail "$e"; fi
  fi
done
exit 0
"""

# the guest's accounts, for the owner's and group's lists
LINUX_ACCOUNTS = r"""
printf 'PASSWD %s\n' "$(base64 < /etc/passwd | tr -d '\n')"
printf 'GROUP %s\n' "$(base64 < /etc/group | tr -d '\n')"
"""

SCOPES = ("self", "all", "files", "folders")
MODE_SPEC = re.compile(r"^([ugo][+-][rwx]{1,3})(,[ugo][+-][rwx]{1,3})*$")


def perms_argv(folder: str, names: Iterable[str], mode: str, owner: str, scope: str) -> list[str]:
    """The Linux guest's command for Permissions…: `mode` as chmod's +/- clauses (or ""), `owner` as "user:group",
    "user" or ":group" (or "")."""
    if mode and not MODE_SPEC.match(mode):
        raise ValueError(f"Not a mode for this: {mode!r}")
    if scope not in SCOPES:
        raise ValueError(f"No such scope: {scope!r}")
    return ["sh", "-c", LINUX_PERMS, "sh", b64(folder), mode, b64(owner) if owner else "", scope,
            *[b64(n) for n in names]]


def parse_accounts(out: str) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """(users, groups) as (name, number): root first, then people (1000 and up), then the system's own."""
    found: dict[str, list[tuple[str, int]]] = {"PASSWD": [], "GROUP": []}
    for line in out.splitlines():
        kind, _, data = line.strip().partition(" ")
        if kind in found and data:
            for row in unb64(data).splitlines():
                f = row.split(":")
                if len(f) > 2 and f[0] and f[2].isdigit():
                    found[kind].append((f[0], int(f[2])))

    def order(item: tuple[str, int]) -> tuple:
        n = item[1]
        return (0 if n == 0 else 1 if 1000 <= n < 65534 else 2, n, item[0])
    return sorted(found["PASSWD"], key=order), sorted(found["GROUP"], key=order)


def mode_spec(bits: dict[str, bool | None]) -> str:
    """chmod's +/- clauses from {"ur": True, "uw": False, "gx": None, …}: True adds, False takes away, None (mixed
    among what is chosen) leaves as it is."""
    out = []
    for who in "ugo":
        on = "".join(b for b in "rwx" if bits.get(who + b) is True)
        off = "".join(b for b in "rwx" if bits.get(who + b) is False)
        out += [f"{who}+{on}"] * bool(on) + [f"{who}-{off}"] * bool(off)
    return ",".join(out)


# -- an edited file back where it came from (Edit…) ---------------------------------------------------------------
# Its contents only, written into the file that is there: the file keeps its owner, its rights, its links (a fresh
# copy would take the folder owner's and this computer's). The copy goes first into a folder of its own in the
# guest's temporary folder (the usual way: network, Proxmox or SSH), then this writes it over and takes that away.

LINUX_PUTBACK = r"""
t=$(printf %s "$1" | base64 -d); n=$(printf %s "$3" | base64 -d)
fail() { rm -rf -- "$t"; printf 'ERRB %s\n' "$(printf %s "$1" | base64 | tr -d '\n')"; exit 5; }
[ -f "$t/$n" ] || fail "The copy did not arrive."
cd -- "$(printf %s "$2" | base64 -d)" 2>/dev/null || fail "No such folder"
new=; [ -e "$n" ] || new=1
e=$( { cat -- "$t/$n" > "$n"; } 2>&1 ) || fail "$e"
rm -rf -- "$t"
[ -z "$new" ] || chown "$(stat -c %u:%g .)" -- "$n" 2>/dev/null
exit 0
"""

WINDOWS_PUTBACK = r"""
$ErrorActionPreference = 'Stop'
function D([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
function E([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
$t = D '{tmp}'; $d = D '{folder}'; $n = D '{name}'; $code = 0
try {
  $src = Join-Path $t $n
  if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { 'ERR The copy did not arrive.'; $code = 6 }
  elseif (-not (Test-Path -LiteralPath $d -PathType Container)) { 'ERR No such folder'; $code = 4 }
  else {
    $in = [IO.File]::OpenRead($src)
    try {
      $out = [IO.File]::Open((Join-Path $d $n), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write)
      try { $out.SetLength(0); $in.CopyTo($out) } finally { $out.Close() }
    } finally { $in.Close() }
  }
} catch { 'ERRB ' + (E $_.Exception.Message); $code = 5 }
Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue
exit $code
"""


def putback_argv(os_name: str, tmp: str, folder: str, name: str) -> list[str]:
    if os_name == "windows":
        return _ps(WINDOWS_PUTBACK.replace("{tmp}", b64(tmp)).replace("{folder}", b64(folder))
                   .replace("{name}", b64(name)))
    return ["sh", "-c", LINUX_PUTBACK, "sh", b64(tmp), b64(folder), b64(name)]


def put_back(side, os_name: str, path: Path, folder: str, progress: Progress, cancel: threading.Event,
             finish: Callable[[list[str]], None]) -> str:
    """`path` of this computer over the file of the same name in the guest's `folder` (see LINUX_PUTBACK), through
    `side` (VmFiles or ContainerFiles); `finish` runs the guest's last command. Returns the way it went."""
    tmp_name = f"pcx-edit-{secrets.token_hex(6)}"
    side.mkdir(TEMP[os_name], tmp_name)
    tmp = join(os_name, TEMP[os_name], tmp_name)
    try:
        way = side.send([path], tmp, progress, cancel)
    except BaseException:
        try:
            side.delete(TEMP[os_name], [tmp_name])
        except Exception:  # noqa: BLE001 — what failed first is what the user is told
            pass
        raise
    finish(putback_argv(os_name, tmp, folder, path.name))
    return way


WIN_ATTRIBUTES = (("ReadOnly", 0x1), ("Hidden", 0x2), ("System", 0x4), ("Archive", 0x20), ("Compressed", 0x800),
                  ("Encrypted", 0x4000))


def local_props(folder: Path, names: Iterable[str]) -> list[Props]:
    """The same of this computer's files (Properties… on the left)."""
    out = []
    for name in names:
        p = folder / name
        st = p.lstat()
        kind = ("link" if stat.S_ISLNK(st.st_mode) else "folder" if stat.S_ISDIR(st.st_mode) else
                "file" if stat.S_ISREG(st.st_mode) else "other")
        props = Props(name, kind, 0 if kind == "folder" else st.st_size, mtime=int(st.st_mtime),
                      atime=int(st.st_atime), btime=int(getattr(st, "st_birthtime", 0) or 0))
        if kind == "folder":  # as the guest's find counts: files and folders, links neither (nor followed)
            for root, dirs, files in os.walk(p):
                props.folders += sum(not os.path.islink(os.path.join(root, d)) for d in dirs)
                for f in files:
                    try:
                        fst = os.lstat(os.path.join(root, f))
                    except OSError:
                        continue
                    if stat.S_ISREG(fst.st_mode):
                        props.size += fst.st_size
                        props.files += 1
        if kind == "link":
            props.link = os.readlink(p)
        if os.name == "posix":
            import grp
            import pwd
            props.uid, props.gid, props.mode = st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)
            try:
                props.owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                pass
            try:
                props.group = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                pass
        bits = getattr(st, "st_file_attributes", 0)
        props.attributes = ", ".join(n for n, b in WIN_ATTRIBUTES if bits & b)
        out.append(props)
    return out


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

    # -- changes (the right-click menu)
    def rename(self, folder: str, old: str, new: str) -> None:
        ops_result(*self.run(ops_argv(self.os_name, "rename", folder, old, new)), "Renaming failed")

    def delete(self, folder: str, names: list[str]) -> None:
        ops_result(*self.run(ops_argv(self.os_name, "delete", folder, *names), timeout=600), "Deleting failed")

    def mkdir(self, folder: str, name: str) -> None:
        ops_result(*self.run(ops_argv(self.os_name, "mkdir", folder, name)), "Making the folder failed")

    def properties(self, folder: str, names: list[str]) -> list[Props]:
        return parse_props(*self.run(props_argv(self.os_name, folder, names), timeout=600))  # (a folder: counted)

    def accounts(self) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
        code, out, err = self.run(["sh", "-c", LINUX_ACCOUNTS])
        return parse_accounts(out)

    def put_back(self, path: Path, folder: str, progress: Progress, cancel: threading.Event) -> str:
        """An edited file back over the one it came from: its contents only (see LINUX_PUTBACK)."""
        return put_back(self, self.os_name, path, folder, progress, cancel, lambda argv: ops_result(
            *self.run(argv, timeout=600), "Sending it back failed"))

    def set_permissions(self, folder: str, names: list[str], mode: str, owner: str, scope: str = "self") -> None:
        if self.os_name == "windows":
            raise GuestError("Permissions… is for Linux guests.")
        ops_result(*self.run(perms_argv(folder, names, mode, owner, scope), timeout=600), "Setting the permissions failed")

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

    def _op(self, op: str, folder: str, names: tuple, what: str, timeout: float = 60) -> None:
        self._exec(ops_argv("linux", op, folder, *names), what, timeout)

    def _exec(self, argv: list[str], what: str, timeout: float = 60) -> None:
        done = subprocess.run(self._argv(argv), capture_output=True, text=True, errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL, **procs.hidden())
        if done.returncode == 255:
            raise GuestError(done.stderr.strip()[:300] or "SSH to the host failed.")
        ops_result(done.returncode, done.stdout, done.stderr, what)

    def put_back(self, path: Path, folder: str, progress: Progress, cancel: threading.Event) -> str:
        """An edited file back over the one it came from: its contents only (see LINUX_PUTBACK)."""
        return put_back(self, "linux", path, folder, progress, cancel,
                        lambda argv: self._exec(argv, "Sending it back failed", 600))

    def rename(self, folder: str, old: str, new: str) -> None:
        self._op("rename", folder, (old, new), "Renaming failed")

    def delete(self, folder: str, names: list[str]) -> None:
        self._op("delete", folder, tuple(names), "Deleting failed", timeout=600)

    def mkdir(self, folder: str, name: str) -> None:
        self._op("mkdir", folder, (name,), "Making the folder failed")

    def properties(self, folder: str, names: list[str]) -> list[Props]:
        done = subprocess.run(self._argv(props_argv("linux", folder, names)), capture_output=True, text=True,
                              errors="replace", timeout=600, stdin=subprocess.DEVNULL, **procs.hidden())
        if done.returncode == 255:
            raise GuestError(done.stderr.strip()[:300] or "SSH to the host failed.")
        return parse_props(done.returncode, done.stdout, done.stderr)

    def accounts(self) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
        done = subprocess.run(self._argv(["sh", "-c", LINUX_ACCOUNTS]), capture_output=True, text=True,
                              errors="replace", timeout=60, stdin=subprocess.DEVNULL, **procs.hidden())
        if done.returncode == 255:
            raise GuestError(done.stderr.strip()[:300] or "SSH to the host failed.")
        return parse_accounts(done.stdout)

    def set_permissions(self, folder: str, names: list[str], mode: str, owner: str, scope: str = "self") -> None:
        self._exec(perms_argv(folder, names, mode, owner, scope), "Setting the permissions failed", 600)

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
        with proc:  # (its pipes closed whatever happens)
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
