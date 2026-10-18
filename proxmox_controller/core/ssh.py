"""SSH to a host, for what Proxmox keeps for root's own login: the host's shell and its upgrade. The API cannot open
them with a token (Proxmox checks the user name, and a token's — root@pam!controller — is refused; the upgrade wants
root@pam itself), so the app opens the computer's own terminal with ssh in it.

Everything here is the app's own, beside its settings — its key, and the host keys the user confirmed — so the
user's ~/.ssh is never touched. A key, when the user wants one, is added beside root's password: the host's SSH
settings are never changed, and the password keeps working. Plain Python: no window is involved.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from . import store

WINDOWS = sys.platform.startswith("win")
KEY_FILE = "id_ed25519"
KNOWN_HOSTS = "known_hosts"
SSH_TIMEOUT_S = 20
HOST_KEY_ORDER = ("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "ssh-rsa")
TERMINALS = (  # the first one found opens the window: (program, how it is given a title, how a command)
    ("ptyxis", ["-T"], ["--"]), ("gnome-terminal", [], ["--"]), ("kgx", [], ["--"]), ("konsole", [], ["-e"]),
    ("xfce4-terminal", ["--title"], ["-x"]), ("x-terminal-emulator", [], ["-e"]), ("xterm", ["-T"], ["-e"]))
CLOSE_PROMPT = "Press Enter to close this window."


class SshError(Exception):
    pass


def ssh_dir() -> Path:
    path = store.config_dir() / "ssh"
    path.mkdir(parents=True, exist_ok=True)
    if not sys.platform.startswith("win"):
        os.chmod(path, 0o700)
    return path


def key_path() -> Path:
    return ssh_dir() / KEY_FILE


def known_hosts_path() -> Path:
    return ssh_dir() / KNOWN_HOSTS


def missing_tools() -> list[str]:
    """The OpenSSH programs this needs that the computer lacks (Ubuntu: openssh-client)."""
    return [t for t in ("ssh", "ssh-keygen", "ssh-keyscan") if shutil.which(t) is None]


def install_hint(platform: str = sys.platform) -> str:
    if platform.startswith("win"):  # Windows 10 and 11 bring it; it can be taken out
        return "Windows: Settings → System → Optional features → OpenSSH Client"
    return "Ubuntu: sudo apt install openssh-client"


# -- the app's key ---------------------------------------------------------------------------------

def ensure_key() -> str:
    """The app's public key line, made the first time (ed25519, no passphrase: it is used unattended)."""
    path = key_path()
    if not path.exists():
        comment = f"proxmox-controller@{socket.gethostname() or 'computer'}"
        done = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
                              capture_output=True, text=True, timeout=30)
        if done.returncode != 0 or not path.exists():
            raise SshError(f"ssh-keygen could not make the key: {done.stderr.strip() or done.returncode}")
        if not sys.platform.startswith("win"):
            os.chmod(path, 0o600)
    return public_line()


def public_line() -> str:
    return Path(str(key_path()) + ".pub").read_text().strip()


def key_body(line: str) -> str:
    """'ssh-ed25519 AAAA… comment' → 'AAAA…': what finds the key in a file whatever its comment."""
    parts = line.split()
    return parts[1] if len(parts) > 1 else ""


def fingerprint(key_type_and_blob: str) -> str:
    """'ssh-ed25519 AAAA…' → 'SHA256:…', as ssh-keygen -l and ssh itself show it."""
    blob = base64.b64decode(key_body(key_type_and_blob) + "==")
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# -- the host's key --------------------------------------------------------------------------------

def known_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def scan_host_key(host: str, port: int = 22, timeout: int = 8) -> str:
    """The host's own key as 'type base64', to show the user before trusting it (as ssh asks the first time)."""
    done = subprocess.run(["ssh-keyscan", "-T", str(timeout), "-p", str(port), "-t", "ed25519,ecdsa,rsa", host],
                          capture_output=True, text=True, timeout=timeout + 10)
    found = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            found[parts[1]] = f"{parts[1]} {parts[2]}"
    for kind in HOST_KEY_ORDER:
        if kind in found:
            return found[kind]
    if found:
        return next(iter(found.values()))
    raise SshError(f"{host}:{port} did not answer as an SSH server" +
                   (f": {done.stderr.strip().splitlines()[-1]}" if done.stderr.strip() else "."))


def trusted_host_key(host: str, port: int = 22) -> str:
    """The host key the user confirmed, or ''."""
    path, name = known_hosts_path(), known_name(host, port)
    if not path.exists():
        return ""
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == name:
            return f"{parts[1]} {parts[2]}"
    return ""


def trust_host_key(host: str, port: int, key: str) -> None:
    """Keeps the confirmed host key (it replaces an earlier one of the same host)."""
    path, name = known_hosts_path(), known_name(host, port)
    lines = [ln for ln in (path.read_text().splitlines() if path.exists() else []) if ln.split()[:1] != [name]]
    lines.append(f"{name} {key}")
    path.write_text("\n".join(lines) + "\n")
    if not sys.platform.startswith("win"):
        os.chmod(path, 0o600)


# -- commands --------------------------------------------------------------------------------------

def ssh_argv(host: str, port: int, user: str, use_key: bool, command: list[str] | tuple = (),
             tty: bool = True) -> list[str]:
    """ssh with the app's own known hosts (strict: the confirmed key or nothing) — and the app's key, alone, when
    one is set up. Without one, ssh asks for the password in the terminal."""
    argv = ["ssh"] + (["-t"] if tty else []) + [
        "-p", str(port), "-o", f'UserKnownHostsFile="{known_hosts_path()}"',  # (quoted: ssh splits it at spaces)
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10"]
    if use_key:
        argv += ["-i", str(key_path()), "-o", "IdentitiesOnly=yes"]
    return argv + [f"{user}@{host}"] + list(command)


def install_key_script(line: str) -> str:
    """Adds the key to root's authorized keys once. On Proxmox ~/.ssh/authorized_keys is a link to
    /etc/pve/priv/authorized_keys (shared by the cluster): appending writes through it and leaves the link."""
    body, quoted = key_body(line), "'" + line.replace("'", "'\\''") + "'"
    return ("umask 077; mkdir -p ~/.ssh; f=~/.ssh/authorized_keys; touch \"$f\"; "
            f"grep -qF '{body}' \"$f\" || printf '%s\\n' {quoted} >> \"$f\"")


def remove_key_script(line: str) -> str:
    """Takes the key out again. Written back through the link (cat >), never replaced by a new file (sed -i would
    turn Proxmox's link into a plain file and cut it off from the cluster's keys)."""
    body = key_body(line)
    return ("f=~/.ssh/authorized_keys; [ -e \"$f\" ] || exit 0; t=$(mktemp) || exit 1; "
            f"grep -vF '{body}' \"$f\" > \"$t\"; cat \"$t\" > \"$f\"; rm -f \"$t\"")


def _askpass_helper() -> Path:
    """A tiny program ssh runs to get the password (SSH_ASKPASS): it prints what the app put in its environment for
    that one ssh run. Nothing is written to a file. On Windows (whose OpenSSH runs a .cmd for it, measured with
    9.5p2) it hands that to this app's own program with --askpass: cmd's echo would mangle & | ^ % and the like."""
    if WINDOWS:
        from .claude_connect import bridge_command
        path = ssh_dir() / "askpass.cmd"
        path.write_text("@" + cmd_line([*bridge_command(), "--askpass"]) + "\r\n", encoding="utf-8",
                        newline="")  # (as written: text mode on Windows would turn \r\n into \r\r\n)
        return path
    path = ssh_dir() / "askpass.sh"
    path.write_text("#!/bin/sh\nprintf '%s\\n' \"$PROXMOX_CONTROLLER_SSH_SECRET\"\n")
    os.chmod(path, 0o700)
    return path


def askpass_answer(env=os.environ) -> str:
    """What `--askpass` prints (Windows): the password the app put in ssh's environment for that one run."""
    return env.get("PROXMOX_CONTROLLER_SSH_SECRET", "") + "\n"


def run_with_password(host: str, port: int, user: str, password: str, script: str,
                      ssh: str = "ssh", timeout: int = SSH_TIMEOUT_S) -> str:
    """Runs a shell line on the host, logging in with the password the user typed in the app's window (once, never
    kept). Only the password is tried — no keys — so a wrong one is one failed login, not several."""
    env = {k: v for k, v in os.environ.items() if k != "DESKTOP_STARTUP_ID"}
    env.update(SSH_ASKPASS=str(_askpass_helper()), SSH_ASKPASS_REQUIRE="force",  # (force: no DISPLAY needed)
               PROXMOX_CONTROLLER_SSH_SECRET=password)
    argv = ssh_argv(host, port, user, False, tty=False)
    argv[0] = ssh
    argv[1:1] = ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
                 "-o", "NumberOfPasswordPrompts=1", "-o", "BatchMode=no"]
    argv.append(script)
    try:
        done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SshError(f"{host} did not answer within {timeout} s.") from e
    finally:
        env.pop("PROXMOX_CONTROLLER_SSH_SECRET", None)
    if done.returncode != 0:
        raise SshError(_explain(done.stderr))
    return done.stdout


def run_with_key(host: str, port: int, user: str, script: str, ssh: str = "ssh",
                 timeout: int = SSH_TIMEOUT_S) -> str:
    argv = ssh_argv(host, port, user, True, tty=False)
    argv[0] = ssh
    argv[1:1] = ["-o", "BatchMode=yes"]
    argv.append(script)
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SshError(f"{host} did not answer within {timeout} s.") from e
    if done.returncode != 0:
        raise SshError(_explain(done.stderr))
    return done.stdout


def run_command(host: str, port: int, user: str, script: str, ssh: str = "ssh",
                timeout: int = SSH_TIMEOUT_S, input: str | None = None) -> tuple[int, str, str]:
    """A shell line on the host with the app's key: (exit code, output, errors) whatever the command's exit code —
    only ssh's own failures raise (it exits 255: no answer, the key refused, the host key changed). `input` is the
    command's standard input: the way to hand it a password, which on the command line `ps` would show on both
    computers."""
    argv = ssh_argv(host, port, user, True, tty=False)
    argv[0] = ssh
    argv[1:1] = ["-o", "BatchMode=yes"]
    argv.append(script)
    given = {"stdin": subprocess.DEVNULL} if input is None else {"input": input}
    try:
        done = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, **given)
    except subprocess.TimeoutExpired as e:
        raise SshError(f"The command did not finish within {timeout} s (it was stopped here; on {host} it may "
                       "still be running).") from e
    if done.returncode == 255:
        raise SshError(_explain(done.stderr))
    return done.returncode, done.stdout, done.stderr


def _explain(stderr: str) -> str:
    text = stderr.strip()
    if "Permission denied" in text:
        return "The host did not accept the password (or the user name)."
    if "Not allowed at this time" in text:
        return ("The host refuses SSH from this computer for a few minutes after failed logins (OpenSSH's "
                "PerSourcePenalties). Try again later.")
    if "Host key verification failed" in text or "REMOTE HOST IDENTIFICATION HAS CHANGED" in text:
        return ("The host's key is not the one confirmed before. If the host was reinstalled, confirm its new key "
                "in its SSH settings (Edit…).")
    return text.splitlines()[-1] if text else "ssh failed."


# -- the terminal window ---------------------------------------------------------------------------

def cmd_line(args: list[str]) -> str:
    """A command line for a .cmd file: every argument quoted (so cmd reads & | < > ^ in it as text) the way Windows
    programs split their arguments, and % doubled (cmd would expand it)."""
    out = []
    for arg in args:
        quoted = subprocess.list2cmdline([arg])
        if not quoted.startswith('"'):
            bare = quoted.rstrip("\\")
            quoted = '"' + bare + "\\" * (2 * (len(quoted) - len(bare))) + '"'  # trailing \ doubled before the quote
        out.append(quoted.replace("%", "%%"))
    return " ".join(out)


def windows_console_script(inner: list[str], title: str) -> str:
    """Windows: a .cmd that titles its window, runs `inner` and waits for Enter. In UTF-8 (chcp 65001), so a host's
    name in Greek, say, comes out right in the title."""
    def safe(text: str) -> str:  # (title's text is not quoted: cmd's own characters are taken out of it)
        return "".join(" " if ch in '&|<>^%"' else ch for ch in text)
    return ("@echo off\r\nchcp 65001 >nul\r\n"
            f"title {safe(title)}\r\n"
            f"{cmd_line(inner)}\r\n"
            f'echo.\r\nset /p "_={CLOSE_PROMPT}"\r\n')


def terminal_argv(inner: list[str], title: str = "Proxmox Console", which=shutil.which) -> list[str]:
    """The computer's terminal running `inner`, then waiting for Enter — so what ssh said (a refused password, the
    end of an upgrade) stays on the screen. The window is titled `title` — by the terminal's own option where it has
    one, and by the terminals' common escape sequence otherwise (it showed "sh", the wrapper's name)."""
    if WINDOWS:
        raise SshError("On Windows the console window opens through open_terminal().")
    keep_open = ["sh", "-c", 'printf "\\033]0;%s\\007" "$1"; shift; "$@"; echo; '
                 f'printf "%s" "{CLOSE_PROMPT}"; read _', "sh", title, *inner]
    for program, titled, how in TERMINALS:
        if which(program):
            return [program, *([*titled, title] if titled else []), *how, *keep_open]
    raise SshError("No terminal program was found (" + ", ".join(t[0] for t in TERMINALS) + ").")


def open_terminal(inner: list[str], title: str = "Proxmox Console") -> None:
    if WINDOWS:  # a console window of its own — on Windows 11 its default terminal (Windows Terminal) opens it
        script = ssh_dir() / "console.cmd"
        script.write_text(windows_console_script(inner, title), encoding="utf-8", newline="")
        subprocess.Popen(["cmd.exe", "/c", str(script)], creationflags=subprocess.CREATE_NEW_CONSOLE,
                         cwd=tempfile.gettempdir())
        return
    env = {k: v for k, v in os.environ.items() if k != "DESKTOP_STARTUP_ID"}  # (the app's own launch, not this)
    subprocess.Popen(terminal_argv(inner, title), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, cwd=tempfile.gettempdir())
