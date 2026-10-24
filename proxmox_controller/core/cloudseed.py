"""An Ubuntu desktop VM that sets itself up: the cloud-init disc ("cidata") the app makes for a VM from Ubuntu's cloud
image when Proxmox's own cloud-init drive is not enough.

Proxmox's drive sets the user, the password, SSH keys and the network — that is all an Ubuntu Server VM needs, and
the app keeps using it there. A desktop needs packages installed on the first start (the desktop itself, the QEMU
guest agent), which Proxmox's drive cannot ask for (only a "snippet" file on the host could, and the API cannot write
one). So for the desktop edition the app writes the whole cloud-init configuration itself, onto a small disc of its
own (core/isofs.py), with the same user settings Proxmox would write.

The user's password goes into that configuration only as a SHA-512 crypt hash (made here: Python no longer has the
crypt module), and the disc is taken away once the VM is set up (core/setupdisc.py).

Remote Desktop is Ubuntu's own: GNOME Remote Desktop's Remote Login, which shows the Ubuntu desktop itself over RDP,
with its sound (the user's choice, 24/10, after xrdp's Xfce session turned out light, silent and plain). It needs the
password itself, not a hash, so that goes on the disc as a file of its own (rdp-password) beside user-data: cloud-init
keeps copies of user-data inside the VM, never of other files. On the first boot it is copied into memory (/run),
handed to grdctl on its standard input and removed; it is never written to the VM's disk. Measured on Ubuntu 26.04
(24/10): the credentials must be set before the RDP backend is enabled — the service reads them when it starts."""

from __future__ import annotations

import hashlib
import json
import secrets
import shlex

SEED_LABEL = "cidata"  # the disc's name cloud-init looks for
DESKTOP_PACKAGES = ["ubuntu-desktop-minimal"]
RDP_PACKAGES = ["gnome-remote-desktop", "openssl"]  # (the desktop recommends both: named so they are there)
DARK_PACKAGES = ["dconf-cli"]
RDP_PORT = 3389
RDP_PASSWORD_FILE = "rdp-password"  # on the disc, beside user-data
RDP_PASSWORD_RUN = "/run/pvc-rdp-password"  # in memory, for the first boot only
GRD_HOME = "/var/lib/gnome-remote-desktop"  # (the package makes its user and this folder)
STATE_DIR = "/var/lib/proxmox-controller"
RDP_DONE = f"{STATE_DIR}/rdp-done"  # once there, later boots leave the password on the disc
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
# Dark as the default for every user (each can still change it): a system dconf database under the user's own
DCONF_PROFILE = "user-db:user\nsystem-db:local\n"
DARK_DEFAULTS = "[org/gnome/desktop/interface]\ncolor-scheme='prefer-dark'\ngtk-theme='Yaru-dark'\n"


def sha512_crypt(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    """"$6$salt$hash" as glibc's crypt() makes it (Ulrich Drepper's SHA-crypt), for /etc/shadow."""
    if salt is None:
        salt = "".join(secrets.choice(_B64) for _ in range(16))
    p, s = password.encode("utf-8"), salt.encode("ascii")[:16]
    b = hashlib.sha512(p + s + p).digest()
    a = hashlib.sha512(p + s)
    n = len(p)
    while n > 64:
        a.update(b)
        n -= 64
    a.update(b[:n])
    n = len(p)
    while n:
        a.update(b if n & 1 else p)
        n >>= 1
    c = a.digest()
    dp = hashlib.sha512(p * len(p)).digest()
    p_seq = (dp * (len(p) // 64 + 1))[:len(p)]
    ds = hashlib.sha512(s * (16 + c[0])).digest()
    s_seq = (ds * (len(s) // 64 + 1))[:len(s)]
    for i in range(rounds):
        h = hashlib.sha512(p_seq if i & 1 else c)
        if i % 3:
            h.update(s_seq)
        if i % 7:
            h.update(p_seq)
        h.update(c if i & 1 else p_seq)
        c = h.digest()
    out = ""
    for i in range(21):  # the bytes in glibc's order: (0, 21, 42), (22, 43, 1), (44, 2, 23), …
        t = (i, i + 21, i + 42)
        b2, b1, b0 = t[i % 3:] + t[:i % 3]
        w = (c[b2] << 16) | (c[b1] << 8) | c[b0]
        for _ in range(4):
            out += _B64[w & 63]
            w >>= 6
    w = c[63]
    for _ in range(2):
        out += _B64[w & 63]
        w >>= 6
    head = "$6$" + (f"rounds={rounds}$" if rounds != 5000 else "")
    return f"{head}{s.decode()}${out}"


def hostname_of(vm_name: str) -> str:
    return vm_name.split(".")[0]


def _rdp_commands(host: str, user: str) -> tuple[list, list]:
    """bootcmd (every boot, before the user exists) and runcmd (once, after the packages) for Remote Desktop."""
    fetch = (f"if [ ! -e {RDP_DONE} ]; then mkdir -p /run/pvc-seed && mount -o ro -L {SEED_LABEL} /run/pvc-seed && "
             f"install -m 600 /run/pvc-seed/{RDP_PASSWORD_FILE} {RDP_PASSWORD_RUN}; umount /run/pvc-seed; "
             "rmdir /run/pvc-seed; fi; true")  # (no disc any more, or no file: nothing to do)
    key, cert = f"{GRD_HOME}/rdp-tls.key", f"{GRD_HOME}/rdp-tls.crt"
    grd = ["grdctl", "--system", "rdp"]
    run = [["runuser", "-u", "gnome-remote-desktop", "--", "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
            "-days", "3650", "-subj", f"/CN={host}", "-keyout", key, "-out", cert],
           grd + ["set-tls-key", key], grd + ["set-tls-cert", cert],
           ["sh", "-c", f"{shlex.join(grd + ['set-credentials', user])} < {RDP_PASSWORD_RUN}; rm -f {RDP_PASSWORD_RUN}"],
           grd + ["enable"],  # (only now: it starts the service, which reads the credentials when it starts)
           ["systemctl", "enable", "gnome-remote-desktop.service"],
           ["sh", "-c", f"mkdir -p {STATE_DIR} && touch {RDP_DONE}"]]
    return [fetch], run


def user_data(*, vm_name: str, user: str, password: str, ssh_keys: list[str], desktop: bool = True,
              remote_desktop: bool = False, dark: bool = False, time_zone: str = "", keyboard: str = "") -> str:
    """The cloud-config: Proxmox's own user settings (the user as the image's default user, its password, SSH keys),
    then the packages and what turns them on. Written as JSON, which is YAML too: nothing to quote by hand.
    `time_zone` (IANA) and `keyboard` (an X11 layout, after US English) come from the Proxmox host's place; the menus
    stay in English (the user's choice, 24/10). Remote Desktop also needs the rdp-password file (see seed_files)."""
    if remote_desktop and not password:
        raise ValueError("Remote Desktop needs a password: it signs in with the VM user's own.")
    host = hostname_of(vm_name)
    packages = (["qemu-guest-agent"] + (DESKTOP_PACKAGES if desktop else []) + (RDP_PACKAGES if remote_desktop else [])
                + (DARK_PACKAGES if dark else []))
    cfg: dict = {"hostname": host, "manage_etc_hosts": True, "fqdn": vm_name,
                 "user": {"name": user, "gecos": user},  # (else the login screen calls the user "Ubuntu")
                 "chpasswd": {"expire": False}, "users": ["default"], "package_update": True,
                 "package_upgrade": True,  # (as Proxmox's own: the image on the host ages, the VM starts up to date)
                 "packages": packages, "runcmd": []}
    if password:
        cfg["password"] = sha512_crypt(password)
    if time_zone:
        cfg["timezone"] = time_zone
    if keyboard and keyboard != "us":
        cfg["keyboard"] = {"layout": f"us,{keyboard}", "options": "grp:alt_shift_toggle"}
    keys = [k.strip() for k in ssh_keys if k.strip()]
    if keys:
        cfg["ssh_authorized_keys"] = keys
    if remote_desktop:
        cfg["bootcmd"], rdp = _rdp_commands(host, user)
        cfg["runcmd"] += rdp
    if dark:
        cfg["write_files"] = [{"path": "/etc/dconf/profile/user", "content": DCONF_PROFILE, "permissions": "0644"},
                              {"path": "/etc/dconf/db/local.d/00-proxmox-controller", "content": DARK_DEFAULTS,
                               "permissions": "0644"}]
        cfg["runcmd"].append(["dconf", "update"])
    if desktop:
        # no "Welcome" wizard on the first sign-in: it is all set already, and it kept asking for the password
        home = f"/home/{user}"
        cfg["runcmd"].append(["runuser", "-u", user, "--", "sh", "-c", f"mkdir -p {home}/.config && "
                              f"printf yes > {home}/.config/gnome-initial-setup-done"])
        # the login screen starts with the next boot, once everything is in
        cfg["power_state"] = {"mode": "reboot", "condition": True, "timeout": 120,
                              "message": "Proxmox Controller: the desktop is installed, restarting"}
    cfg["runcmd"].append(["systemctl", "start", "qemu-guest-agent"])  # last: the app reads it as "set up"
    return "#cloud-config\n" + json.dumps(cfg, indent=2) + "\n"


def meta_data(vm_name: str, vmid: int) -> str:
    """A new instance-id per disc: cloud-init sets the VM up once for each."""
    return json.dumps({"instance-id": f"pvc-{int(vmid)}-{secrets.token_hex(4)}",
                       "local-hostname": hostname_of(vm_name)}) + "\n"


def seed_files(*, vm_name: str, vmid: int, user: str, password: str, ssh_keys: list[str], remote_desktop: bool = False,
               dark: bool = False, time_zone: str = "", keyboard: str = "") -> dict[str, bytes]:
    """The setup disc's files for an Ubuntu Desktop VM."""
    files = {"user-data": user_data(vm_name=vm_name, user=user, password=password, ssh_keys=ssh_keys,
                                    remote_desktop=remote_desktop, dark=dark, time_zone=time_zone,
                                    keyboard=keyboard).encode(),
             "meta-data": meta_data(vm_name, vmid).encode()}
    if remote_desktop:
        files[RDP_PASSWORD_FILE] = (password + "\n").encode()
    return files
