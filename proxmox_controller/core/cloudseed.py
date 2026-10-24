"""An Ubuntu desktop VM that sets itself up: the cloud-init disc ("cidata") the app makes for a VM from Ubuntu's cloud
image when Proxmox's own cloud-init drive is not enough.

Proxmox's drive sets the user, the password, SSH keys and the network — that is all an Ubuntu Server VM needs, and
the app keeps using it there. A desktop needs packages installed on the first start (the desktop itself, the QEMU
guest agent, Remote Desktop), which Proxmox's drive cannot ask for (only a "snippet" file on the host could, and the
API cannot write one). So for the desktop edition the app writes the whole cloud-init configuration itself, onto a
small disc of its own (core/isofs.py), with the same user settings Proxmox would write.

The password goes onto that disc only as a SHA-512 crypt hash (made here: Python no longer has the crypt module), and
the disc is taken away once the VM is set up (core/setupdisc.py).

Remote Desktop is xrdp: it signs in with the VM's own user and password (PAM), so no second password is needed and
none has to be written anywhere. Its sessions run Xfce — GNOME has no X11 session any more from Ubuntu 25.10 on, which
xrdp needs, and on 24.04 a GNOME session over xrdp fails while the same user is signed in at the console."""

from __future__ import annotations

import hashlib
import json
import secrets

SEED_LABEL = "cidata"  # the disc's name cloud-init looks for
DESKTOP_PACKAGES = ["ubuntu-desktop-minimal"]
RDP_PACKAGES = ["xrdp", "xorgxrdp", "xfce4"]
RDP_PORT = 3389
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
# colord asks for an administrator's password each time an xrdp session starts ("Authentication is required to
# create a color managed device"): allowed for the VM's administrators (its user is one)
COLORD_RULE = """polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.color-manager.") == 0 && subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
"""


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


def user_data(*, vm_name: str, user: str, password: str, ssh_keys: list[str], desktop: bool = True,
              remote_desktop: bool = False, time_zone: str = "", keyboard: str = "") -> str:
    """The cloud-config: Proxmox's own user settings (the user as the image's default user, its password, SSH keys),
    then the packages and what turns them on. Written as JSON, which is YAML too: nothing to quote by hand.
    `time_zone` (IANA) and `keyboard` (an X11 layout, after US English) come from the Proxmox host's place; the menus
    stay in English (the user's choice, 24/10)."""
    if remote_desktop and not password:
        raise ValueError("Remote Desktop needs a password: xrdp signs in with the VM user's own.")
    host = hostname_of(vm_name)
    cfg: dict = {"hostname": host, "manage_etc_hosts": True, "fqdn": vm_name, "user": user,
                 "chpasswd": {"expire": False}, "users": ["default"], "package_update": True,
                 "package_upgrade": True,  # (as Proxmox's own: the image on the host ages, the VM starts up to date)
                 "packages": ["qemu-guest-agent"] + (DESKTOP_PACKAGES if desktop else [])
                 + (RDP_PACKAGES if remote_desktop else []),
                 "runcmd": [["systemctl", "start", "qemu-guest-agent"]]}
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
        cfg["write_files"] = [{"path": "/etc/polkit-1/rules.d/45-xrdp-colord.rules", "content": COLORD_RULE,
                               "permissions": "0644"}]
        cfg["runcmd"] += [["adduser", "xrdp", "ssl-cert"],  # it reads the certificate's key
                          ["update-alternatives", "--set", "x-session-manager", "/usr/bin/xfce4-session"],
                          ["systemctl", "enable", "--now", "xrdp"]]
    if desktop:  # the login screen starts with the next boot, once everything is in
        cfg["power_state"] = {"mode": "reboot", "condition": True, "timeout": 120,
                              "message": "Proxmox Controller: the desktop is installed, restarting"}
    return "#cloud-config\n" + json.dumps(cfg, indent=2) + "\n"


def meta_data(vm_name: str, vmid: int) -> str:
    """A new instance-id per disc: cloud-init sets the VM up once for each."""
    return json.dumps({"instance-id": f"pvc-{int(vmid)}-{secrets.token_hex(4)}",
                       "local-hostname": hostname_of(vm_name)}) + "\n"
