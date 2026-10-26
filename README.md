# Claude Proxmox Controller

**Your Proxmox VE hosts in one window — and Claude, working on them as far as you let it.**

Proxmox Controller is a desktop app for Windows and Linux. On its own it is a fast home for your hosts: containers
and virtual machines, consoles, files, snapshots, backups and graphs, without a browser or a web login. The magic is
**Claude Access**: Claude (Anthropic's AI) can look after your hosts — start and stop guests, create VMs that set
themselves up, read logs, run commands inside guests, copy files — through switches you set for each host and
requests you approve in a window of the app. You stay in charge of every step.

*by the mechanic — built together with Claude*

---

## Claude Access: AI on your servers, safely

Claude reaches your hosts only through this app, and only as far as each host's switches allow:

| Switch | What it opens | Default |
|---|---|---|
| Read | state, addresses, settings, snapshots, backups, tasks, graphs | On |
| Power | start, shut down, stop, reboot, wake | Ask |
| Change | new guests, settings, snapshots, backups | Ask |
| Destroy | deleting guests, snapshots, backups | Ask |
| Host | the host's own power | Ask |
| Console | the guest's screen: screenshots, keys, clicks | Ask |
| Commands | commands inside guests (QEMU guest agent) | Ask |
| Files | copying files to and from guests | Off |
| Host commands | shell commands on the Proxmox host (SSH) | Ask |

Each switch is **Off** (refused), **Ask** (a window asks you: *Allow*, *Allow this kind for an hour*, or *Deny*) or
**On**. The approval window wears yellow-and-black warning stripes, so it is never lost among other windows.
Claude never sees a password: where one is needed, the app asks **you** for it in its own window. Every request is
logged with the reason Claude gave. Claude's token on each host holds only the Proxmox privileges its open switches
need. The full list of tools is in [docs/claude-access.md](docs/claude-access.md).

It works with Claude Desktop and Claude Code (the app connects them for you).

## Without AI

Everything works without Claude too:

- **Hosts** — one or many, with Wake-on-LAN, the host's console and upgrade, and its CPU, memory and storage.
- **Guests** — start, shut down, stop, reboot, many at once; notes, tags, boot order; edit cores, memory, disks,
  display, sound and USB devices.
- **Consoles** — a built-in one (with **Paste…**: text typed into the guest key by key, even in an installer), or
  SPICE through virt-viewer for sound, clipboard and USB.
- **Files** — this computer on one side, a VM or container on the other: send, receive, drag, and a right-click menu
  with Rename, Delete, Properties, Permissions and **Edit** (open a guest's file in your own editor, save, send back).
- **New VMs that set themselves up** — Windows 11 with no setup questions; ready-made Ubuntu Desktop (with Remote
  Desktop) or Server in minutes; Ubuntu Server from its ISO, installing itself; a static IP if you want one.
- **Install Guest Agent** — for VMs that lack it, typed into their console for you.
- **Snapshots, backups, scheduled backup jobs, graphs.**
- **Updates** — a striped tab tells you when a new version is out; one click installs it.

## Install

- **Windows 10/11** — download the setup from [themechanic.store/controller](https://themechanic.store/controller)
  and run it. It installs for your user and offers to add virt-viewer (the SPICE console).
- **Ubuntu / Debian** — download the `.deb` from the same page and open it, or install from the terminal (the
  package brings virt-viewer with it):

  ```bash
  sudo apt install ./proxmox-controller_1.0.0_amd64.deb
  ```

- **Ubuntu / Debian, from its apt repository** — it then updates with the rest of the system:

  ```bash
  wget -qO- https://themechanic.store/apt-controller/proxmox-controller.gpg | sudo tee /usr/share/keyrings/proxmox-controller.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/proxmox-controller.gpg] https://themechanic.store/apt-controller ./" | sudo tee /etc/apt/sources.list.d/proxmox-controller.list
  sudo apt update && sudo apt install proxmox-controller
  ```

  The package is built on Ubuntu 24.04 and runs there and on newer releases (tested on Ubuntu Desktop 26.04).

Each host needs a Proxmox API token (Help in the app shows how to make one).

## From the source

Linux, Python 3.12+:

```bash
./install.sh
```

The tests: `.venv/bin/python -I tools/run_tests.py`. The packages: `packaging/windows/build.py` (on Windows, with
PyInstaller and Inno Setup) and `packaging/linux/build_deb.py` (on Ubuntu 24.04, with PyInstaller and dpkg-deb).

## License

[MIT](LICENSE) — the code is open for anyone to read, use and build on.
