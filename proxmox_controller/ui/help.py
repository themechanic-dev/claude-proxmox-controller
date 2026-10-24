"""The Help window: one section per feature, in English (Qt rich text)."""

from __future__ import annotations

import html

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QScrollArea, QVBoxLayout, QWidget

from .. import APP_NAME
from ..core import connector_tools
from .widgets import card, label

def switch_table_html() -> str:
    """Every switch and every tool under it, made from the connector's own list (connector_tools.access_table), so
    this page can never say something the code does not do."""
    parts = ["Each switch, what it lets Claude do on a host, and every tool under it. A new host starts with the "
             "switches shown as default; you change them for each host in <b>☰ → Claude Access…</b>"]
    for row in connector_tools.access_table():
        tools = "".join(
            f"<br>&nbsp;&nbsp;• <tt>{html.escape(t['name'])}</tt> — {html.escape(t['does'])}"
            + (f" <i>({html.escape('; '.join(t['notes']))})</i>" if t["notes"] else "") for t in row["tools"])
        parts.append(f"<b>{html.escape(row['title'])}</b> (default: {row['default'].capitalize()}) — "
                     f"{html.escape(row['covers'])}.<br>&nbsp;&nbsp;<i>{html.escape(row['enforced'])}</i>{tools}")
    return "<br><br>".join(parts)


SECTIONS = [
    ("What this app does",
     "Proxmox Controller looks after one or more <b>Proxmox VE</b> hosts — a real server or an ordinary PC "
     "that runs Proxmox. For each host you see its CPU, memory, disks and every container and virtual machine; "
     "you can start, shut down and restart them, create and edit containers, take snapshots, open a console "
     "and see graphs. Hosts that support <b>Wake-on-LAN</b> can be turned on from the app."),
    ("Adding a host",
     "Open the <b>☰</b> menu (top right) → <b>Hosts and Settings…</b> → <b>Add Host…</b> — the very first host "
     "can also be added from the start page. Fill in:<br>"
     "• <b>Address</b> — the IP or name of the Proxmox host (the web interface's port 8006 is assumed).<br>"
     "• <b>API token</b> — in the Proxmox web UI: <i>Datacenter → Permissions → API Tokens → Add</i>, user "
     "<i>root@pam</i>, a Token ID such as <i>controller</i>, and untick <i>Privilege Separation</i>. "
     "Copy the Token ID (like <i>root@pam!controller</i>) and the secret, which Proxmox shows only once.<br>"
     "• <b>Certificate</b> — press <b>Get Certificate</b> and compare the fingerprint with the one in "
     "<i>&lt;node&gt; → System → Certificates</i> (pve-ssl.pem). Proxmox uses its own certificate; checking it "
     "once makes sure the app only ever talks to <i>your</i> server, and it refuses to send the token if the "
     "certificate ever changes."),
    ("More than one host",
     "The window shows one host at a time, so a single server gets all the room. With two or more hosts the "
     "<b>☰</b> menu lists them: pick one, or press <b>Ctrl+1</b> … <b>Ctrl+9</b>. Adding, editing and removing "
     "hosts is in <b>Hosts and Settings…</b>; removing one only forgets it here — nothing changes on the host."),
    ("Storage",
     "Under CPU, Memory, System disk and Uptime, every storage of the host has a card of its own: how much is "
     "used, of how much, and the percentage, with a bar that turns yellow from 75 % and red from 90 %. Up to four "
     "sit side by side, all the same width; more go on to the next row. Point at one to see what it holds and how "
     "much is free. A storage that does not answer (a NAS that is off) says <i>Not available</i>, one switched off "
     "in Proxmox <i>Disabled</i>. In a cluster, storage the nodes share (a NAS, Ceph) shows once, each node's own "
     "with the node's name."),
    ("Containers and virtual machines",
     "Select one in the list (or right-click it):<br>"
     "• <b>Start</b> · <b>Shut Down</b> (clean, from inside) · <b>Stop</b> (at once, like pulling the plug — "
     "only when Shut Down does not work) · <b>Reboot</b>.<br>"
     "• <b>Console</b> — a click opens the kind chosen in Settings; the arrow next to it offers every kind:<br>"
     "&nbsp;&nbsp;– <b>SPICE</b> opens remote-viewer (package virt-viewer) with sound, a shared clipboard and USB "
     "devices; the VM needs a SPICE display (Proxmox: Hardware → Display) and, for sound, an audio device with the "
     "SPICE driver.<br>"
     "&nbsp;&nbsp;– <b>Built-in console</b> shows the screen in a window of this app, for VMs and containers alike, "
     "with nothing to set up and no web login. <b>Ctrl+Alt+Del</b> is a button there.<br>"
     "&nbsp;&nbsp;– <b>In the browser</b> opens Proxmox's own console; it needs you to be logged in to the Proxmox "
     "web interface in that browser (otherwise it says “401: No ticket”).<br>"
     "• <b>Files</b> — this computer on the left, the guest on the right: choose on one side and press "
     "<b>Send →</b> or <b>← Receive</b>, or drag from one side to the other (files from the desktop's file manager "
     "can be dropped on the guest's side too). Folders go whole, with names and times. A VM copies over the network "
     "when it can reach this computer (fast) and through Proxmox's guest agent otherwise (slow, about 1 MB/s); it "
     "needs the QEMU guest agent. A container goes over the host's SSH with this app's key. On Linux what arrives "
     "belongs to the owner of the folder it lands in.<br>"
     "• <b>Install Guest Agent</b> — a button of the row, for a running VM whose agent does not answer (Files "
     "offers it too, and so does right-click): the app turns the agent on in the VM's settings and types the installation into the VM's "
     "console — on Linux sudo's password is typed by you in its window; on Windows it puts the VirtIO drivers disc "
     "in (downloading it onto the host if needed) and you press Yes on Windows' question from its window. A VM that "
     "had the agent off needs one restart (a button there). The console must be signed in, with the English (US) "
     "keyboard; a live picture of it is in the window.<br>"
     "• <b>Edit</b> — CPU cores, memory, swap, disk size (it can only grow), network, start with the host, "
     "notes; for VMs also the display, the sound card and USB devices. A running VM gets new USB devices at once; "
     "a new display or sound card at its next start (Reboot here — a restart inside the VM is not enough).<br>"
     "• <b>Notes</b> — the guest's notes, the same as in Proxmox (Summary → Notes). Write on the left and see "
     "them on the right as Proxmox shows them (Markdown: # titles, - lists, **bold**, links). <b>Ctrl+S</b> saves "
     "and keeps the window open; it can stay open beside the main window. Point at a name in the list to read its "
     "notes.<br>"
     "• <b>Graphs</b> — CPU and memory over the last hour, day, week or month, as kept by Proxmox. Each opens in a "
     "window of its own that you can move to any screen and enlarge; several can be open at once, and they update "
     "by themselves (every minute for Hour). <b>Graph Wall</b> (at the top of the host's page) shows every running "
     "VM and container at once in one window made for a screen of its own: a card appears when a guest starts and "
     "goes when it stops, and the cards shrink so that all of them always fit. Double-click a card for its full "
     "graphs.<br>"
     "• <b>Delete</b> — a stopped container or VM, only after you type its name. Its disks and snapshots go with "
     "it; its backups (which Proxmox would keep) are listed and deleted too unless you clear the box — protected "
     "ones always stay.<br>"
     "Click a column title to sort by it (sizes and times sort as numbers); <b>Hide stopped</b> keeps the list "
     "short. The <b>Boot</b> column shows ⏻ for guests that start when the host starts (<b>Start at boot</b>, set "
     "in New VM, New Container and Edit), with their place in the start order.<br>"
     "<b>Boot order</b> (shown when Start at boot is ticked): lower numbers start first and shut down last; "
     "<i>Any</i> comes after those with a number. <i>then wait</i> is how long Proxmox waits before it starts the next "
     "one — useful when, say, a DNS server must be up first. <i>Shutdown timeout</i> is how long the guest may take "
     "to shut down by itself when the host shuts down. Tags set in Proxmox show next to the name; point at the name to read the guest's notes."),
    ("Several at once, and tasks",
     "<b>Several guests</b> — Ctrl-click or Shift-click selects several in the list (Ctrl+A: all of them). "
     "<b>Start</b> and <b>Shut Down</b> then open Bulk Start or Bulk Shut Down with them ticked; <b>Stop</b> and "
     "<b>Reboot</b> go to each of them after one question. The other buttons work on one guest at a time. (The row "
     "of buttons above the list takes a second row when the window is too narrow for one, and goes back to one as "
     "it widens.)<br>"
     "<b>Bulk Start… / Bulk Shut Down…</b> (beside <i>Tasks</i>, under the list) do what the web UI's Bulk Actions "
     "do, in one Proxmox task. The ticked guests start one by one in their <b>boot order</b>, Proxmox waiting each "
     "one's <i>then wait</i> before the next; Bulk Start ticks those with Start at boot to begin with. They shut "
     "down in the reverse order (guests with the same order together); each may take the time you set, 180 s "
     "unless changed, and one still running after it is stopped like pulling the plug — untick that to leave it "
     "running instead. The window shows which guest is being started or shut down; the task goes on on the host "
     "even if you close it.<br>"
     "<b>Tasks</b> — the host's recent tasks, as in the web UI's panel at the bottom: what was done, when, by whom "
     "(the app's token, or you in the web UI), how long it took and how it ended. Running ones have a blue dot and "
     "count up; failed ones are red; yellow ones did their job with warnings (Proxmox's <i>WARNINGS: 2</i> — a VM "
     "that started, with a word about its firmware, say: the log says what). Double-click one (or right-click → "
     "Open Log) for its log, followed live while it runs; <b>Stop Task…</b> there stops one still running. Click "
     "<b>Tasks</b> to fold the list away; the app remembers it."),
    ("IP addresses",
     "Containers report their addresses to Proxmox by themselves. A VM needs the <b>QEMU guest agent</b>: in "
     "Proxmox turn it on under <i>VM → Options → QEMU Guest Agent</i>, and inside the VM install "
     "<tt>qemu-guest-agent</tt> (Windows: from the VirtIO drivers disc), then restart the VM.<br>"
     "Without the agent the app looks for the VM's MAC address in this computer's network table. That works for "
     "machines this computer has talked to recently; such addresses are shown dimmed."),
    ("New VM",
     "<b>New VM</b> installs an operating system from an <b>ISO image</b>, makes a <b>ready-made Ubuntu</b>, or "
     "copies a <b>template</b>.<br>"
     "• <b>ISO image</b> — choose one already on the host, or get one: <b>Download…</b> has the host fetch it "
     "from a web address (nothing passes through this computer; add the SHA-256 checksum if the site gives one), "
     "<b>Upload…</b> sends a file from this computer, for example a Windows image you downloaded yourself.<br>"
     "• <b>Operating system</b> sets sensible sizes. <b>Windows 11</b> also gets UEFI with Secure Boot and a TPM "
     "2.0. Windows has no drivers for the fast VirtIO disk and network: with <b>Get VirtIO ISO</b> the host "
     "downloads Red Hat's drivers disc and setup can load them from it; without it the VM uses a SATA disk and an "
     "Intel e1000e card, which Windows knows by itself.<br>"
     "• <b>Windows setup: Installs itself</b> (on by default) — the app writes an answer file "
     "(<tt>autounattend.xml</tt>) onto a small disc of its own beside the Windows ISO, and Windows Setup does the rest "
     "with no keys pressed: the VirtIO disk and network drivers load from the VirtIO disc, the disk is partitioned, "
     "the <b>edition</b> you chose is installed (as the installer lists it: <i>Windows 11 Pro</i>…), in the "
     "<b>language</b> of the ISO (read from its name; the keyboard is English US), and the questions of the first "
     "start are skipped. It creates the <b>User</b> with your password (both typed here; leave them empty for no "
     "password), signs in once by itself and finishes: <b>Remote Desktop</b> on and let through the firewall (needs a "
     "password, and Pro, Education, Enterprise or Server — Home has none), the <b>Dark theme</b> if ticked, and last "
     "the VirtIO guest tools with the QEMU guest agent. When the app starts the VM it watches its screen and presses "
     "Enter at <i>Press any key to boot from CD or DVD</i> for you (if it is missed, it tries again through the "
     "firmware's Boot Manager), and chooses <i>I don't have a product key</i> on Setup's product key page — the "
     "answer file holds no key, so Windows stays unactivated, as without it (if you start the VM yourself, do both "
     "in its Console). Its log of what it saw is boot-prompt.log in the app's data folder. The answer disc "
     "holds the password (in Windows' own hidden form, which is not encryption), so the app empties the VM's CD drive "
     "and deletes the disc as soon as the agent answers — Windows is ready — or, without the agent, after the VM has "
     "run 30 minutes; it checks once a minute while the app is open (or the next time it opens). Untick it to install "
     "by hand in the Console as before.<br>"
     "• <b>Ready-made Ubuntu</b> — from Ubuntu's official cloud image (<b>Get Image</b> has the host download it "
     "once, into a storage with the <i>Import</i> content): no installer. <b>Server</b> is ready about a minute after "
     "it starts — Proxmox's own cloud-init sets the user, your password (or an SSH key) and the network. "
     "<b>Desktop</b> installs Ubuntu Desktop and the QEMU guest agent by itself on the first start (10–20 minutes), "
     "then restarts into the login screen. <b>Remote Desktop</b> turns on Ubuntu's own (GNOME Remote Desktop): the "
     "Ubuntu desktop itself over RDP, with its sound. Connect to the VM's address (port 3389) with any Remote Desktop "
     "app, accept its self-signed certificate, sign in with the same user and password, then once more at the Ubuntu "
     "login screen (in Remmina, set Audio output mode to Local for the sound). <b>Dark theme</b> makes the desktop "
     "dark. For the desktop the app writes cloud-init's settings onto a small disc of its own (Proxmox's cloud-init "
     "cannot install packages), with the password as a hash — and, for Remote Desktop, the password itself in a file "
     "of its own, which the VM reads into memory once and never keeps on its disk — and deletes the disc once the "
     "agent answers.<br>"
     "• <b>Display, Sound, USB</b> — new VMs get the SPICE display and an Intel HD Audio card that plays "
     "through SPICE (set Sound to None for a server). <b>Pointer: USB tablet</b> (on for new VMs) makes the "
     "mouse land exactly where you point in this app's console, and where Claude clicks: Proxmox leaves the tablet "
     "out with the SPICE display unless it is set, and Windows then has only a relative mouse. For a VM made "
     "before, tick it in Edit (Proxmox plugs it in at once, or at the next start where USB hotplug is off). Tick "
     "USB devices plugged into the host to hand them to the "
     "VM; <i>USB devices of this computer</i> lets remote-viewer pass devices of the computer you sit at "
     "(remote-viewer: File → USB device selection).<br>"
     "• After it starts, open its <b>Console</b> to install the operating system (or to watch Windows install "
     "itself).<br>"
     "• <b>Copy a template</b> — turn a prepared VM into a template in Proxmox (right-click → Convert to "
     "template); a full copy stands on its own, a linked copy shares the template's disk and saves space."),
    ("New container",
     "<b>New Container</b> asks for a hostname, a template, CPU, memory, disk, network and a root password "
     "(and optionally your SSH public key). <b>Download…</b> fetches more templates — Debian, Ubuntu, Alpine "
     "and others — straight onto the host. Unprivileged containers are the safer default; tick <i>nesting</i> "
     "if you want to run Docker inside."),
    ("Backups",
     "<b>Backups…</b> opens a window for one guest that can stay open beside the app.<br>"
     "• <b>Back Up Now</b> — choose the storage, the mode (<i>Snapshot</i> keeps it running; <i>Suspend</i> pauses "
     "it a moment; <i>Stop</i> shuts it down during the backup) and the compression; the note may use "
     "{{guestname}} and {{vmid}}. The bar follows Proxmox's progress; the backup goes on on the host even if you "
     "close the window.<br>"
     "• <b>Restore…</b> — over the guest itself (it must be stopped; type its name to confirm: everything since the "
     "backup is lost) or as a new guest with a new ID, beside the original.<br>"
     "• <b>Protect</b> keeps a backup from being pruned or deleted; <b>Delete…</b> removes an unprotected one.<br>"
     "Unlike a snapshot, a backup is a separate file: it survives the guest's disk.<br>"
     "<b>Backups of Deleted Guests…</b> (the arrow of Backup Jobs…) lists what was kept of guests that no longer "
     "exist: <b>Restore…</b> brings one back — by default with its old ID and network addresses (MAC), so the "
     "router gives it the IP it had.<br>"
     "<b>Backup Jobs…</b> (above the list) are the backups Proxmox runs by itself (Datacenter → Backup): when "
     "(every day, Monday to Friday, weekends, one day a week, or a Proxmox calendar event such as "
     "<tt>mon,wed,fri 22:00</tt>), which guests (some, all, or all but some), where, and how many to keep — older ones "
     "beyond those numbers are removed after each run, protected ones stay. <b>Run Now</b> runs a job at once. The "
     "window warns about guests no job covers, and each guest's Backups window says which job covers it."),
    ("Claude Access",
     "Claude — Claude Code (also the Code tab of the Claude desktop app), Claude Desktop and Cowork — can look after "
     "your hosts through this app, only as far as you let it. Open <b>☰ → Claude Access…</b>:<br>"
     "• <b>Let Claude use Proxmox Controller</b> is the switch for all: off, every request is refused.<br>"
     "• <b>Claude apps on this computer → Connect</b> adds the connector to Claude Code or Claude Desktop, no terminal "
     "needed. Then start a new conversation in Claude Code; quit Claude Desktop and open it again.<br>"
     "• <b>Set Up…</b> (for each host) makes, with your API token, Claude's own user on the host "
     "(<tt>claude-controller@pve</tt>, with no password: it cannot log in to the web interface), its role and its API "
     "token. <b>Remove…</b> takes all of it away again.<br>"
     "• <b>Nine switches</b> for each host, each <b>Off</b> (refused), <b>Ask</b> (a window asks you: <i>Allow</i>, "
     "<i>Allow This Kind for 1 Hour</i> or <i>Deny</i>; no answer in two minutes is a No) or <b>On</b> (done at "
     "once): Read, Power, Change, Destroy, Host, Console, Commands, Files and Host commands. <b>What each switch "
     "allows</b> "
     "below lists every tool Claude has, under its switch.<br>"
     "• <b>The approval window</b> has yellow and black hazard stripes along its top and all round, so it is found "
     "at once among many windows. <b>Play a sound when Claude asks</b> (at the top of Claude Access) adds a short "
     "sound — Double beep, Beep or Bell; <b>▶ Play</b> lets you hear it — once as the window opens.<br>"
     "• <b>Hours without asking</b> — the arrow beside <i>Allow This Kind for 1 Hour</i> gives 1, 3, 8 or 12 hours "
     "(for a night's work, say). While they last, Claude Access shows <i>allowed without asking until …</i> in yellow "
     "beside that kind, and the log says <i>Allowed (hours you gave)</i>. A click on that kind's Off, Ask or On ends "
     "them at once; so does quitting the app. Never for Host commands, nor where a password is asked.<br>"
     "• Between requests Claude's token can only read (with Read On); for each request the app allows, it lends the "
     "token that kind's privileges for just that request. Changing backup jobs needs privileges too broad to lend, "
     "so Claude can see the jobs but not change them.<br>"
     "• <b>Passwords never go through Claude.</b> Where one is needed — the user of a new VM, the root of a new "
     "container, a login or sudo prompt in a console — the app asks <i>you</i> for it in its window (always, even when "
     "that kind is On; for a console it shows the guest's screen, so you see where it goes) and passes it on itself: "
     "Claude is only told it was set. An installer's password and its confirmation come from one window: you type "
     "it twice there (so a typo shows) and it goes into both fields — the picture marks in red where the second goes. Only English (US) keyboard characters: the "
     "guest gets the keys of that keyboard.<br>"
     "• <b>New Ubuntu VMs from a cloud image</b>: the host downloads Ubuntu Server's official cloud image once (24.04 "
     "or 26.04); a VM made from it is ready about a minute after it starts — no installer: a user, your password, an "
     "SSH key if given, network by DHCP. The desktop edition adds a SPICE display and sound and installs Ubuntu "
     "Desktop by itself on the first start (with Remote Desktop if asked). <b>Windows installs itself</b> when Claude "
     "names its user: the same answer disc as in New VM, with the password typed by you in the app's window; with a "
     "start, the app itself presses Enter at the installer's question — it waits only seconds, so no second approval "
     "is asked, whatever the Console switch says. Any other system "
     "installs from its ISO through the console.<br>"
     "• <b>Claude's clicks need an absolute pointer</b> in the VM — a USB tablet (every VM this app makes has one), "
     "or in Linux QEMU's vmmouse. Before clicking, the app reads which mouse the VM uses; without an absolute one it "
     "tells Claude so and clicks nothing (a click would land wherever the pointer already is), and Claude can add "
     "the tablet with an Edit request.<br>"
     "• Every request is listed under <b>Requests</b>, with the reason Claude gave and what was decided.<br>"
     "• Claude reaches the app only while it is open (and unlocked). Scheduled tasks (routines) can do only what is "
     "On: nobody is there to answer Ask.<br>"
     "• <b>Lock the API tokens with a password</b> first (Settings → Security): unlocked, programs running as you — "
     "Claude included — could read your own token and go around the switches."),
    ("What each switch allows", switch_table_html()),
    ("Security",
     "<b>Settings → Security → Lock with a Password…</b> keeps your hosts' API tokens (and Claude's) encrypted on this "
     "computer (scrypt and AES-256-GCM); the app asks for the password each time it starts, before it reaches any "
     "host. There is no way to recover a forgotten password: <b>Forgot Password…</b> forgets the tokens — give each "
     "host its token again with <b>Edit…</b> and set up Claude's access again. <b>Change Password…</b> and "
     "<b>Remove Password…</b> ask for the current one first."),
    ("Snapshots",
     "A snapshot saves a guest as it is right now. Take one before a risky change; if something goes wrong, "
     "<b>Roll Back</b> returns to that moment (everything after it is lost). Snapshots need storage that "
     "supports them, such as LVM-thin or ZFS."),
    ("Wake-on-LAN",
     "To turn a host on from the app, three things are needed:<br>"
     "1. <b>BIOS/UEFI</b> of the host: turn on <i>Wake on LAN</i> (on home motherboards also called "
     "<i>Power On by PCI-E</i>, <i>Resume by LAN</i> or <i>Wake on PME</i>); turn off <i>ErP</i>/<i>EuP</i> "
     "or <i>Deep Sleep</i>, which cut the network card's power when off.<br>"
     "2. <b>The network card</b>, inside Proxmox: <tt>ethtool -s &lt;card&gt; wol g</tt>, made permanent "
     "with a <tt>post-up</tt> line in <i>/etc/network/interfaces</i>.<br>"
     "3. <b>The app</b>: the host's MAC address in the host's <b>Edit…</b> (press <b>Detect</b> while the host "
     "is on).<br>"
     "Wake-on-LAN works inside your home network; routers do not pass it on from the internet."),
    ("Shutting down a host",
     "<b>Shut Down Host</b> asks Proxmox to stop its guests cleanly and then power off — the same as the "
     "Shutdown button in the Proxmox web UI. <b>Reboot Host</b> does the same and starts again."),
    ("The host's console and upgrade",
     "<b>Console</b> (at the top of the host's page) opens the host's own shell — root, as the Proxmox web UI's "
     "<i>Shell</i> — in this computer's terminal, over SSH. Proxmox keeps that shell for root's own login and refuses "
     "it to an API token, so it cannot open inside the app.<br>"
     "<b>Upgrade</b> lists the package updates waiting on the host (Proxmox looks for them daily; <b>Check Now</b> "
     "asks again) and <b>Upgrade…</b> runs <i>pveupgrade</i> in the terminal — what Proxmox's own Upgrade button "
     "runs: it shows what it will do and asks before installing. After a new kernel, reboot the host. The button "
     "shows how many updates wait: <b>Upgrade (12)</b>.<br>"
     "<b>Package sources</b> (in the same window): without a Proxmox subscription, Proxmox's enterprise repository "
     "refuses the host (401) — the daily check then ends in an error, and <b>Proxmox's own updates never show</b>, "
     "only Debian's. <b>Use No-Subscription</b> adds Proxmox's free repository (Ceph's too, where its enterprise one "
     "is on) and switches the enterprise ones off, as Updates → Repositories does in the web UI. <b>Check Now</b> "
     "says in the window which sources refused, instead of an error.<br>"
     "The first time, the app asks for the host's SSH settings: the user (root), the port, and the host's key — "
     "compare its fingerprint with <tt>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</tt> on the host. "
     "<b>Set up a key</b> spares typing the password each time: the app makes its own key, adds it beside root's "
     "password with the password you give once (it is not kept), and from then on opens at once. <b>Your password "
     "always keeps working</b> — the host's SSH settings are never changed. <b>SSH Settings…</b> (the arrow of "
     "Console) shows the key and has <b>Remove Key</b>. Without a key, the terminal asks for the password."),
    ("What it stores on your computer",
     "• Linux: <tt>~/.config/proxmox-controller/</tt> · Windows: <tt>%APPDATA%\\ProxmoxController\\</tt><br>"
     "• <tt>hosts.json</tt> — addresses, token IDs, certificate fingerprints, MAC addresses.<br>"
     "• <tt>secrets.json</tt> — the API token secrets, kept apart; readable only by your user.<br>"
     "• Only while <b>Start with the computer</b> is on (Settings) — Linux: "
     "<tt>~/.config/autostart/store.themechanic.ProxmoxController.desktop</tt> · Windows: the value <i>Proxmox "
     "Controller</i> under <tt>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</tt> (Settings → "
     "Apps → Startup lists it).<br>"
     "• <tt>connector-log.jsonl</tt> — Claude's requests (Claude Access → Requests). Linux: "
     "<tt>~/.local/share/proxmox-controller/</tt> · Windows: <tt>%LOCALAPPDATA%\\ProxmoxController\\</tt>. "
     "While the app runs, Claude's bridge reaches it through <tt>/run/user/&lt;id&gt;/proxmox-controller/"
     "connector.sock</tt> (Windows: the named pipe <tt>\\\\.\\pipe\\proxmox-controller-&lt;you&gt;</tt>), open to your "
     "user only.<br>"
     "• <tt>ssh/</tt> — the app's own SSH key (<tt>id_ed25519</tt>) and the host keys you confirmed "
     "(<tt>known_hosts</tt>); your own <tt>~/.ssh</tt> is never touched.<br>"
     "Nothing is installed on the Proxmox hosts — only, if you choose <b>Set up a key</b>, the app's key in root's "
     "authorized keys (<b>Remove Key</b> takes it off)."),
    ("Troubleshooting",
     "<b>“Proxmox refused the API token”</b> — check the Token ID and secret; the token must not be expired.<br>"
     "<b>“not allowed to do this”</b> — the token has Privilege Separation on, or its user lacks the right; "
     "give it the needed role under <i>Datacenter → Permissions</i>.<br>"
     "<b>“presented a different certificate”</b> — the host's certificate changed (renewed or replaced). If "
     "you did that, open <b>Edit</b>, press <b>Get Certificate</b> and confirm the new one.<br>"
     "<b>Wake does nothing</b> — check the three Wake-on-LAN steps; the host must be on the same network."),
]


class HelpDialog(QDialog):
    """Help in its own window, so it can stay open next to the host it explains."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(f"Help — {APP_NAME}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 12)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(24, 20, 24, 12)
        bl.setSpacing(14)
        for title, text in SECTIONS:
            bl.addWidget(card(label(title, "heading"), label(text, wrap=True)))
        bl.addStretch(1)
        scroll.setWidget(body)
        lay.addWidget(scroll, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        buttons.setContentsMargins(24, 0, 24, 0)
        lay.addWidget(buttons)
        self.resize(700, 720)
