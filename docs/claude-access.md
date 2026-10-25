# What Claude may do — the switches

<!-- Made by tools/claude_access_doc.py from the code (connector_tools.access_table): do not edit. -->

Claude reaches your Proxmox hosts only through Proxmox Controller, and only as far as each host's switches let it. Every switch is **Off** (refused), **Ask** (a window of the app asks you: *Allow*, *Allow This Kind for 1 Hour* — its arrow: 3, 8 or 12 hours — or *Deny*; no answer in two minutes is a No) or **On** (done at once). Above them, *Let Claude use Proxmox Controller* turns all of it off. Passwords never go through Claude: where one is needed, the app asks you for it in its own window. Every request is logged with the reason Claude gave.

## Read — default: On

State, addresses, settings, notes, snapshots, backups, jobs, tasks, graphs.

*This app and Proxmox: Claude's token holds these privileges while Read is On: VM.Audit, Sys.Audit, Datastore.Audit, VM.GuestAgent.Audit, SDN.Audit*

| Tool | What it does |
|---|---|
| `list_hosts` | The Proxmox hosts Proxmox Controller lets you use, whether each is online, and what you may do on each (each kind of request is off, ask — the user approves it — or on). |
| `host_status` | A host's nodes: CPU, memory, system disk, uptime, load, and storage use. |
| `list_guests` | Every VM and container of a host: state, CPU, memory, disk, IP addresses, tags, start at boot and boot order, notes. |
| `guest_details` | One guest's full Proxmox configuration, and for a VM the settings waiting for its next start. |
| `list_snapshots` | A guest's snapshots. |
| `list_backups` | A guest's backups, newest first — also of a guest deleted since, by its old ID. |
| `list_backup_jobs` | The scheduled backups (Datacenter → Backup) and the guests no job covers. |
| `list_tasks` | The host's recent tasks, newest first, with how they ended. |
| `task_log` | A task's log (a backup's progress, an error). |
| `guest_usage` | A guest's average and peak CPU, memory, network and disk use over the last hour, day, week or month. |
| `list_install_media` | What new guests can be made from: ISO images, container templates, storages, network bridges and the next free VMID. |

## Power — default: Ask

Start, shut down, stop, reboot; Bulk Start and Shut Down; wake the host.

*This app and Proxmox: lent to Claude's token only for a request the app allows: VM.PowerMgmt*

| Tool | What it does |
|---|---|
| `guest_power` | Start, shut down (clean), stop (at once, like pulling the plug — only if shut down does not work) or reboot a guest. |
| `bulk_power` | Start several guests one after the other in their boot order, or shut them down in reverse order — one Proxmox task, like the web UI's Bulk Actions. |
| `wake_host` | Turn the host on with Wake-on-LAN (it must support it and be set up for it). |

## Change — default: Ask

Edit, notes, snapshots, Back Up Now, new VMs and containers, copies, ISOs.

*This app and Proxmox: lent to Claude's token only for a request the app allows: VM.Config.CPU, VM.Config.Memory, VM.Config.Disk, VM.Config.Network, VM.Config.Options, VM.Config.HWType, VM.Config.CDROM, VM.Config.Cloudinit, VM.Snapshot, VM.Backup, VM.Clone, VM.Allocate, Datastore.AllocateSpace, Datastore.AllocateTemplate, SDN.Use, Sys.AccessNetwork*

| Tool | What it does |
|---|---|
| `edit_guest` | Change a guest's settings: cores, memory_mib, swap_mib, name, start_at_boot, boot_order, boot_delay_s, shutdown_timeout_s, tags, notes, tablet. |
| `grow_disk` | Make a guest's disk bigger (never smaller). |
| `take_snapshot` | Take a snapshot of a guest. |
| `backup_now` | Back a guest up now (it keeps running in snapshot mode). |
| `create_vm` | Create a VM that boots an ISO image (see list_install_media). *(starting it also needs Power not Off)* |
| `get_cloud_image` | Have the host download Ubuntu Server's official cloud image (24.04 or 26.04), once, to make VMs from with create_cloud_vm. |
| `create_cloud_vm` | Create an Ubuntu VM from a cloud image (see get_cloud_image) — no installer: a user, its password (the USER types it in Proxmox Controller's window; you never give or see a password), optionally an SSH public key, network by DHCP. *(starting it also needs Power not Off; asks you for a password)* |
| `create_container` | Create an unprivileged container from a template (see list_install_media). *(starting it also needs Power not Off; asks you for a password)* |
| `clone_vm` | Copy a VM or a template as a new VM. |
| `download_iso` | Have the host download an ISO image from a web address. |
| `restore_backup` | Restore a guest's backup as a new guest — or over the guest itself (replace: true; it must be stopped, and that is a Destroy request). *(starting it also needs Power not Off; Change or Destroy, by its arguments)* |

## Destroy — default: Off

Delete guests, roll back or delete snapshots, delete backups, restore over.

*This app and Proxmox: lent to Claude's token only for a request the app allows: VM.Allocate, VM.Snapshot, VM.Snapshot.Rollback, VM.Backup, Datastore.AllocateSpace*

| Tool | What it does |
|---|---|
| `restore_backup` | Restore a guest's backup as a new guest — or over the guest itself (replace: true; it must be stopped, and that is a Destroy request). *(starting it also needs Power not Off; Change or Destroy, by its arguments)* |
| `delete_guest` | Delete a stopped guest with all its disks and snapshots — and its backups, which Proxmox would keep (protected ones always stay), unless keep_backups is true. |
| `rollback_snapshot` | Roll a guest back to a snapshot (what came after it is lost). |
| `delete_snapshot` | Delete a snapshot. |
| `delete_backup` | Delete a backup (not a protected one). |
| `stop_task` | Stop a running task (one started through this connector). |

## Host — default: Off

Shut down or reboot the host itself.

*This app and Proxmox: lent to Claude's token only for a request the app allows: Sys.PowerMgmt*

| Tool | What it does |
|---|---|
| `host_power` | Shut down or reboot the host itself (its guests are shut down first). |

## Console — default: Off

See a guest's screen, type into it and click on it.

*This app and Proxmox: lent to Claude's token only for a request the app allows: VM.Console*

| Tool | What it does |
|---|---|
| `console_screenshot` | A picture of a running guest's screen. |
| `console_send` | Type text into a running guest's console and/or press keys: enter, tab, escape, backspace, delete, arrows (up, down, left, right), home, end, pageup, pagedown, f1–f12, and combinations such as ctrl+alt+delete or ctrl+c. |
| `console_click` | Click — or double-click, right-click, or turn the wheel (scroll: + up, − down) — on a running guest's screen at x, y of the latest console_screenshot picture (take a fresh one first: the click lands where things are now). |
| `console_type_password` | Type a password into a running guest's console — at a login, a sudo prompt, or an installer's password screen. *(asks you for a password)* |

## Commands — default: Off

Run commands inside VMs that have the QEMU guest agent.

*This app and Proxmox: lent to Claude's token only for a request the app allows: VM.GuestAgent.Unrestricted*

| Tool | What it does |
|---|---|
| `run_command` | Run a program inside a running VM through the QEMU guest agent and get its output (for example ["systemctl", "status", "nginx"], or ["sh", "-c", "df -h"]). |

## Files — default: Off

Copy files between this computer and VMs or containers, and list their folders.

*VMs — this app and Proxmox: lent to Claude's token only for a request the app allows: VM.GuestAgent.Unrestricted; only the app's own copy and listing commands run with it. Containers — this app only: over the app's SSH key, as host commands. Paths on the user's computer are shown whole in the approval window; nothing is replaced unless replace is asked.*

| Tool | What it does |
|---|---|
| `list_guest_files` | The files and folders in a folder of a running VM (through its QEMU guest agent) or container (over the host's SSH): name, folder or not, size, modified. |
| `send_files` | Copy files and folders of the user's computer (whole paths) into a folder of a running VM or container — names and times kept, folders whole. |
| `receive_files` | Copy files and folders (names) from a folder of a running VM or container into a folder of the user's computer (a whole path that exists). |

## Host commands — default: Off

Run commands on the host itself, as root, over the app's SSH key.

*This app only: the commands go over SSH with the app's key, not through Proxmox's API, so Proxmox cannot refuse them on its own. Each one is shown in the approval window, every time (no 'Allow This Kind for 1 Hour', nor longer). The app's SSH key file itself is not encrypted: a program running as you on this computer (Claude Code with a shell, too) could read it and use it without asking — Off stops the connector, not that.*

| Tool | What it does |
|---|---|
| `host_command` | Run a shell command on the Proxmox host itself, as root, over the SSH key the user set up in Proxmox Controller, and get its output and exit code — for what the API cannot do (installed programs, services, logs, files). |
| `set_container_root_password` | Set a running container's root password to one the USER types in Proxmox Controller's window (you never give or see it) — for a container whose root password is lost, or to give it a new one. *(asks you for a password)* |
