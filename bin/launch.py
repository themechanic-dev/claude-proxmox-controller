"""Entry point used by bin/proxmox-controller (works from the source tree).

    proxmox-controller          the app
    proxmox-controller --mcp    the connector's bridge, started by Claude (no window, no Qt)
    … --askpass                 (Windows) what ssh runs for the password the app gave it
    … --uninstall [--all]       (Windows) what the uninstaller runs: the start-at-login entry and the connector's
                                entries in the Claude apps go (--all: the hosts and settings too)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

if "--askpass" in sys.argv[1:]:  # Windows: ssh asks this for the password the app gave it for one run
    from proxmox_controller.core.ssh import askpass_answer  # noqa: E402
    sys.stdout.reconfigure(encoding="utf-8")  # the password's own bytes, as the host compares them (no code page)
    sys.stdout.write(askpass_answer())
    sys.exit(0)

if "--uninstall" in sys.argv[1:]:  # Windows: the uninstaller, before the program's files go
    from proxmox_controller.core.uninstall import cleanup  # noqa: E402
    print("\n".join(cleanup(remove_data="--all" in sys.argv[1:])))
    sys.exit(0)

if "--mcp" in sys.argv[1:]:
    from proxmox_controller.core import mcp  # noqa: E402
    sys.exit(mcp.main())

from proxmox_controller.app import main  # noqa: E402

sys.exit(main(sys.argv))
