"""Entry point used by bin/proxmox-controller (works from the source tree).

    proxmox-controller          the app
    proxmox-controller --mcp    the connector's bridge, started by Claude (no window, no Qt)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

if "--mcp" in sys.argv[1:]:
    from proxmox_controller.core import mcp  # noqa: E402
    sys.exit(mcp.main())

from proxmox_controller.app import main  # noqa: E402

sys.exit(main(sys.argv))
