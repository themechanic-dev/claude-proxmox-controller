"""Writes docs/claude-access.md — every switch of Claude Access and every tool under it — from the code.

    python3 tools/claude_access_doc.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)

from proxmox_controller.core.connector_tools import access_markdown  # noqa: E402

path = os.path.join(ROOT, "docs", "claude-access.md")
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    f.write(access_markdown())
print(path)
