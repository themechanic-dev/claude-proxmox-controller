"""Runs the tests the safe way on a desktop: the process is made non-dumpable first, so a crash (Qt and threads can
crash a test run) prints a Python traceback here instead of putting Ubuntu's "internal error" window on the screen.

    .venv/bin/python -I tools/run_tests.py [--strict] [test names…]      --strict: ResourceWarning is an error
"""

import ctypes
import faulthandler
import os
import sys
import unittest
import warnings

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

if sys.platform.startswith("linux"):
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0
faulthandler.enable(all_threads=True)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
args = sys.argv[1:]
if "--strict" in args:
    args.remove("--strict")
    warnings.simplefilter("error", ResourceWarning)
os.chdir(ROOT)
sys.path.insert(0, ROOT)
loader = unittest.defaultTestLoader
suite = loader.loadTestsFromNames(args) if args else loader.discover("tests", top_level_dir=ROOT)
result = unittest.TextTestRunner(verbosity=1).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
