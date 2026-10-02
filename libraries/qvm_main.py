"""Frozen entry point for the `qvm` binary (Nuitka --onefile).

This is the top-level module Nuitka freezes; compile.sh points at it and adds libraries/
to the module search path. It lives IN libraries/ next to the flat modules (no package),
so it imports the CLI entry FLAT -- `import command_line_interface` -- and the modules load
as bare siblings. It puts its own directory on sys.path first so the import resolves both
frozen and run straight from source; inside the frozen binary __file__ resolves into the
bundled extraction dir, so the siblings load from there.

Crucially we do NOT chdir: the VM identity derives from the caller's CURRENT WORKING
DIRECTORY via Config.from_cwd(), and the frozen bootstrap leaves cwd untouched, so a `qvm`
invoked inside /some/project resolves THAT directory's VM -- the single most important
correctness property of the port, preserved through freezing.

Run from source (unfrozen) the same way compile.sh freezes it:
    PYTHONPATH=libraries python3 libraries/qvm_main.py <args>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from command_line_interface import main  # noqa: E402  (after the sys.path bootstrap above)

if __name__ == "__main__":
    sys.exit(main())
