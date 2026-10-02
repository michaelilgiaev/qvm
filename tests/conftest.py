"""Shared pytest fixtures + import-path setup for the qvm test suite.

`bash tests.sh` already puts libraries/ on PYTHONPATH, and pyproject.toml's
[tool.pytest.ini_options] pythonpath does the same for a bare `pytest` run. This conftest
belt-and-suspenders it so the flat modules resolve no matter how the tests are
launched, and it puts this tests/ dir on the path so a test can import the shared
test-only helper beside it (`from hypervisor_helpers import make_cfg`).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
# qvm has a SINGLE import root (libraries/) -- unlike azzio, which also carries
# scripts/libraries. The flat modules live directly in libraries/.
_LIB = str(REPO / "libraries")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# Also put THIS tests/ dir on the path so a test module can import the shared, test-only
# helper that sits beside it (`from hypervisor_helpers import make_cfg`). Under pytest's
# importlib import mode the rootdir's tests/ dir is NOT added implicitly, so without this a
# sibling-helper import fails with ModuleNotFoundError. conftest is imported before any test
# module, so this runs early enough for every test.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# The tests/ dir is now on the path, so the test-mode helper (beside this file) imports.
import _testmodes  # noqa: E402  (import after the sys.path setup above, by design)


def pytest_collection_modifyitems(config, items):
    """Skip the privileged test tiers unless their mode is enabled in tests/test_modes.conf.

    Two independent booleans gate two tiers; both default OFF so a plain `bash tests.sh` is
    green with no connectivity and no sudo. We SKIP (not deselect) so the logs still SHOW the
    gated tests as `s` -- visibly not-run, not silently vanished. Modes come from
    tests/test_modes.conf (env vars override); flip them with `tests.sh --online/--offline`
    (network) and `tests.sh --user/--root` (root). See tests/_testmodes.py for the parser.

    - `network`: OFFLINE (default) skips it -- those tests reach a real host and a plain run
      must stay green with no connectivity and NEVER hang on a DNS lookup. ONLINE runs them.
    - `root`: USER (default) skips it. ROOT selects it -- the offline btrfs loop-mount test(s)
      then run IF the process is actually UID 0, else self-skip via their own `os.geteuid()`.
    """
    marks = []
    if _testmodes.is_offline():
        marks.append(("network",
                      pytest.mark.skip(reason="offline mode (tests.sh --offline); run with tests.sh --online")))
    if _testmodes.is_user():
        marks.append(("root",
                      pytest.mark.skip(reason="user mode (tests.sh --user); run with tests.sh --root")))
    if not marks:
        return
    for item in items:
        for keyword, skip in marks:
            if keyword in item.keywords:
                item.add_marker(skip)
