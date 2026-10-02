"""Single source of truth for the qvm test suite's TEST MODES -- two independent
booleans, `network` and `root`, that select which privileged tiers of the suite run.

Why this exists
---------------
Most of this suite is PURE: it exercises the deterministic Python logic (the QEMU/virtiofsd
argv builders, the hypervisor.cfg schema + coercion, CWD-derived VM identity, the config
watcher) against fakes, never launching a VM, touching the network, or using sudo. Two tiers
are the exception and are gated by a persisted toggle so a plain `bash tests.sh` stays green
with no connectivity and no privileges:

- `network`: any test that reaches a REAL host. OFFLINE (the default) SKIPS the
  `network`-marked tests, so a plain run never hangs on a DNS lookup. ONLINE runs them.
  (This tier is provided for parity and may hold no tests in the current suite.)
- `root`: tests that need UID 0 to run (the offline `hypervisor share --offline` btrfs
  loop-mount path). USER mode (the default) SKIPS the `root`-marked tests. ROOT mode SELECTS
  them -- they then run IF the process is actually UID 0, and otherwise self-skip via their
  own `os.geteuid()` guard (selecting the tier does not force root).

The two booleans gate in OPPOSITE directions but the file meaning is uniform ("run this
tier?"): `network=true` runs the network tier, `root=true` selects the root tier.

The toggle
----------
Both booleans live in ONE LOCAL file, `tests/test_modes.conf` (default: both `false`), as
`key = value` lines::

    network = false
    root = false

The file is per-machine local state: it is GITIGNORED, not committed. `tests.sh` CREATES it
with the both-`false` default on first run if it is missing, and otherwise leaves it alone, so
a fresh clone starts both-off (nothing to hang on, no sudo demanded) and each machine keeps its
own toggles. Because the file may not exist yet on a brand-new clone before the first
`tests.sh` run, this module treats a MISSING file exactly like the default (both off) -- see
`_read_conf`, which never raises.

Flip the toggles WITHOUT running the suite via `tests.sh --offline/--online` (network) and
`tests.sh --user/--root` (root) -- they rewrite the file and exit. Environment variables
`QVM_TESTS_NETWORK` / `QVM_TESTS_ROOT` override the file for a single run; tests.sh
exports them to match the file so its run and the two isolated off-screen log-copy runs (whose
repo copies do not contain the conf) all agree, and CI can set them directly.

The root tier additionally DEMANDS sudo: with `root = true` persisted, a plain `bash tests.sh`
run as a non-root user STOPS at the shell layer (in tests.sh) and asks the user to re-run under
sudo, rather than quietly skipping the root-marked tests. The `os.geteuid()` self-skip in the
root-marked tests remains as a second layer (for `-m root` selection and the test-only
`QVM_ALLOW_NONROOT` escape hatch, which bypasses the shell-layer demand).

Anything unrecognized (a typo in the file, a bad env value) falls back to the SAFE default
(the tier OFF): an offline run can never hang, and a user-mode run can never need sudo, so an
ambiguous config fails closed, not open. For the network var ONLY, the legacy words `online`
/ `offline` are also accepted as well as the generic boolean tokens.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# The LOCAL config file. It lives beside the tests but is GITIGNORED, not committed -- it is
# per-machine state that tests.sh auto-creates (both off) on first run. A fresh clone therefore
# may not have it yet; _read_conf() treats a missing file as the safe both-off default.
CONFIG_PATH = Path(__file__).resolve().parent / "test_modes.conf"

# The env vars that override the file for one run (tests.sh exports them; CI may set them).
ENV_NETWORK = "QVM_TESTS_NETWORK"
ENV_ROOT = "QVM_TESTS_ROOT"

# Canonical mode words kept for the network API's public surface (is_offline/is_online).
OFFLINE = "offline"
ONLINE = "online"

# Truthy/falsey tokens accepted in the conf and env vars. Everything else -> None (unknown),
# and each caller then falls back to its safe default (fail closed).
_TRUE = frozenset({"true", "1", "yes", "on"})
_FALSE = frozenset({"false", "0", "no", "off"})

# The ASCII whitespace set the sibling bash parser (conf_bool in tests.sh) trims with its POSIX
# `[[:space:]]` in the C/UTF-8 locale: space, tab, newline, carriage return, vertical tab, form
# feed. We normalize to EXACTLY this set (not Python's larger Unicode str.strip()) so the two
# parsers agree byte-for-byte -- a leading NBSP (U+00A0) or other exotic Unicode space is NOT a
# separator here, so such a value stays unrecognized and falls CLOSED (tier off), matching bash and
# erring safe. `str.split()`/`str.strip()` with no args would instead eat U+00A0 and friends and
# read the value as truthy, diverging from bash and failing OPEN.
_ASCII_WS = " \t\n\r\v\f"


def _ascii_strip(value: str) -> str:
    """Trim only ASCII whitespace from both ends -- the same set bash's `[[:space:]]` trims. Any
    other character (including exotic Unicode whitespace and interior spaces) is preserved, so a
    value that is not a clean token fails to match below and falls closed."""
    return value.strip(_ASCII_WS)


def _as_bool(value: str | None) -> bool | None:
    """Map a raw string to a bool, or None if it is not a recognized token. ASCII-whitespace
    trimmed + case-folded; interior/exotic whitespace leaves the value unrecognized -> None."""
    if value is None:
        return None
    v = _ascii_strip(value).lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return None


def _network_token(value: str | None) -> bool | None:
    """Parse a NETWORK value, accepting the legacy words `online`/`offline` in addition to the
    generic boolean tokens. `online` -> True (run the tier), `offline` -> False."""
    if value is None:
        return None
    v = _ascii_strip(value).lower()
    if v == ONLINE:
        return True
    if v == OFFLINE:
        return False
    return _as_bool(v)


def _read_conf() -> dict[str, str]:
    """Parse `test_modes.conf` into a {key: raw_value} dict. Never raises -- a missing, unreadable,
    or invalid-UTF-8 file yields an empty dict (or drops the bad bytes), and each caller then falls
    back to its safe default. Lines without `=`, blank lines, and `#` comments are ignored.

    Robustness details that keep this byte-faithful to the bash parser and crash-free:
      * bytes are decoded with errors='replace' (NOT read_text, which raises UnicodeDecodeError on a
        stray non-UTF-8 byte) -- a corrupt conf must fail CLOSED, never take down pytest collection.
      * lines are split ONLY on \\n / \\r\\n (str.splitlines() also breaks on form-feed, vertical
        tab, and Unicode line separators, which bash's line-oriented grep does not) -- so a value
        with an embedded FF/VT stays on one line here too, matching bash.
      * the per-line and per-value trim is ASCII-only (_ascii_strip), matching bash.
    """
    out: dict[str, str] = {}
    try:
        raw = CONFIG_PATH.read_bytes()
    except OSError:
        return out
    text = raw.decode("utf-8", errors="replace")
    for line in text.replace("\r\n", "\n").split("\n"):
        line = _ascii_strip(line)
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        # ASCII-strip both (matches bash: grep trims the key with [[:space:]], conf_bool trims the
        # value the same). The value keeps its raw case here; _as_bool/_network_token case-fold it.
        out[_ascii_strip(key).lower()] = _ascii_strip(val)
    return out


def network_enabled() -> bool:
    """True when the NETWORK tier should run. Env var wins, then the conf, else the safe
    default (False: offline cannot hang). Never raises."""
    env = _network_token(os.environ.get(ENV_NETWORK))
    if env is not None:
        return env
    conf = _network_token(_read_conf().get("network"))
    return conf if conf is not None else False


def root_enabled() -> bool:
    """True when the ROOT tier should be SELECTED. Env var wins, then the conf, else the safe
    default (False: user mode never needs sudo). Selecting the tier does not force UID 0 -- the
    root-marked tests keep their own privilege guards. Never raises."""
    env = _as_bool(os.environ.get(ENV_ROOT))
    if env is not None:
        return env
    conf = _as_bool(_read_conf().get("root"))
    return conf if conf is not None else False


# --- Network public surface --------------------------------------------------------------
def current_mode() -> str:
    """The active network mode as a word: ONLINE or OFFLINE."""
    return ONLINE if network_enabled() else OFFLINE


def is_offline() -> bool:
    return not network_enabled()


def is_online() -> bool:
    return network_enabled()


# --- Root public surface -----------------------------------------------------------------
def is_user() -> bool:
    """True when the suite is in USER mode (root tier NOT selected)."""
    return not root_enabled()


# --- Marker census (how many tests each gated tier holds) --------------------------------
# The repo root, from this file's location: tests/_testmodes.py -> parents[1] is the repo. Used
# to root the collection at the repo's tests/ dir regardless of the caller's CWD.
_REPO = Path(__file__).resolve().parents[1]

# pytest's per-run collection summary always ends with a line naming how many items were
# SELECTED by the `-m` expression -- `collected 2035 items / 2029 deselected / 6 selected` on a
# match, `... / 0 selected` when none match. We read that `N selected` field. It is the value
# pytest's OWN marker-expression engine resolves, so parametrized cases and module-global
# `pytestmark` markers are counted exactly as a real `-m <marker>` run would select them (a grep
# of `@pytest.mark.<marker>` decorators would undercount both -- e.g. this repo's 6 network tests
# come from ONE module-global `pytestmark`, not six decorators).
_SELECTED_RE = re.compile(r"(\d+) selected")


def marker_test_count(marker: str, *, python: str | None = None) -> int | None:
    """How many tests carry the given pytest marker, via pytest's own collector.

    Returns the integer count, or None when it cannot be determined (pytest/venv missing, a
    collection error, or a timeout) so the caller can show "unavailable" rather than a wrong
    number. NEVER raises -- this backs the read-only `tests.sh --status` report, which must stay
    robust and side-effect free (`--collect-only` runs NO test: no network, no sudo, no writes).

    `python` selects the interpreter to run pytest under (defaults to the current one); tests.sh
    passes its venv python so the count reflects the venv's installed pytest and plugins. pytest
    EXITS 5 when zero tests match ("no tests ran"), so success is judged by parsing the
    `N selected` field, NOT by the return code.
    """
    py = python or sys.executable
    try:
        # pyproject.toml's addopts already sets `-p no:cacheprovider` (no .pytest_cache is ever
        # written), so we do not repeat it here; `--collect-only` runs no test (no net/sudo/writes).
        proc = subprocess.run(
            [py, "-m", "pytest", "-m", marker, "--collect-only", "-q", str(_REPO / "tests")],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(_REPO),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    hits = _SELECTED_RE.findall(proc.stdout)
    if not hits:
        return None
    return int(hits[-1])


def count_field(marker: str, noun: str, *, python: str | None = None) -> str:
    """Format `marker_test_count` as the bracketed, plural-aware field `tests.sh --status`
    appends to each mode line: `[1 network test]`, `[2 root tests]`, `[0 root tests]`, or
    `[<noun> tests: unavailable]` when the count could not be taken (e.g. no built venv)."""
    n = marker_test_count(marker, python=python)
    if n is None:
        return f"[{noun} tests: unavailable]"
    if n == 1:
        return f"[1 {noun} test]"
    return f"[{n} {noun} tests]"


# --- Writer (convenience; the user-facing toggle is `tests.sh`, which writes in bash) ------
def write_modes(*, network: bool | None = None, root: bool | None = None) -> dict[str, bool]:
    """Persist the given booleans to the config file, preserving any key not passed. Returns
    the full {network, root} state written. The user-facing toggle path is
    `tests.sh --online/--offline/--user/--root` (bash), which writes the file directly and does
    not import this module; this writer is a convenience/last-line guard."""
    cur = {"network": network_enabled(), "root": root_enabled()}
    if network is not None:
        cur["network"] = bool(network)
    if root is not None:
        cur["root"] = bool(root)
    CONFIG_PATH.write_text(
        "network = {}\nroot = {}\n".format(
            "true" if cur["network"] else "false",
            "true" if cur["root"] else "false",
        )
    )
    return cur


# --- CLI (used by tests.sh --status to print each tier's marker count) --------------------
# `python _testmodes.py --count-field <marker> <noun> [python]` prints the bracketed count field
# for that marker and exits 0. tests.sh passes its venv python as the optional third arg so the
# count reflects the venv's pytest. This is deliberately crash-proof: any unexpected error prints
# the "unavailable" form and still exits 0, so the read-only --status report is never derailed by
# the count.
def _main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "--count-field":
        marker, noun = argv[1], argv[2]
        python = argv[3] if len(argv) >= 4 and argv[3] else None
        try:
            print(count_field(marker, noun, python=python))
        except Exception:                       # never let the count crash --status
            print(f"[{noun} tests: unavailable]")
        return 0
    print("usage: _testmodes.py --count-field <marker> <noun> [python]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
