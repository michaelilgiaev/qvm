"""configuration_defaults.py - user-wide default overrides for `qvm`.

`qvm` is a PER-DIRECTORY tool: every VM's settings live in that folder's
hypervisor.cfg, and the base values a fresh `qvm install` starts from are the
hardcoded configuration._CFG_DEFAULTS. This module is the small, user-owned config that
lets those base defaults be overridden ONCE, globally, so every NEW VM inherits them.
It is the state behind the `qvm --configure` subcommand and the bare-`azzio`
TUI's Hypervisor screen. A directory's own hypervisor.cfg still WINS for that VM --
configuration.HypervisorCfg.from_dir layers this file UNDER the per-directory cfg (and
under env), so changing the defaults only affects new installs and keys a VM leaves unset.

WHERE. The app itself installs root-owned under /usr/local/lib/azzio-hypervisor, which a
normal user cannot write to, so the defaults land somewhere the USER owns:
~/.config/azzio-hypervisor/defaults.cfg (XDG-style, 0644 -- no secrets). Mirrors
packages/backup/config.py's CONFIG_PATH convention.

FORMAT. The SAME `key = value` text as hypervisor.cfg (parsed by the ONE canonical
configuration.parse_conf_text), holding ONLY the keys the user overrode. Every value goes
through the SAME configuration_schema coercers, so a bad defaults value is rejected exactly
like a bad hypervisor.cfg value (set_key refuses it; a corrupt file on load degrades to
"no overrides" so a VM launch never fails just because this optional file is damaged).
"""

from __future__ import annotations

import os
import sys

# Flat sibling imports: the modules live directly in libraries/ (no package). The
# sys.path bootstrap makes the bare imports resolve when run flat by absolute path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import configuration  # noqa: E402  (after the sys.path bootstrap above)
import configuration_schema  # noqa: E402

_DEFAULTS_FILE_NAME = "defaults.cfg"


def defaults_path() -> str:
    """Absolute path to the user's defaults.cfg, honouring $XDG_CONFIG_HOME (falling back
    to ~/.config). Computed on each call (NOT a module constant) so a changed
    XDG_CONFIG_HOME -- and the test harness that sets it -- is always respected. Same
    location convention as backup/config.CONFIG_PATH."""
    base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return os.path.join(base, "azzio-hypervisor", _DEFAULTS_FILE_NAME)


def exists() -> bool:
    """True if the user has ever set a default (the file is present)."""
    return os.path.isfile(defaults_path())


def load() -> dict:
    """Return the raw {key: value(str)} override map, keeping ONLY recognised schema keys.

    A missing, unreadable, or un-parseable file all degrade to {} (no overrides) -- a VM
    launch must never fail just because this optional file is absent or damaged; it simply
    falls back to the built-in defaults. Values stay as STRINGS here (the same shape a
    hypervisor.cfg body yields); coercion happens where they are layered in from_dir, so
    this module and the loader share the one schema."""
    path = defaults_path()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = configuration.parse_conf_text(fh.read())
    except OSError:
        return {}
    # Keep only recognised settings, re-keyed to the CANONICAL Title_Case name (so a file
    # written in any casing, or with a legacy key, still resolves through the schema).
    out = {}
    for k, v in raw.items():
        canon = configuration_schema.canonical_key(k)
        if canon is not None:
            out[canon] = v
    return out


def save(overrides: dict) -> str:
    """Persist ``overrides`` (only recognised schema keys) to defaults_path(), 0644,
    creating the dir. Writes in schema order, one `key = value` per line. Returns the path
    written. Callers that need validation go through set_key(); save() itself trusts its
    input (from_dir re-coerces on load, so a stray value can never brick a launch)."""
    path = defaults_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    kept = {k: overrides[k] for k in configuration_schema.KEYS if k in overrides}
    lines = [f"{k} = {kept[k]}" for k in configuration_schema.KEYS if k in kept]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(path, 0o644)
    return path


def set_key(key: str, raw: str) -> tuple[bool, str]:
    """Validate ``raw`` for ``key`` via the schema and, on success, merge it into the
    defaults file. Returns (ok, error): ok=False leaves the file UNTOUCHED and error is a
    human message (unknown key, or the coercer's reason). Persists the RAW string (not the
    coerced value) so the file stays in the same textual form as a hypervisor.cfg."""
    canon = configuration_schema.canonical_key(key)
    if canon is None:
        known = ", ".join(configuration_schema.KEYS)
        return False, f"unknown key: {key} (known keys: {known})"
    ok, _val, err = configuration_schema.coerce_one(canon, raw)
    if not ok:
        return False, f"{canon}: {err} (got '{raw}')"
    overrides = load()
    overrides[canon] = raw.strip()
    save(overrides)
    return True, ""


def reset() -> None:
    """Remove the defaults file (back to the built-in defaults). Safe when absent."""
    try:
        os.remove(defaults_path())
    except OSError:
        pass
