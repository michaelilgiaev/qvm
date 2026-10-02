"""configuration_schema.py - the typed hypervisor.cfg schema, coercion, and validation.

hypervisor.cfg is a real typed config: each key coerces to a Python type and is
validated. This module is the SINGLE SOURCE OF TRUTH for that. Two callers share it:

  * configuration.HypervisorCfg.from_dir -- parses the file into typed values.
  * configuration_watcher -- on every live save, re-runs coerce_all(); an empty error
    list means "valid -> apply", a non-empty one means "invalid -> revert".

Everything here is PURE (str in, typed value or error string out): no I/O, no
process launch. That is what makes the live-reload accept/revert decision
unit-testable without a running VM. (The one seam: a percentage size like "15%" is
kept AS a percent spec here -- see _PercentOrInt -- and turned into a concrete
number later, in configuration, where the host totals and the VM dir are known.)

The FILE FORMAT this validates (what `install` writes):
  * keys are Title_Case (Share_Host_GPU, Secure_Shell, ...); lookup is
    case-insensitive, and legacy lowercase keys still resolve.
  * bools render as True / False (legacy true/false/on/off/1/0/yes/no still parse).
  * strings are quoted (Network = "eno1"); the quotes are optional on input.
  * RAM / CPUs / Disk_Size_GB take a plain number OR a percentage of the host ("15%").
  * Ports is a comma/space list of guest:host maps (Ports = "22:49156, 1500:49157").

Type model (per key):
  bool     : Share_Host_GPU, Clipboard, Secure_Shell, Fullscreen,
             Ask_Before_Quitting_Hypervisor, Audio
  string   : Network              (user | none | <interface name>)
  shared   : Shared               (False | True/empty = working dir | /abs/path)
  usb      : USB                  (False/empty | /dev/... [more /dev/...])
  ports    : Ports                (guest:host maps; the 22:host map is the ssh forward)
  port     : Ssh_Forward_Port     (the BASE host port the guest's :22 forward starts from)
  int|pct  : RAM, CPUs, Disk_Size_GB   (a whole number, or "N%" of the host total)
"""

from __future__ import annotations

import re

# --- primitive coercers: each returns (ok, value, error) --------------------
# value is meaningful only when ok is True.


def _as_str(raw):
    """Every value from a parsed cfg file is a str; but a caller could hand
    coerce_all an already-typed dict. Reject non-str defensively so a coercer
    never raises AttributeError on `.strip()`."""
    return raw if isinstance(raw, str) else None


def _unquote(s: str) -> str:
    """Strip ONE matching pair of surrounding single or double quotes. The new file
    writes strings quoted (Network = "eno1"); quotes are optional on input, so an old
    unquoted value (network = eno1) and a hand-typed 'user' both parse the same."""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


# Booleans accept the new True/False AND every legacy spelling the format ever used
# (true/false, on/off -- the old Audio enum, 1/0 -- the old env flags, yes/no).
_BOOL_TRUE = {"true", "on", "1", "yes"}
_BOOL_FALSE = {"false", "off", "0", "no"}


def _coerce_bool(raw):
    s = _as_str(raw)
    if s is None:
        return False, None, "must be True or False"
    low = _unquote(s).lower()
    if low in _BOOL_TRUE:
        return True, True, ""
    if low in _BOOL_FALSE:
        return True, False, ""
    return False, None, "must be True or False"


def _coerce_int(raw):
    s = _as_str(raw)
    if s is not None:
        s = _unquote(s)
    # ASCII-only: str.isdigit() is also True for superscripts/other-script digits
    # (e.g. "²", Arabic-Indic) that int() then fails to parse -- guard with
    # isascii() so those are rejected cleanly instead of raising ValueError.
    if not (s and s.isascii() and s.isdigit()):   # rejects None, "", "-4", "3.5", "²"
        return False, None, "must be a positive whole number"
    n = int(s)
    if n < 1:                                       # rejects "0"
        return False, None, "must be >= 1"
    return True, n, ""


_MAX_PORT = 65535


def _coerce_port_number(s: str):
    """A single TCP port: 1..65535. Shared by _coerce_ports for both sides of a map."""
    if not (s and s.isascii() and s.isdigit()):
        return False, None, "must be a whole number"
    n = int(s)
    if n < 1 or n > _MAX_PORT:
        return False, None, f"must be in 1..{_MAX_PORT}"
    return True, n, ""


class Percent:
    """A percentage-of-the-host size spec (e.g. 15 for "15%"). Kept as its own type so
    a coerced value is unambiguously "resolve me against the host total later"
    (configuration does that, where the totals and VM dir are known). Equality/repr are
    defined so the watcher can compare values and tests can assert on them."""

    __slots__ = ("percent",)

    def __init__(self, percent: int):
        self.percent = percent

    def __eq__(self, other):
        return isinstance(other, Percent) and other.percent == self.percent

    def __hash__(self):
        return hash(("Percent", self.percent))

    def __repr__(self):
        return f"Percent({self.percent})"


_PERCENT_RE = re.compile(r"^([0-9]+)\s*%$")


def _coerce_int_or_percent(raw):
    """A whole number OR a percentage of the host ("15%", 1..100). Returns an int for a
    plain number and a Percent for a percentage; configuration.resolve_sizes() turns the
    Percent into a concrete number. This backs RAM, CPUs and Disk_Size_GB."""
    s = _as_str(raw)
    if s is None:
        return False, None, 'must be a whole number or a percentage like "15%"'
    s = _unquote(s)
    m = _PERCENT_RE.match(s)
    if m:
        pct = int(m.group(1))
        if not 1 <= pct <= 100:
            return False, None, "percentage must be in 1..100"
        return True, Percent(pct), ""
    ok, val, _err = _coerce_int(s)
    if ok:
        return True, val, ""
    return False, None, 'must be a whole number or a percentage like "15%"'


def _coerce_audio(raw):
    """Audio is now a plain bool (True/False); the legacy on/off spelling still parses
    via _coerce_bool's _BOOL_TRUE/_FALSE sets, so an old `audio = on` keeps working."""
    return _coerce_bool(raw)


def _coerce_forward_port(raw):
    """A single TCP port (1..65535): the BASE host port the guest's :22 forward starts
    from. select_ssh_port uses it as the floor and bumps +1 past any port a running VM
    already holds, so the Nth concurrent VM lands on base+N-1. Quotes are optional on
    input (Ssh_Forward_Port = 49350 and = "49350" both parse), matching the other keys."""
    s = _as_str(raw)
    if s is None:
        return False, None, f"must be a whole number in 1..{_MAX_PORT}"
    return _coerce_port_number(_unquote(s))


# A plausible Linux network-interface name: letters, digits, and . _ - @ (no
# whitespace, no slash). Covers eno1, enp5s0, wlan0, br0, vlan.10, bond0.
_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]*$")


def _coerce_network(raw):
    s = _as_str(raw)
    if s is None:
        return False, None, "must be user, none, or a host interface name"
    s = _unquote(s)
    if s in ("user", "none"):
        return True, s, ""
    if _IFACE_RE.match(s):
        return True, s, ""
    return False, None, 'must be "user", "none", or a host interface name (see "ip -br addr")'


def _coerce_shared(raw):
    """False -> off; True/'' -> enabled at the working dir; else an absolute host path."""
    s = _as_str(raw)
    if s is None:
        return False, None, 'must be False, empty (working dir), or an absolute path'
    s = _unquote(s)
    low = s.lower()
    if low in _BOOL_FALSE:
        return True, False, ""
    if low in _BOOL_TRUE or s == "":
        return True, True, ""          # True == "the working dir" sentinel
    if s.startswith("/"):
        return True, s, ""
    return False, None, 'must be False, empty (working dir), or an absolute path'


def _coerce_usb(raw):
    """False/'' -> []; otherwise whitespace/comma-separated ABSOLUTE device paths.

    Legacy tolerance: pre-redesign cfgs wrote a boolean (`usb = false`/`true`); both
    map to [] (no device passthrough) so an old hypervisor.cfg still loads."""
    s = _as_str(raw)
    if s is None:
        return False, None, "must be False or absolute device path(s)"
    s = _unquote(s)
    if s == "" or s.lower() in (_BOOL_FALSE | _BOOL_TRUE):
        return True, [], ""
    tokens = [t for t in re.split(r"[,\s]+", s) if t]
    for t in tokens:
        if not t.startswith("/"):
            return False, None, (
                f"USB entry '{t}' must be an absolute device path "
                "(e.g. /dev/bus/usb/003/004; see 'lsusb' and "
                "'lsblk -o NAME,TRAN,MOUNTPOINT')"
            )
    return True, tokens, ""


def _coerce_ports(raw):
    """A comma/space list of guest:host port maps (Ports = "22:49156, 1500:49157").

    Each map forwards the guest's <guest> port to the host's <host> port; the map whose
    GUEST port is 22 is the VM's ssh forward (configuration.select_ssh_port reads it).
    Returns a list of (guest, host) int tuples. False/'' -> [] (no forwards).

    Legacy tolerance: a bare number (the old ssh_guest_to_host_port_forward = 49156)
    is read as the ssh map 22:<number>, so an old cfg -- and codelis, which still writes
    that key -- keeps forwarding guest :22 to the same host port."""
    s = _as_str(raw)
    if s is None:
        return False, None, 'must be host:guest port maps like "22:49156"'
    s = _unquote(s)
    if s == "" or s.lower() in (_BOOL_FALSE | _BOOL_TRUE):
        return True, [], ""
    out: list = []
    seen_guest: set = set()
    for token in (t for t in re.split(r"[,\s]+", s) if t):
        if ":" not in token:
            # Legacy bare number -> the ssh forward (guest 22 -> that host port).
            ok, host, err = _coerce_port_number(token)
            if not ok:
                return False, None, f"port '{token}' {err}"
            guest = 22
        else:
            g, h = token.split(":", 1)
            okg, guest, errg = _coerce_port_number(g.strip())
            if not okg:
                return False, None, f"guest port '{g.strip()}' {errg}"
            okh, host, errh = _coerce_port_number(h.strip())
            if not okh:
                return False, None, f"host port '{h.strip()}' {errh}"
        if guest in seen_guest:
            return False, None, f"duplicate guest port {guest} in Ports"
        seen_guest.add(guest)
        out.append((guest, host))
    return True, out, ""


# --- the schema: canonical key -> coercer -----------------------------------
# Order here is also the ORDER KEYS ARE WRITTEN in the generated file. Keys are
# Title_Case; lookup is case-insensitive (see _canonical / coerce_one).
SCHEMA = {
    "Share_Host_GPU":                 _coerce_bool,
    "Network":                        _coerce_network,
    "Shared":                         _coerce_shared,
    "Clipboard":                      _coerce_bool,
    "Secure_Shell":                   _coerce_bool,
    "Ports":                          _coerce_ports,
    "Ssh_Forward_Port":               _coerce_forward_port,
    "USB":                            _coerce_usb,
    "Fullscreen":                     _coerce_bool,
    "Ask_Before_Quitting_Hypervisor": _coerce_bool,
    "RAM":                            _coerce_int_or_percent,
    "CPUs":                           _coerce_int_or_percent,
    "Disk_Size_GB":                   _coerce_int_or_percent,
    "Audio":                          _coerce_audio,
}

KEYS = tuple(SCHEMA)

# Case-insensitive canonical-key lookup: lower(key) -> the Title_Case key in SCHEMA.
# So Secure_Shell / secure_shell / SECURE_SHELL all resolve to the one schema entry.
_CANON = {k.lower(): k for k in SCHEMA}


def canonical_key(key: str) -> "str | None":
    """The Title_Case schema key a (case-insensitively matched) key maps to, or None if
    it is not a recognised setting."""
    return _CANON.get(key.strip().lower())


def coerce_one(key: str, raw: str):
    """Coerce a single key's raw string. (ok, value, error). Unknown key -> ok with
    value None (caller ignores it). Key match is case-insensitive."""
    canon = canonical_key(key)
    if canon is None:
        return True, None, ""
    return SCHEMA[canon](raw)


def coerce_all(raw: dict) -> tuple[dict, list[str]]:
    """Coerce a whole KEY=VALUE(str) map to typed values, keyed by CANONICAL key name.

    Returns (values, errors). Unknown keys are ignored (never errors). Each bad value
    contributes one 'Key: reason' string to errors; a non-empty errors list is the
    signal to REVERT a live edit. Keys absent from raw are simply absent from values
    (the caller layers these over the defaults). Later duplicates (e.g. both `Secure_Shell`
    and legacy `ssh`) overwrite earlier ones for the same canonical key."""
    values: dict = {}
    errors: list[str] = []
    for key, rawval in raw.items():
        canon = canonical_key(key)
        if canon is None:
            continue
        ok, val, err = SCHEMA[canon](rawval)
        if ok:
            values[canon] = val
        else:
            errors.append(f"{canon}: {err} (got '{rawval}')")
    return values, errors
