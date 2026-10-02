"""configuration.py - CWD-derived VM identity, paths, and configuration.

Everything about a VM is derived from the CURRENT WORKING DIRECTORY:

    cd ~/Hypervisors/azzio && qvm install some.iso

Config object is built once (Config.from_cwd()) and threaded through every
subcommand. VM / PROC / DISK are always derived from the directory and are NOT
overridable. Everything else is read from hypervisor.cfg (priority: env > cfg > default).
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass

# Flat sibling imports: the modules live directly in libraries/ (no package), so the bare
# imports resolve against this dir once it is on sys.path. There is exactly ONE
# checks/configuration_schema module (and therefore one HypervisorError class the tests can
# catch). The launcher execs command_line_interface.py flat by absolute path and does NOT cd,
# so Config.from_cwd() resolves the VM against the caller's directory. Mirrors the flat layout
# of packages/backup + passwords.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import configuration_schema  # noqa: E402  (after the sys.path bootstrap above)
import host_resources  # noqa: E402
from checks import die  # noqa: E402
from configuration_schema import Percent  # noqa: E402

CODE = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
VARS_TMPL = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"

DEFAULT_SSH_FORWARD_PORT = 49350
# The guest port the ssh forward targets. `qvm install --ssh` turns on Secure_Shell
# and the base host port comes from the Ssh_Forward_Port key (default 49350); select_ssh_port
# starts from that base and bumps +1 past any port a running VM already holds, so the Nth
# concurrent VM lands on base+N-1. An explicit "22:host" map in Ports still overrides the base.
GUEST_SSH_PORT = 22

_HYPERVISOR_CFG_NAME = "hypervisor.cfg"

# The system disk is ALWAYS this name, in every VM dir -- not derived from the
# folder. Referenced by Config.from_cwd() and by resolve_run_disk()'s fallback.
DISK_NAME = "azzio.qcow2"

# Defaults as already-COERCED values (the same types coerce_all yields): bools are bool,
# strings are str, Ports/USB are lists, and RAM/CPUs/Disk_Size_GB default to a PERCENT of
# the host (15%) -- resolved to a concrete number per-VM by resolve_sizes().
_CFG_DEFAULTS: dict = {
    "Share_Host_GPU":                 True,
    "Network":                        "user",
    "Shared":                         False,
    "Clipboard":                      False,
    "Secure_Shell":                   False,
    "Ports":                          [],
    "Ssh_Forward_Port":               DEFAULT_SSH_FORWARD_PORT,
    "USB":                            [],
    "Fullscreen":                     False,
    "Ask_Before_Quitting_Hypervisor": False,
    "RAM":                            Percent(15),
    "CPUs":                           Percent(15),
    "Disk_Size_GB":                   Percent(15),
    "Audio":                          True,
}

# The keys whose value can be a Percent, and the host-total each resolves against.
_PERCENT_KEYS = ("RAM", "CPUs", "Disk_Size_GB")

# A single MINIMAL header block at the top of the generated file (the user asked for the
# comments to be at the top and as few as possible). No per-key inline comments.
_CFG_HEADER = (
    "### hypervisor.cfg -- True/False, strings quoted. RAM/CPUs/Disk_Size_GB: a number or"
    ' "N%" of the host.\n'
    '### Network: "user" (NAT) | "none" | a host iface ("ip -br addr"). Ports: guest:host'
    ' maps ("22:49156, 1500:49157").\n'
    "### USB: False or device path(s) (\"lsusb\", \"lsblk -o NAME,TRAN,MOUNTPOINT\")."
    " Edits apply live where they can.\n"
)


def _render_value(key: str, val) -> str:
    """Render a coerced value back to its hypervisor.cfg string form. Bools -> True/False,
    strings -> quoted, Ports -> "g:h, g2:h2", USB -> space-joined paths, Percent -> N%
    (unquoted, so a percentage reads as distinct from a quoted string; the parser still
    accepts a quoted "N%" on input)."""
    if isinstance(val, bool):
        return "True" if val else "False"
    if isinstance(val, Percent):
        return f"{val.percent}%"
    if key == "Ports":
        return '"' + ", ".join(f"{g}:{h}" for g, h in val) + '"' if val else "False"
    if key == "USB":
        return '"' + " ".join(val) + '"' if val else "False"
    if isinstance(val, str):
        return f'"{val}"'
    return str(val)


def _render_defaults() -> dict:
    """A fresh copy of the coerced defaults (helper for tests / the generator)."""
    return dict(_CFG_DEFAULTS)


def effective_defaults() -> dict:
    """The base defaults a fresh `qvm install` starts from: the built-in
    _CFG_DEFAULTS with the user's global overrides (defaults.cfg) layered on top. Coerced
    values, in schema order. This is what `qvm --configure --status` reports and what
    the bare-`azzio` TUI summarises -- deliberately EXCLUDES any per-directory hypervisor.cfg
    and env (those are per-VM, not defaults)."""
    vals = dict(_CFG_DEFAULTS)
    _apply_user_defaults(vals)
    return vals


def render_defaults_text(vals: dict) -> str:
    """Render effective defaults as plain `Key = value` lines (schema order), for the
    `--configure --status` report. Unlike _hypervisor_cfg_text this carries NO header --
    it is a status dump, not a generated cfg file."""
    return "".join(f"{key} = {_render_value(key, vals[key])}\n"
                   for key in configuration_schema.KEYS)


def _hypervisor_cfg_text(vals: dict) -> str:
    """Generate hypervisor.cfg text: a minimal header block, then one 'Key = value' per
    setting in schema order. `vals` holds COERCED values (as from _CFG_DEFAULTS or a
    HypervisorCfg's raw specs)."""
    lines = [_CFG_HEADER.rstrip("\n"), ""]
    for key in configuration_schema.KEYS:
        lines.append(f"{key} = {_render_value(key, vals[key])}")
    return "\n".join(lines) + "\n"


def resolve_sizes(vals: dict, directory: str) -> None:
    """Turn any Percent RAM/CPUs/Disk_Size_GB in `vals` into a concrete whole number,
    IN PLACE. RAM -> % of host MiB, CPUs -> % of host logical CPUs, Disk_Size_GB -> % of
    the total size of the filesystem the VM dir lives on. A plain number is left as-is.
    Done here (not in the schema) because it needs the host totals and the VM dir, which
    the pure schema deliberately does not know."""
    totals = {
        "RAM": lambda: host_resources.host_total_ram_mib(),
        "CPUs": lambda: host_resources.host_cpu_count(),
        "Disk_Size_GB": lambda: host_resources.host_total_disk_gb(directory),
    }
    for key in _PERCENT_KEYS:
        v = vals.get(key)
        if isinstance(v, Percent):
            vals[key] = host_resources.resolve_percent(v.percent, totals[key]())


@dataclass
class HypervisorCfg:
    share_host_gpu: bool
    network: str
    shared: "bool | str"
    clipboard: bool
    secure_shell: bool
    ports: list          # list of (guest, host) int tuples
    ssh_forward_port: int  # BASE host port for the guest :22 forward (select_ssh_port's floor)
    usb: list
    fullscreen: bool
    ask_before_quitting_hypervisor: bool
    disk_size_gb: int
    ram: int
    cpus: int
    audio: bool

    @property
    def ssh(self) -> bool:
        """Back-compat alias: ssh is on when the Secure_Shell toggle is on."""
        return self.secure_shell

    @property
    def ssh_port(self) -> "int | None":
        """The host port the guest's :22 forwards to (the host side of the 22:host map in
        Ports), or None when no such map is configured."""
        for guest, host in self.ports:
            if guest == GUEST_SSH_PORT:
                return host
        return None

    @classmethod
    def from_dir(cls, directory: str) -> "HypervisorCfg":
        # Layering (lowest priority first): built-in defaults -> the user's global
        # default overrides (~/.config/azzio-hypervisor/defaults.cfg) -> this directory's
        # own hypervisor.cfg -> env. So a global default changes what NEW installs and
        # unset keys resolve to, while a directory's own cfg still wins for that VM.
        vals = dict(_CFG_DEFAULTS)
        _apply_user_defaults(vals)
        path = os.path.join(directory, _HYPERVISOR_CFG_NAME)
        if os.path.isfile(path):
            raw = _migrate_legacy_keys(_parse_conf(path))
            coerced, errors = configuration_schema.coerce_all(raw)
            if errors:
                die(f"{_HYPERVISOR_CFG_NAME}: " + "; ".join(errors))
            vals.update(coerced)
        _apply_env_overrides(vals)
        resolve_sizes(vals, directory)
        return cls(**_as_dataclass_kwargs(vals))

    @classmethod
    def write(cls, directory: str, vals: dict) -> str:
        path = os.path.join(directory, _HYPERVISOR_CFG_NAME)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_hypervisor_cfg_text(vals))
        return path


# Map the coerced-values dict (canonical Title_Case keys) to the dataclass field names.
_FIELD_FOR_KEY = {
    "Share_Host_GPU": "share_host_gpu",
    "Network": "network",
    "Shared": "shared",
    "Clipboard": "clipboard",
    "Secure_Shell": "secure_shell",
    "Ports": "ports",
    "Ssh_Forward_Port": "ssh_forward_port",
    "USB": "usb",
    "Fullscreen": "fullscreen",
    "Ask_Before_Quitting_Hypervisor": "ask_before_quitting_hypervisor",
    "RAM": "ram",
    "CPUs": "cpus",
    "Disk_Size_GB": "disk_size_gb",
    "Audio": "audio",
}


def _as_dataclass_kwargs(vals: dict) -> dict:
    """Translate a coerced {CanonicalKey: value} dict to HypervisorCfg(**kwargs)."""
    return {_FIELD_FOR_KEY[k]: vals[k] for k in configuration_schema.KEYS}


# Env overrides mirror the cfg keys (uppercased), plus a few legacy names kept for
# ergonomics. Each raw env string goes through the SAME coercer as the file, so an
# override is validated exactly like a file value.
_ENV_OVERRIDES = {
    "NETWORK":        "Network",
    "DISK_SIZE_GB":   "Disk_Size_GB",
    "RAM":            "RAM",
    "CPUS":           "CPUs",
    "AUDIO":          "Audio",
    "PORTS":          "Ports",
    "SHARED":         "Shared",
    "CLIPBOARD":      "Clipboard",
    "USB":            "USB",
    "SHARE_HOST_GPU": "Share_Host_GPU",
    "SECURE_SHELL":   "Secure_Shell",
    "FULLSCREEN":     "Fullscreen",
    "ASK_QUIT":       "Ask_Before_Quitting_Hypervisor",
    # Legacy env names (pre-redesign) still honoured so existing launchers/scripts work:
    "SSH":            "Secure_Shell",              # old ssh bool
    "SSHPORT":        "Ports",                     # old bare ssh port -> the 22:<port> map
    "DISK_SIZE":      "Disk_Size_GB",              # old "200G"-style size -> normalised to GB below
}

# Legacy 1/0 env flags for booleans: keep the old ergonomics (SHARE_HOST_GPU=1). All bool
# coercers already accept "1"/"0", so these need no special path -- listed for clarity.
_ENV_BOOL_ONEZERO = {"SHARE_HOST_GPU", "SSH", "SECURE_SHELL", "CLIPBOARD",
                     "FULLSCREEN", "ASK_QUIT"}


def _apply_env_overrides(vals: dict) -> None:
    for env, key in _ENV_OVERRIDES.items():
        raw = os.environ.get(env, "")
        if not raw:
            continue
        # DISK_SIZE (legacy) may carry a unit suffix like "200G"; normalise to GB.
        if env == "DISK_SIZE":
            raw = str(_legacy_disk_size_to_gb(raw))
        ok, val, err = configuration_schema.coerce_one(key, raw)
        if not ok:
            die(f"{env}: {err} (got '{raw}')")
        if val is not None:
            vals[key] = val


def _apply_user_defaults(vals: dict) -> None:
    """Layer the user's global default overrides (defaults.cfg) over the built-in defaults.

    Imported LAZILY to avoid an import cycle (configuration_defaults imports this module).
    Each override is re-coerced through the schema; a value that fails is SILENTLY skipped
    (the file is optional and set_key already validated on write -- degrading a stray bad
    line to "use the built-in" must never fail a VM launch, unlike a directory's own
    hypervisor.cfg which dies loudly)."""
    import configuration_defaults  # deferred (avoids a config <-> defaults import cycle)
    for key, raw in _migrate_legacy_keys(configuration_defaults.load()).items():
        ok, val, _err = configuration_schema.coerce_one(key, raw)
        if ok and val is not None:
            canon = configuration_schema.canonical_key(key)
            if canon is not None:
                vals[canon] = val


def _slugify(base: str) -> str:
    """Sanitize a directory name to a [a-z0-9-] slug (matches common.sh)."""
    s = base.lower()
    s = re.sub(r"[^a-z0-9-]", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "vm"


# The explicit VM-name override key, read RAW (never through the typed schema, so it
# does not appear in `--configure`, the generated cfg, or the live-reload watcher). Env
# wins over the file so a launcher can set it without editing the cfg.
_VM_NAME_ENV = "HYPERVISOR_VM_NAME"
_VM_NAME_CFG_KEY = "vm_name"


def _vm_name_in_cfg(directory: str) -> str:
    """The raw `vm_name = ...` line in this dir's hypervisor.cfg, or '' when absent.
    Read with the ONE canonical parser (parse_conf_text) so it agrees with the loader
    about what a line is; a missing/unreadable cfg yields ''. This is the PER-DIRECTORY
    source, safe for host-wide enumeration (`qvm ls`) where an ambient env var
    must NOT leak onto every listed VM."""
    path = os.path.join(directory, _HYPERVISOR_CFG_NAME)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = parse_conf_text(fh.read())
    except OSError:
        return ""
    return raw.get(_VM_NAME_CFG_KEY, "").strip()


def _vm_name_override(directory: str) -> str:
    """An explicit VM name for the CURRENT invocation's dir, or '' when none is set.
    Order: the HYPERVISOR_VM_NAME env var wins, then the dir's `vm_name =` cfg line.

    Env is honoured ONLY here (the single-VM launcher/`from_dir` context, where the env
    belongs to THIS process). Host-wide enumeration must use _vm_name_in_cfg instead --
    reading the env there would stamp one shell's HYPERVISOR_VM_NAME onto every VM `ls`
    reports. Kept OUT of the typed schema on purpose: it is a launcher-set identity hint,
    not a tunable VM setting, so it must not clutter --configure or the generated file."""
    env = os.environ.get(_VM_NAME_ENV, "").strip()
    if env:
        return env
    return _vm_name_in_cfg(directory)


def _proc_name(vm: str) -> str:
    """The process comm for a VM slug, ALWAYS ending in '-vm' within the kernel's
    15-char comm limit (TASK_COMM_LEN-1). A short slug is just '{vm}-vm'; a long one
    (e.g. 'codelis-claudedebug') would have its '-vm' suffix truncated by a naive
    '{vm}-vm'[:15], breaking `qvm ls` (which filters on comm.endswith('-vm')) and
    `pkill -x` teardown. So we trim the SLUG to leave room for '-vm' and keep the suffix
    intact. `_running_instances` recovers the authoritative, untruncated name from the
    dir/cfg anyway -- this comm only has to reliably say 'a hypervisor VM'."""
    suffix = "-vm"
    room = 15 - len(suffix)
    return f"{vm[:room]}{suffix}"


@dataclass
class Config:
    dir: str
    vm: str
    proc: str
    disk: str
    vars: str
    shared: str
    spice_sock: str
    hypervisor_cfg_path: str
    hcfg: HypervisorCfg
    code: str
    vars_tmpl: str

    # convenience aliases into hcfg (read-only after construction). ram/cpus are
    # ints in the cfg; QEMU's -m/-smp take strings, so render them as str here.
    @property
    def disk_size_gb(self) -> int: return self.hcfg.disk_size_gb
    @property
    def disk_size(self) -> str:
        """The qcow2 size string qemu-img create wants, e.g. '200G' -- disk_size_gb
        rendered with the G suffix (the cfg now stores whole GiB, not a unit string)."""
        return f"{self.hcfg.disk_size_gb}G"
    @property
    def ram(self) -> str: return str(self.hcfg.ram)
    @property
    def cpus(self) -> str: return str(self.hcfg.cpus)
    @property
    def audio(self) -> bool: return self.hcfg.audio
    @property
    def share_host_gpu(self) -> bool: return self.hcfg.share_host_gpu

    @property
    def shared_path(self) -> str:
        """The host directory to share, honouring hcfg.shared:
        True -> the default ./shared dir; a str -> that path; False -> '' (off)."""
        s = self.hcfg.shared
        if s is True:
            return self.shared
        if isinstance(s, str) and s:
            return s
        return ""

    @property
    def virtiofs_sock(self) -> str:
        """The vhost-user UNIX socket the virtiofsd daemon listens on and QEMU
        connects to for the shared folder. Lives beside virtiofs.sock in the VM dir;
        one per VM dir, so two VMs never collide. Derived, not a stored field -- like
        the spice socket. VISIBLE (no leading dot): the hypervisor hides nothing, so
        the user can see and hand-remove any leftover if they ever need to."""
        return os.path.join(self.dir, "virtiofs.sock")

    @property
    def virtiofs_pidfile(self) -> str:
        """The pid file _spawn_virtiofsd writes for the running virtiofsd daemon
        (virtiofs.sock.pid, beside the socket). Runtime artifact -- created on `run`
        and removed on teardown -- so an external watcher can find the daemon pid
        without scanning the process table, and it is part of the codelis cache
        layout. Derived, not stored, exactly like the socket paths."""
        return os.path.join(self.dir, "virtiofs.sock.pid")

    @classmethod
    def from_cwd(cls) -> "Config":
        """The Config for the CURRENT working directory -- the default target of every
        subcommand. A thin wrapper over from_dir(os.getcwd()) so the identity-derivation
        lives in ONE place (from_dir), reused by `view`/`stop` when they target another
        VM by PID or name (that VM lives in its own directory, not the cwd)."""
        return cls.from_dir(os.getcwd())

    @classmethod
    def from_dir(cls, directory: str) -> "Config":
        """The Config for an ARBITRARY VM directory. VM identity (vm/proc) is derived
        from the directory basename -- so two dirs never collide -- and every path
        (disk, UEFI vars, sockets, cfg) is rooted at `directory`. from_cwd() is just
        from_dir(os.getcwd()); `view`/`stop` call this directly with the directory a
        resolved-by-PID/name instance reports, to act on a VM the user is NOT cd'd into."""
        d = directory
        base = os.path.basename(d)
        # VM identity: normally the directory basename, but an explicit vm_name (env
        # HYPERVISOR_VM_NAME, or a `vm_name = ...` line in hypervisor.cfg) OVERRIDES it.
        # codelis uses this so its instance -- which always lives in the fixed dir
        # <workdir>/venv/codelis (basename 'codelis') -- can still be NAMED after the work
        # directory, e.g. 'codelis-claudedebug'. When no override is set we fall back to the
        # basename, so a plain `qvm` in some dir is unchanged.
        override = _vm_name_override(d)
        vm = _slugify(override) if override else _slugify(base)
        proc = _proc_name(vm)

        hcfg = HypervisorCfg.from_dir(d)  # schema in from_dir already validated it

        return cls(
            dir=d,
            vm=vm,
            proc=proc,
            # The disk is ALWAYS azzio.qcow2 -- a fixed name, NOT derived from the
            # directory slug. Every azzio VM's system disk is the azzio image; naming
            # it after the folder (codelis.qcow2, worktest.qcow2, ...) was noise. The
            # VM identity (vm/proc, so two dirs never collide) still comes from the dir.
            disk=os.path.join(d, DISK_NAME),
            vars=os.path.join(d, "OVMF_VARS.4m.fd"),
            shared=os.path.join(d, "shared"),
            spice_sock=os.path.join(d, "spice.sock"),
            hypervisor_cfg_path=os.path.join(d, _HYPERVISOR_CFG_NAME),
            hcfg=hcfg,
            code=CODE,
            vars_tmpl=VARS_TMPL,
        )

    # --- ISO argument: REQUIRED, must be a .iso that exists ------------------
    def resolve_iso(self, arg: str) -> str:
        """A .iso file is mandatory. Accepts a path or a bare filename in CWD.

        Returns the resolved path or raises HypervisorError. Unlike the old
        behaviour, this never auto-discovers: the caller must name the file.
        """
        if not arg:
            die("an ISO is required -- e.g. 'qvm install azzio.iso'")
        if not arg.endswith(".iso"):
            die(f"expected a .iso file, got: {arg}")
        if "/" in arg:
            if not os.path.isfile(arg):
                die(f"ISO not found: {arg}")
            return arg
        in_dir = os.path.join(self.dir, arg)
        if os.path.isfile(in_dir):
            return in_dir
        if os.path.isfile(arg):
            return arg
        die(f"ISO not found in {self.dir}: {arg}")

    def find_iso(self) -> str:
        """Best-effort single *.iso in the dir for status display; '' if not exactly one."""
        matches = _glob_sorted(self.dir, ".iso")
        return matches[0] if len(matches) == 1 else ""

    # --- disk argument: REQUIRED, must be a .qcow2 that exists ---------------
    def resolve_run_disk(self, arg: str) -> str:
        """The .qcow2 to boot. Accepts a path or a bare filename in CWD; with NO
        argument it falls back to this dir's fixed azzio.qcow2 (the disk `install`
        creates), so `qvm run` just works."""
        if not arg:
            if os.path.isfile(self.disk):
                return self.disk
            die(f"no disk to boot: {self.disk} -- run 'qvm install <iso>' first")
        if not arg.endswith(".qcow2"):
            die(f"expected a .qcow2 file, got: {arg}")
        if "/" in arg:
            if not os.path.isfile(arg):
                die(f"disk not found: {arg}")
            return arg
        in_dir = os.path.join(self.dir, arg)
        if os.path.isfile(in_dir):
            return in_dir
        if os.path.isfile(arg):
            return arg
        die(f"disk not found in {self.dir}: {arg}")


def parse_conf_text(text: str) -> dict[str, str]:
    """Parse a KEY=VALUE hypervisor.cfg BODY, stripping '#' and '###' comments. The ONE
    canonical parser -- the live-reload watcher uses this too, so its validation can never
    disagree with the loader about what a line is. Splits on '\\n' only (NOT
    str.splitlines(), which also breaks on \\x0b \\x0c \\x85 \\u2028 ... and would let a
    body pass the watcher yet mis-parse in the loader)."""
    out: dict[str, str] = {}
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0]   # '###' is just '#' repeated -> same split point
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _parse_conf(path: str) -> dict[str, str]:
    """Parse a KEY=VALUE hypervisor.cfg file (matches common.sh)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_conf_text(fh.read())


# Pre-redesign key names, mapped to their current names so an old hypervisor.cfg keeps
# working. Case-insensitive: matched against the lowercased raw key. The current key
# wins if BOTH are present. `ssh_guest_to_host_port_forward`'s bare-number value is
# accepted by _coerce_ports as the 22:<n> ssh map, so codelis -- which still writes that
# key -- keeps forwarding guest :22 to the same host port with no change on its side.
_LEGACY_KEY_ALIASES = {
    "sshd": "Secure_Shell",
    "ssh": "Secure_Shell",
    "ssh_guest_to_host_port_forward": "Ports",
}

# A legacy disk_size value carried a unit suffix (200G / 1024M / 2T). We convert it to
# whole GiB for the new Disk_Size_GB key (rounding up so a sub-GiB size never becomes 0).
_LEGACY_DISK_RE = re.compile(r"^\s*([0-9]+)\s*([MGT])\s*$", re.IGNORECASE)
_UNIT_TO_MIB = {"M": 1, "G": 1024, "T": 1024 * 1024}


def _legacy_disk_size_to_gb(value: str) -> int:
    """Convert a legacy disk_size string (e.g. '200G', '1024M', '2T') to whole GiB. A
    value that is already a plain number or a percentage is returned unchanged (so the
    new Disk_Size_GB coercer handles it)."""
    m = _LEGACY_DISK_RE.match(value or "")
    if not m:
        return value  # not a unit string -> let the normal coercer deal with it
    mib = int(m.group(1)) * _UNIT_TO_MIB[m.group(2).upper()]
    return max(1, -(-mib // 1024))  # ceil-divide to GiB, floored at 1


def _migrate_legacy_keys(raw: dict) -> dict:
    """Rewrite a raw {key: value(str)} map so a pre-redesign hypervisor.cfg (or a
    codelis-written one) loads under the new schema: rename legacy keys to their current
    names (case-insensitively; current name wins if both are present) and convert a legacy
    `disk_size = 200G` value to whole GiB. Recognised current keys pass through untouched;
    the case-insensitive coerce layer maps their casing."""
    out: dict = {}
    # First copy through everything, converting a legacy unit-suffixed disk_size value.
    for key, val in raw.items():
        low = key.strip().lower()
        if low in _LEGACY_KEY_ALIASES:
            continue  # handled below, so an explicit current key can win
        if low == "disk_size":
            out.setdefault("Disk_Size_GB", str(_legacy_disk_size_to_gb(val)))
            continue
        out[key] = val
    # Then layer legacy-aliased keys in, without clobbering a current key already present.
    for key, val in raw.items():
        low = key.strip().lower()
        new = _LEGACY_KEY_ALIASES.get(low)
        if new is None:
            continue
        canon_present = any(configuration_schema.canonical_key(k) == new for k in out)
        if not canon_present:
            out[new] = val
    return out


def _glob_sorted(directory: str, suffix: str) -> list[str]:
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(suffix))
    except OSError:
        return []
    paths = [os.path.join(directory, n) for n in names]
    return [p for p in paths if os.path.isfile(p)]   # skip a dir named like *.iso


def select_ssh_port(cfg: Config) -> int:
    """The forwarded host port for guest :22 -- the SSH port-forward manager.

    The base (floor) is, in order: an explicit "22:host" map in Ports (a user pin always
    wins), else this VM's Ssh_Forward_Port cfg key, else the built-in DEFAULT_SSH_FORWARD_PORT
    (49350). From that floor we bump +1 past every port ALREADY CLAIMED so two VMs never
    share one host port: a port is "claimed" if a running hypervisor VM's cfg advertises it
    (so the first VM gets the base, the second base+1, the Nth base+N-1 -- deterministic even
    before a guest's sshd is up), OR if a live socket is already bound there (belt-and-braces
    against non-VM listeners and the same-instant TOCTOU). Never climbs past the max valid TCP
    port (65535) -- if everything up to there is taken it dies cleanly rather than letting the
    bump reach 65536 and crash socket.bind (OverflowError)."""
    base = cfg.hcfg.ssh_port or cfg.hcfg.ssh_forward_port or DEFAULT_SSH_FORWARD_PORT
    claimed = _ports_claimed_by_running_vms(exclude_dir=cfg.dir)
    port = base
    while port <= configuration_schema._MAX_PORT:
        if port not in claimed and not _port_in_use(port):
            return port
        port += 1
    die(f"no free host port available at or above {base} "
        f"(up to {configuration_schema._MAX_PORT})")


def _ports_claimed_by_running_vms(exclude_dir: str = "") -> set:
    """The set of host ssh ports every OTHER running hypervisor VM already advertises, so a
    new VM bumps past them and the Nth concurrent VM lands on base+N-1. Reads each running
    VM's cfg via the enumeration backend (vm_instances._running_instances) -- imported
    LAZILY here because vm_instances imports THIS module (a top-level import would be a
    cycle). `exclude_dir` drops this VM's own dir so a relaunch of an already-running dir
    does not treat its own pinned port as a conflict. Best-effort: any error (no /proc,
    a test stub) degrades to an empty set, so port selection still works -- it just loses
    the cross-instance bump and falls back to the live-socket probe alone."""
    try:
        import vm_instances  # deferred (avoids a config <-> vm_instances import cycle)
        exclude = os.path.realpath(exclude_dir) if exclude_dir else ""
        claimed = set()
        for inst in vm_instances._running_instances():
            if exclude and os.path.realpath(inst.get("dir", "")) == exclude:
                continue
            port = inst.get("ssh_port")
            if port is not None:
                claimed.add(port)
        return claimed
    except Exception:
        return set()


def _port_in_use(port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True
        except OverflowError:
            return True   # out of the 0..65535 range -> not a usable port
