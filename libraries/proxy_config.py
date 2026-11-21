"""proxy_config.py - proxy URL / proxies-file parsing and the failover decision.

hypervisor.cfg `Proxy` is off (`False`), `True` (the file named `proxies`
next to hypervisor.cfg, one URL per line), one URL (`socks4://`, `socks5://`,
or `http://`), or that same kind of file name. `Proxy_Kill_Switch` decides
what a lost proxy means:

  * True  -> cut that guest's internet as soon as the proxy stops answering.
             Do not fall through to the host's real route, and do not rotate.
  * False -> keep using a proxy. When the value named a file and the current
             proxy stops answering, try proxies PARALLEL_ATTEMPTS at a time
             until one accepts a tunnel, then keep that one. A proxy that
             still answers is not replaced because another is faster.

This module is pure: it reads a file only in load_plan(), and the failover
decision takes a clock reading instead of sleeping. The network namespace that
actually carries guest packets lives in proxy_runtime.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# How often the running gateway asks the current proxy if it is still up, and
# how long that connect may take. A connect that finishes inside the window is
# a live proxy no matter how slow it was. A refused connection fails at once.
# The window is long enough that one slow reply is not mistaken for a dead proxy.
PROBE_EVERY_S = 1.0
PROBE_TIMEOUT_S = 8.0

# How many proxies from a proxies file are dialed together when the current one
# is not known to work. The first tunnel that comes up is kept. The next group
# is started only when the whole group is down.
PARALLEL_ATTEMPTS = 10

_OFF = {"", "false", "off", "none", "no", "0"}
# True selects the proxies file. These spellings match the other bools.
_ON = {"true", "on", "yes", "1"}

# The file Proxy=True reads. It sits next to hypervisor.cfg.
PROXIES_FILE = "proxies"

_SPEC_ERROR = (
    'must be False, True (the proxies file), a socks4://, socks5://, or '
    'http:// URL, or a file name such as "proxies"'
)

# socks4/socks5/http host:port, optional user or user:pass@. IPv6 in brackets.
_URL_RE = re.compile(
    r"^(?P<scheme>socks4|socks5|http)://"
    r"(?:(?P<user>[^:@/\s]+)(?::(?P<password>[^@/\s]*))?@)?"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[^:/\s]+)"
    r":(?P<port>[0-9]{1,5})$",
    re.IGNORECASE,
)

# A file name in the same directory as hypervisor.cfg. No directory separators,
# so `proxies` is accepted and `../proxies` is not.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True)
class ProxyEndpoint:
    """One upstream proxy. `scheme` is `socks4`, `socks5`, or `http`."""

    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    def render(self) -> str:
        """The URL form, with a password redacted so logs can print it."""
        auth = ""
        if self.username:
            secret = ":***" if self.password else ""
            auth = f"{self.username}{secret}@"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{auth}{host}:{self.port}"


@dataclass(frozen=True)
class ProxyPlan:
    """What `Proxy` resolved to. `from_file` is what allows failover."""

    enabled: bool
    from_file: bool
    source: str
    endpoints: tuple[ProxyEndpoint, ...]


@dataclass(frozen=True)
class HealthState:
    """Where the gateway is in the proxy list, and whether the guest is cut off."""

    index: int
    down_since: "float | None"
    killed: bool


def _unquote(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1].strip()
    return s


def parse_endpoint(url: str) -> "ProxyEndpoint | None":
    """Parse one proxy URL, or None when it is not a socks4/socks5/http URL."""
    match = _URL_RE.match(url.strip())
    if not match:
        return None
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        return None
    host = match.group("host")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return None
    return ProxyEndpoint(
        scheme=match.group("scheme").lower(),
        host=host,
        port=port,
        username=match.group("user") or "",
        password=match.group("password") or "",
    )


def coerce_proxy_spec(raw) -> tuple[bool, object, str]:
    """Schema coercer for `Proxy`. (ok, value, error).

    Value is False when the proxy is off, True when it should read the
    `proxies` file, or the original URL / file name string. The file itself
    is not opened here -- the schema stays free of I/O, and a missing file
    is reported at boot.
    """
    if not isinstance(raw, str):
        return False, None, _SPEC_ERROR
    text = _unquote(raw)
    low = text.lower()
    if low in _OFF:
        return True, False, ""
    if low in _ON:
        return True, True, ""
    if "://" in text:
        if parse_endpoint(text) is None:
            return False, None, _SPEC_ERROR
        return True, text, ""
    if _NAME_RE.match(text):
        return True, text, ""
    return False, None, _SPEC_ERROR


def parse_proxy_list(text: str) -> tuple[list[ProxyEndpoint], list[str]]:
    """Split a proxies file into endpoints. Blank lines and # comments are skipped.

    Returns (endpoints, errors). Each error names the 1-based line that failed.
    """
    endpoints: list[ProxyEndpoint] = []
    errors: list[str] = []
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        endpoint = parse_endpoint(line)
        if endpoint is None:
            errors.append(
                f"line {number}: expected socks4://, socks5://, or http://host:port, got {line!r}"
            )
            continue
        endpoints.append(endpoint)
    return endpoints, errors


def load_plan(directory: str, spec) -> ProxyPlan:
    """Resolve a coerced Proxy value against `directory`.

    Raises FileNotFoundError or ValueError when a named file is missing, empty,
    or contains a bad line. A False spec returns a disabled plan. True reads
    the file named `proxies`.
    """
    if spec is False or spec is None or spec == "":
        return ProxyPlan(False, False, "", ())
    if spec is True:
        return _plan_from_file(directory, PROXIES_FILE)
    if "://" in str(spec):
        endpoint = parse_endpoint(str(spec))
        if endpoint is None:
            raise ValueError(f"invalid proxy URL: {spec}")
        return ProxyPlan(True, False, "", (endpoint,))
    return _plan_from_file(directory, str(spec))


def _plan_from_file(directory: str, name: str) -> ProxyPlan:
    """Read `name` from `directory` into a plan that may fail over."""
    path = os.path.join(directory, name)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise FileNotFoundError(
            f"{name} (next to hypervisor.cfg) could not be read: {exc.strerror or exc}"
        ) from exc
    endpoints, errors = parse_proxy_list(text)
    if errors:
        raise ValueError(f"{name}: " + "; ".join(errors))
    if not endpoints:
        raise ValueError(f"{name}: no proxy URLs")
    return ProxyPlan(True, True, name, tuple(endpoints))


def describe(plan: ProxyPlan, kill_switch: bool) -> str:
    """One stderr line for boot, naming the proxy and the kill switch."""
    first = plan.endpoints[0].render()
    if plan.from_file:
        where = f"file {plan.source} ({len(plan.endpoints)} proxies), starting at {first}"
    else:
        where = first
    flag = "on" if kill_switch else "off"
    return f"Proxy: {where}. Kill switch: {flag}."


def batch_indexes(count: int, start: int, size: int) -> list[list[int]]:
    """Walk `count` entries once, from `start`, in groups of `size`.

    The last group is shorter when the list does not divide evenly. Groups do
    not overlap and the walk does not repeat an index.
    """
    if count < 1 or size < 1:
        return []
    groups: list[list[int]] = []
    offset = 0
    while offset < count:
        group = min(size, count - offset)
        groups.append([(start + offset + i) % count for i in range(group)])
        offset += group
    return groups


def note_probe(
    state: HealthState,
    *,
    ok: bool,
    now: float,
    kill_switch: bool,
    from_file: bool,
    count: int,
) -> tuple[HealthState, str]:
    """PURE. Fold one reachability result into `state`.

    Returns (new_state, action). action is `none`, `kill`, `restore`, or
    `switch`. `ok` means the proxy answered. How long that took is not an
    input: a slow answer is still an answer. A kill switch cuts the guest on
    the first failure and never rotates. Without it, a proxies file with more
    than one URL rotates on that same failure. A single URL has nowhere to
    rotate to, so it stays put until it answers again.
    """
    if count < 1:
        return state, "none"
    index = state.index % count
    if ok:
        action = "restore" if state.killed else "none"
        return HealthState(index, None, False), action
    down_since = now if state.down_since is None else state.down_since
    if kill_switch:
        action = "none" if state.killed else "kill"
        return HealthState(index, down_since, True), action
    if from_file and count > 1:
        return HealthState((index + 1) % count, None, False), "switch"
    return HealthState(index, down_since, False), "none"
