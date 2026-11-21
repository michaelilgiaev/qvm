"""proxy_config.py - proxy URL / proxies-file parsing and the failover decision.

hypervisor.cfg `Proxy` is either off, one URL (`socks5://host:port` or
`http://host:port`), or the name of a file sitting next to hypervisor.cfg
(the usual name is `proxies`) with one URL per line. `Proxy_Kill_Switch`
decides what a lost proxy means:

  * True  -> cut that guest's internet as soon as the proxy stops answering.
             Do not fall through to the host's real route, and do not rotate.
  * False -> keep using a proxy. When the value named a file and the current
             proxy has been down for more than 10 seconds, move to the next
             URL in the file.

This module is pure: it reads a file only in load_plan(), and the failover
decision takes a clock reading instead of sleeping. The network namespace that
actually carries guest packets lives in proxy_runtime.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# A lost proxy is rotated only once it has been unreachable for MORE than this
# many seconds. The kill switch does not wait and does not rotate.
FAILOVER_AFTER_S = 10.0

# How often the running gateway asks the current proxy if it is still up.
PROBE_EVERY_S = 1.0
PROBE_TIMEOUT_S = 2.0

_OFF = {"", "false", "off", "none", "no", "0"}
# A proxy is a URL or a file name. True/yes/1 would otherwise look like a file.
_ON = {"true", "on", "yes", "1"}

# socks5://host:port or http://host:port, optional user:pass@. IPv6 in brackets.
_URL_RE = re.compile(
    r"^(?P<scheme>socks5|http)://"
    r"(?:(?P<user>[^:@/\s]+):(?P<password>[^@/\s]+)@)?"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[^:/\s]+)"
    r":(?P<port>[0-9]{1,5})$",
    re.IGNORECASE,
)

# A file name in the same directory as hypervisor.cfg. No directory separators,
# so `proxies` is accepted and `../proxies` is not.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True)
class ProxyEndpoint:
    """One upstream proxy. `scheme` is `socks5` or `http`."""

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
    """Parse one proxy URL, or None when it is not a socks5/http URL."""
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

    Value is False when the proxy is off, or the original URL / file name
    string when it is on. The file itself is not opened here -- the schema
    stays free of I/O, and a missing file is reported at boot.
    """
    if not isinstance(raw, str):
        return False, None, (
            'must be False, a proxy URL like "socks5://host:port", '
            'or a file name such as "proxies"'
        )
    text = _unquote(raw)
    low = text.lower()
    if low in _OFF:
        return True, False, ""
    if low in _ON:
        return False, None, (
            'must be False, a proxy URL like "socks5://host:port", '
            'or a file name such as "proxies"'
        )
    if "://" in text:
        if parse_endpoint(text) is None:
            return False, None, (
                'must be a socks5://host:port or http://host:port URL '
                "(or a file name such as proxies)"
            )
        return True, text, ""
    if _NAME_RE.match(text):
        return True, text, ""
    return False, None, (
        'must be False, a proxy URL like "socks5://host:port", '
        'or a file name such as "proxies"'
    )


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
                f"line {number}: expected socks5://host:port or http://host:port, got {line!r}"
            )
            continue
        endpoints.append(endpoint)
    return endpoints, errors


def load_plan(directory: str, spec) -> ProxyPlan:
    """Resolve a coerced Proxy value against `directory`.

    Raises FileNotFoundError or ValueError when a named file is missing, empty,
    or contains a bad line. A False spec returns a disabled plan.
    """
    if spec is False or spec is None or spec == "":
        return ProxyPlan(False, False, "", ())
    if "://" in str(spec):
        endpoint = parse_endpoint(str(spec))
        if endpoint is None:
            raise ValueError(f"invalid proxy URL: {spec}")
        return ProxyPlan(True, False, "", (endpoint,))
    name = str(spec)
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


def note_probe(
    state: HealthState,
    *,
    ok: bool,
    now: float,
    kill_switch: bool,
    from_file: bool,
    count: int,
    failover_after: float = FAILOVER_AFTER_S,
) -> tuple[HealthState, str]:
    """PURE. Fold one reachability probe into `state`.

    Returns (new_state, action). action is `none`, `kill`, `restore`, or
    `switch`. A kill switch cuts the guest on the first failed probe and never
    rotates. Without it, a proxies file rotates only after the current proxy
    has been down for more than `failover_after` seconds. A single URL has
    nowhere to rotate to, so it stays put until it answers again.
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
    if from_file and count > 1 and (now - down_since) > failover_after:
        return HealthState((index + 1) % count, now, False), "switch"
    return HealthState(index, down_since, False), "none"
