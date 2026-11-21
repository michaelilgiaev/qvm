"""proxy_config.py - proxy URL / proxies-file parsing and the failover decision.

hypervisor.cfg `Proxy` is off (`False`), `True` (the file named `proxies`
next to hypervisor.cfg, one URL per line), one URL (`socks4://`, `socks5://`,
or `http://`), or that same kind of file name. `Proxy_Kill_Switch` decides
what a lost proxy means:

  * True  -> cut that guest's internet as soon as the proxy stops answering.
             Do not fall through to the host's real route, and do not rotate.
  * False -> keep using a proxy. When the value named a file and the current
             proxy stops forwarding, try proxies PARALLEL_ATTEMPTS at a time.
             The whole group is started, and the fastest one that actually
             carries two verified HTTPS replies at once is kept. The others
             that also carry them are saved and used, in that speed order,
             when the current one stops. A handshake alone is not enough, and
             neither is a proxy that substitutes its own certificate. A guest
             connection that fails or goes silent abandons that proxy at once
             and tries the next ones. A canary that still answers does not
             keep a proxy the guest cannot use.

This module is pure: it reads a file only in load_plan(), and the failover
decision takes a clock reading instead of sleeping. The network namespace that
actually carries guest packets lives in proxy_runtime.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

# How often the running gateway asks the current proxy if it is still up, and
# how long that connect may take. A connect that finishes inside the window is
# a live proxy no matter how slow it was. A refused connection fails at once.
# The window is long enough that one slow reply is not mistaken for a dead proxy.
PROBE_EVERY_S = 0.4
PROBE_TIMEOUT_S = 1.2

# A guest dial does not get the canary's patience. One proxy has this long to
# finish the tunnel and to send the first byte. After that it is abandoned and
# the next proxies are tried together.
GUEST_DIAL_TIMEOUT_S = 0.6

# The running VM writes this beside hypervisor.cfg. `qvm --configure` reads it.
# `proxy.cmd` is how that screen asks the running VM to switch now.
STATUS_NAME = "proxy.status"
CMD_NAME = "proxy.cmd"

# A proxy is responsive when its latest check finished inside this window.
# It is durable after this many successes in a row, spanning at least DURABLE_S
# with no failure in between. One lucky reply is not a durable proxy.
RESPONSIVE_S = 0.8
DURABLE_OK = 3
DURABLE_S = 8.0


@dataclass(frozen=True)
class ProxyRecord:
    """What repeated checks have learned about one proxy."""

    ok_count: int = 0
    fail_count: int = 0
    streak_ok: int = 0
    streak_fail: int = 0
    streak_since: "float | None" = None
    last_ok: "float | None" = None
    last_fail: "float | None" = None
    latency: "float | None" = None


def note_health(
    record: ProxyRecord, *, ok: bool, now: float, latency: "float | None" = None,
) -> ProxyRecord:
    """Fold one check into `record`. A failure ends the current uptime streak."""
    if ok:
        since = record.streak_since if record.streak_ok else now
        return ProxyRecord(
            ok_count=record.ok_count + 1,
            fail_count=record.fail_count,
            streak_ok=record.streak_ok + 1,
            streak_fail=0,
            streak_since=since,
            last_ok=now,
            last_fail=record.last_fail,
            latency=record.latency if latency is None else latency,
        )
    return ProxyRecord(
        ok_count=record.ok_count,
        fail_count=record.fail_count + 1,
        streak_ok=0,
        streak_fail=record.streak_fail + 1,
        streak_since=None,
        last_ok=record.last_ok,
        last_fail=now,
        latency=record.latency,
    )


def health_label(record: "ProxyRecord | None", now: float) -> str:
    """`durable`, `responsive`, `slow`, `down`, or `unproven`.

    Durable means it has kept answering, quickly, for DURABLE_S. Responsive
    means the latest answer was quick but the streak is still short. Slow
    answers. Down means the latest check failed.
    """
    if record is None or (record.ok_count == 0 and record.fail_count == 0):
        return "unproven"
    failed_last = record.streak_fail > 0 and (
        record.last_ok is None or (record.last_fail or 0) >= (record.last_ok or 0)
    )
    if failed_last:
        return "down"
    latency = record.latency
    quick = latency is not None and latency <= RESPONSIVE_S
    up = 0.0 if record.streak_since is None else max(0.0, now - record.streak_since)
    if record.streak_ok >= DURABLE_OK and up >= DURABLE_S and quick:
        return "durable"
    if record.streak_ok >= 1 and quick:
        return "responsive"
    if record.streak_ok >= 1:
        return "slow"
    return "down"


def health_rank(label: str) -> int:
    """Label order for display. Selection uses latency, not this rank."""
    return {"durable": 0, "responsive": 1, "slow": 2, "unproven": 3, "down": 4}.get(label, 5)


def selection_key(record: "ProxyRecord | None", now: float) -> tuple:
    """Sort key for which proxy carries the guest. Lower wins.

    A proxy whose latest check failed sorts last. Every other proxy sorts by
    its latest latency, so the fastest measured one is first. Durability is
    reported, and it does not outrank a faster reply.
    """
    label = health_label(record, now)
    latency = None if record is None else record.latency
    return (1 if label == "down" else 0, latency if latency is not None else 1e9)


def should_promote(current_s: "float | None", candidate_s: "float | None") -> bool:
    """True when `candidate_s` is fast enough to replace the proxy in use.

    Fifty milliseconds of noise does not move the guest. A clearly faster
    measurement does.
    """
    if candidate_s is None:
        return False
    if current_s is None:
        return True
    return candidate_s + 0.05 < current_s

# How many proxies from a proxies file are proved together when none is pinned.
# The whole group is started before one is chosen. The first proxy that
# forwards real bytes is kept. The next group starts only when nobody in this
# group forwarded. A completed handshake is not a win.
PARALLEL_ATTEMPTS = 10

# A proxy is up when two TLS tunnels to this host both verify the real
# certificate and come back with a real reply at the same time. Cleartext
# HTTP is the wrong signal: a proxy that substitutes its own certificate
# still answers port 80, and the guest's HTTPS then fails. Port 53 is also
# wrong: plenty of proxies that carry web traffic refuse it, and a proxy
# that allows only one connection cannot carry a guest. Read at call time
# so a test can aim the canary elsewhere.
CANARY_HOST = "1.1.1.1"
CANARY_PORT = 443
# None uses the system trust store. A test sets this to a CA it generated.
CANARY_CAFILE: str | None = None

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


# ISO 3166-1 alpha-2 names for the country code on Cloudflare's trace page.
_COUNTRIES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
    "AG": "Antigua and Barbuda", "AL": "Albania", "AM": "Armenia", "AR": "Argentina",
    "AT": "Austria", "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina",
    "BD": "Bangladesh", "BE": "Belgium", "BG": "Bulgaria", "BH": "Bahrain",
    "BR": "Brazil", "BY": "Belarus", "CA": "Canada", "CH": "Switzerland",
    "CL": "Chile", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark",
    "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia",
    "EG": "Egypt", "ES": "Spain", "FI": "Finland", "FR": "France", "GB": "United Kingdom",
    "GE": "Georgia", "GR": "Greece", "GT": "Guatemala", "HK": "Hong Kong",
    "HR": "Croatia", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
    "IL": "Israel", "IN": "India", "IQ": "Iraq", "IR": "Iran", "IS": "Iceland",
    "IT": "Italy", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia",
    "KR": "South Korea", "KW": "Kuwait", "KZ": "Kazakhstan", "LB": "Lebanon",
    "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "MA": "Morocco",
    "MD": "Moldova", "MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria",
    "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NZ": "New Zealand",
    "PA": "Panama", "PE": "Peru", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PT": "Portugal", "QA": "Qatar", "RO": "Romania",
    "RS": "Serbia", "RU": "Russia", "SA": "Saudi Arabia", "SE": "Sweden",
    "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia", "TH": "Thailand",
    "TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine", "US": "United States",
    "UY": "Uruguay", "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam",
    "ZA": "South Africa",
}


def country_name(code: str) -> str:
    """English name for a trace `loc=` code. Unknown codes come back unchanged."""
    cleaned = (code or "").strip().upper()
    if not cleaned:
        return ""
    return _COUNTRIES.get(cleaned, cleaned)


def read_proxy_status(directory: str) -> "dict | None":
    """The running VM's proxy.status, or None when no session has published one."""
    path = os.path.join(directory, STATUS_NAME)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.loads(fh.read())
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def request_next_proxy(directory: str) -> None:
    """Ask the running VM in `directory` to drop the current proxy now."""
    path = os.path.join(directory, CMD_NAME)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("next\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


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
