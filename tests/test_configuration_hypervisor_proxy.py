"""Proxy settings, failover decisions, and the guest network namespace.

The namespace tests stay on 127.0.0.1. Guest destinations are documentation
addresses (203.0.113.0/24) or the slirp resolver (10.0.2.3). A fake proxy on
localhost is the only socket that may answer them. One test is marked
`network`: it loads tests/fixtures/proxies and checks that a guest receives
real bytes. A plain run skips it and does not dial the internet.
"""

from __future__ import annotations

import base64
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import configuration_schema as cs
import configuration_watcher
import proxy_config
import proxy_runtime
import proxy_tunnel
import virtual_machine as vm
from checks import HypervisorError
from configuration import HypervisorCfg
from hypervisor_helpers import make_cfg
from proxy_config import HealthState, parse_endpoint

# pytest already has threads when the namespace forks. The warning is about that
# process, and the child closes the extras it inherited.
pytestmark = pytest.mark.filterwarnings(
    "ignore:This process .* is multi-threaded, use of fork\\(\\) may lead to deadlocks:DeprecationWarning"
)

# The canary's trust anchor and the leaf a good proxy presents. A second leaf,
# signed by a CA that is not this one, is what an intercepting proxy presents.
_TRUSTED_CA = ""
_TRUSTED_CERT = ""
_TRUSTED_KEY = ""
_FORGED_CERT = ""
_FORGED_KEY = ""


def _make_canary_material(directory: Path, name: str) -> tuple[str, str, str]:
    """Return `(ca_crt, leaf_crt, leaf_key)` for a CA and a 1.1.1.1 server leaf."""
    ca_key = directory / f"{name}-ca.key"
    ca_crt = directory / f"{name}-ca.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt),
            "-days", "2", "-subj", f"/CN=qvm-{name}-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
        ],
        check=True, capture_output=True,
    )
    leaf_key = directory / f"{name}-leaf.key"
    leaf_csr = directory / f"{name}-leaf.csr"
    leaf_crt = directory / f"{name}-leaf.crt"
    leaf_ext = directory / f"{name}-leaf.ext"
    leaf_ext.write_text(
        "subjectAltName=IP:1.1.1.1\nbasicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    )
    subprocess.run(
        [
            "openssl", "req", "-new", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(leaf_key), "-out", str(leaf_csr),
            "-subj", "/CN=1.1.1.1",
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(leaf_csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(leaf_crt), "-days", "2", "-extfile", str(leaf_ext),
        ],
        check=True, capture_output=True,
    )
    return str(ca_crt), str(leaf_crt), str(leaf_key)


@pytest.fixture(scope="module", autouse=True)
def _trust_the_canary_certificate(tmp_path_factory):
    """Point the canary at a CA this process generated.

    The forged leaf has the same name and is signed by a different CA, which
    is what a proxy presents when it intercepts TLS.
    """
    global _TRUSTED_CA, _TRUSTED_CERT, _TRUSTED_KEY, _FORGED_CERT, _FORGED_KEY
    directory = tmp_path_factory.mktemp("canary-ca")
    trusted_ca, trusted_crt, trusted_key = _make_canary_material(directory, "trusted")
    _forged_ca, forged_crt, forged_key = _make_canary_material(directory, "forged")
    del _forged_ca
    previous = proxy_config.CANARY_CAFILE
    proxy_config.CANARY_CAFILE = trusted_ca
    _TRUSTED_CA = trusted_ca
    _TRUSTED_CERT = trusted_crt
    _TRUSTED_KEY = trusted_key
    _FORGED_CERT = forged_crt
    _FORGED_KEY = forged_key
    yield
    proxy_config.CANARY_CAFILE = previous


# --- schema ------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["False", "false", "off", "none", "no", "0", "", "  "])
def test_proxy_off_spellings(raw):
    vals, errors = cs.coerce_all({"Proxy": raw})
    assert not errors
    assert vals["Proxy"] is False


@pytest.mark.parametrize("raw", ["True", "true", "yes", "on", "1", '"True"'])
def test_proxy_true_selects_the_proxies_file(raw):
    vals, errors = cs.coerce_all({"Proxy": raw})
    assert not errors
    assert vals["Proxy"] is True


@pytest.mark.parametrize("raw", [
    "socks5://127.0.0.1:1080",
    "socks4://203.99.183.197:1080",
    "socks4://user@186.1.182.194:4153",
    "http://proxy.example:8080",
    "SOCKS5://example.com:1080",
    "socks5://alice:secret@10.1.1.1:1080",
    "http://[2001:db8::1]:8080",
    '"socks5://127.0.0.1:1"',
])
def test_proxy_accepts_urls(raw):
    vals, errors = cs.coerce_all({"Proxy": raw})
    assert not errors
    assert "://" in vals["Proxy"]


@pytest.mark.parametrize("raw", [
    "https://127.0.0.1:1080",
    "socks5://127.0.0.1",
    "socks5://127.0.0.1:0",
    "socks5://127.0.0.1:65536",
    "socks5://:1080",
    "../proxies",
    "proxies/extra",
    ".hidden",
    "has space",
])
def test_proxy_rejects_bad_values(raw):
    _vals, errors = cs.coerce_all({"Proxy": raw})
    assert errors, raw


def test_proxy_accepts_a_file_name_without_opening_it():
    vals, errors = cs.coerce_all({"Proxy": "proxies"})
    assert not errors
    assert vals["Proxy"] == "proxies"


def test_kill_switch_is_a_bool():
    vals, errors = cs.coerce_all({"Proxy_Kill_Switch": "True"})
    assert not errors and vals["Proxy_Kill_Switch"] is True
    _vals, errors = cs.coerce_all({"Proxy_Kill_Switch": "maybe"})
    assert errors


def test_proxy_is_not_a_live_key():
    assert "Proxy" not in configuration_watcher._LIVE_KEYS
    assert "Proxy_Kill_Switch" not in configuration_watcher._LIVE_KEYS


def test_from_dir_reads_proxy_and_env_wins(tmp_path, monkeypatch):
    (tmp_path / "hypervisor.cfg").write_text(
        'Proxy = "socks5://127.0.0.1:1"\nProxy_Kill_Switch = False\n',
        encoding="utf-8",
    )
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.proxy == "socks5://127.0.0.1:1"
    assert hcfg.proxy_kill_switch is False
    monkeypatch.setenv("PROXY", "proxies")
    monkeypatch.setenv("PROXY_KILL_SWITCH", "yes")
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.proxy == "proxies"
    assert hcfg.proxy_kill_switch is True
    monkeypatch.setenv("PROXY", "True")
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.proxy is True


def test_defaults_leave_proxy_off(tmp_path):
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.proxy is False
    assert hcfg.proxy_kill_switch is False


# --- file + decision ---------------------------------------------------------

def test_load_plan_skips_blanks_and_comments(tmp_path):
    (tmp_path / "proxies").write_text(
        "\n# comment\nsocks4://127.0.0.1:9\nsocks5://127.0.0.1:1\n\nhttp://127.0.0.1:2\n",
        encoding="utf-8",
    )
    plan = proxy_config.load_plan(str(tmp_path), "proxies")
    assert plan.enabled and plan.from_file and plan.source == "proxies"
    assert [(e.scheme, e.port) for e in plan.endpoints] == [
        ("socks4", 9), ("socks5", 1), ("http", 2),
    ]
    same = proxy_config.load_plan(str(tmp_path), True)
    assert same == plan
    text = proxy_config.describe(plan, False)
    assert "file proxies (3 proxies)" in text
    assert "Kill switch: off" in text


def test_load_plan_errors_name_the_line(tmp_path):
    (tmp_path / "proxies").write_text("socks5://127.0.0.1:1\n\ngarbage\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 3"):
        proxy_config.load_plan(str(tmp_path), "proxies")


def test_load_plan_rejects_an_empty_or_missing_file(tmp_path):
    (tmp_path / "proxies").write_text("# nothing\n\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no proxy"):
        proxy_config.load_plan(str(tmp_path), "proxies")
    with pytest.raises(FileNotFoundError):
        proxy_config.load_plan(str(tmp_path), "missing")


def test_describe_redacts_a_password():
    plan = proxy_config.load_plan(".", "socks5://alice:s3cret@127.0.0.1:1080")
    text = proxy_config.describe(plan, True)
    assert "s3cret" not in text
    assert "alice:***@" in text
    assert "Kill switch: on" in text
    endpoint = parse_endpoint("socks5://[2001:db8::2]:1080")
    assert endpoint is not None
    assert endpoint.host == "2001:db8::2"
    assert endpoint.render() == "socks5://[2001:db8::2]:1080"


def _probe(state, **kw):
    base = dict(ok=False, now=0.0, kill_switch=False, from_file=True, count=3)
    base.update(kw)
    return proxy_config.note_probe(state, **base)


def test_note_probe_kill_switch_cuts_immediately_and_does_not_rotate():
    state, action = _probe(HealthState(0, None, False), now=5, kill_switch=True)
    assert action == "kill" and state.killed and state.index == 0
    state, action = _probe(state, now=100, kill_switch=True)
    assert action == "none" and state.killed and state.index == 0
    state, action = _probe(state, ok=True, now=101, kill_switch=True)
    assert action == "restore" and not state.killed and state.down_since is None


def test_batch_indexes_groups_without_repeating():
    assert proxy_config.PARALLEL_ATTEMPTS == 10
    assert proxy_config.batch_indexes(15, 0, 10) == [list(range(10)), list(range(10, 15))]
    assert proxy_config.batch_indexes(3, 1, 10) == [[1, 2, 0]]
    assert proxy_config.batch_indexes(0, 0, 10) == []


def test_note_probe_switches_on_the_first_failure_and_keeps_a_success():
    alive, action = _probe(HealthState(0, None, False), ok=True, now=50)
    assert action == "none" and alive.index == 0 and alive.down_since is None
    dead, action = _probe(HealthState(0, None, False), now=50)
    assert action == "switch" and dead.index == 1 and dead.down_since is None
    stayed, action = _probe(dead, ok=True, now=99)
    assert action == "none" and stayed.index == 1


def test_note_probe_does_not_rotate_a_single_url_or_without_a_file():
    state = HealthState(0, 0.0, False)
    stayed, action = _probe(state, now=100, from_file=True, count=1)
    assert action == "none" and stayed.index == 0
    stayed, action = _probe(state, now=100, from_file=False, count=4)
    assert action == "none" and stayed.index == 0
    wrapped, action = _probe(HealthState(2, 0.0, False), now=11)
    assert action == "switch" and wrapped.index == 0
    same, action = _probe(state, count=0)
    assert action == "none" and same is state


def test_note_probe_success_clears_the_down_timer():
    state, action = _probe(HealthState(1, 50.0, False), ok=True, now=60)
    assert action == "none" and state.down_since is None and state.index == 1 and not state.killed


def test_the_fastest_proxy_sorts_ahead_of_a_slower_durable_one():
    """Latency picks the proxy. A long uptime does not beat a faster reply."""
    now = 100.0
    quick = proxy_config.ProxyRecord(
        ok_count=1, streak_ok=1, streak_since=now, last_ok=now, latency=0.12,
    )
    durable = proxy_config.ProxyRecord()
    for at in (10.0, 12.0, 10.0 + proxy_config.DURABLE_S):
        durable = proxy_config.note_health(durable, ok=True, now=at, latency=0.7)
    assert proxy_config.health_label(durable, 10.0 + proxy_config.DURABLE_S) == "durable"
    assert proxy_config.selection_key(quick, now) < proxy_config.selection_key(durable, now)
    assert proxy_config.should_promote(0.7, 0.12) is True
    assert proxy_config.should_promote(0.20, 0.18) is False
    assert proxy_config.should_promote(None, 0.2) is True
    assert proxy_config.should_promote(0.2, None) is False


def test_health_label_requires_a_streak_before_a_proxy_is_durable():
    """One fast reply is responsive. Durable takes repeated quick successes."""
    record = proxy_config.ProxyRecord()
    assert proxy_config.health_label(record, 0) == "unproven"
    record = proxy_config.note_health(record, ok=True, now=10, latency=0.2)
    assert proxy_config.health_label(record, 10) == "responsive"
    assert proxy_config.health_rank("durable") < proxy_config.health_rank("responsive")
    record = proxy_config.note_health(record, ok=True, now=12, latency=0.3)
    record = proxy_config.note_health(record, ok=True, now=10 + proxy_config.DURABLE_S, latency=0.3)
    assert record.streak_ok >= proxy_config.DURABLE_OK
    assert proxy_config.health_label(record, 10 + proxy_config.DURABLE_S) == "durable"
    slow = proxy_config.note_health(
        proxy_config.ProxyRecord(), ok=True, now=1, latency=proxy_config.RESPONSIVE_S + 1,
    )
    assert proxy_config.health_label(slow, 1) == "slow"
    down = proxy_config.note_health(record, ok=False, now=100)
    assert proxy_config.health_label(down, 100) == "down"
    assert down.streak_ok == 0 and down.fail_count == 1 and down.ok_count == record.ok_count


def test_public_dns_target_rewrites_private_resolvers():
    assert proxy_runtime._public_dns_target("10.0.2.3") == "1.1.1.1"
    assert proxy_runtime._public_dns_target("192.168.1.1") == "1.1.1.1"
    assert proxy_runtime._public_dns_target("127.0.0.1") == "1.1.1.1"
    assert proxy_runtime._public_dns_target("8.8.8.8") == "8.8.8.8"


# --- handshakes --------------------------------------------------------------

def _recvall(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return bytes(buf)


def test_socks4_handshake_leaves_the_first_payload_byte():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = {}

    def run():
        conn, _addr = listener.accept()
        try:
            head = _recvall(conn, 8)
            version, command, dest_port, packed = struct.unpack("!BBH4s", head)
            user = bytearray()
            while True:
                byte = _recvall(conn, 1)
                if byte == b"\x00":
                    break
                user += byte
            seen["version"] = version
            seen["command"] = command
            seen["user"] = bytes(user).decode()
            seen["dest"] = (socket.inet_ntoa(packed), dest_port)
            conn.sendall(b"\x00\x5a\x00\x00\x00\x00\x00\x00Z")
        finally:
            time.sleep(1)
            conn.close()
            listener.close()

    threading.Thread(target=run, daemon=True).start()
    proxy = parse_endpoint(f"socks4://bob@127.0.0.1:{port}")
    assert proxy is not None
    sock = proxy_tunnel.open_tunnel(proxy, "203.0.113.10", 80, timeout=3)
    try:
        assert sock.recv(1) == b"Z"
    finally:
        sock.close()
    assert seen["version"] == 4 and seen["command"] == 1
    assert seen["user"] == "bob"
    assert seen["dest"] == ("203.0.113.10", 80)


def test_socks4_refuses_a_name_and_a_denied_connect():
    with pytest.raises(proxy_tunnel.ProxyTunnelError, match="IPv4"):
        proxy_tunnel.socks4_connect(socket.socket(), "example.com", 80)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def run():
        conn, _addr = listener.accept()
        while conn.recv(1) != b"\x00":
            pass
        conn.sendall(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
        time.sleep(0.2)
        conn.close()
        listener.close()

    threading.Thread(target=run, daemon=True).start()
    proxy = parse_endpoint(f"socks4://127.0.0.1:{port}")
    assert proxy is not None
    with pytest.raises(proxy_tunnel.ProxyTunnelError, match="reply 91"):
        proxy_tunnel.open_tunnel(proxy, "203.0.113.10", 80, timeout=3)


def test_socks5_handshake_leaves_the_first_payload_byte():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = {}

    def run():
        conn, _addr = listener.accept()
        try:
            version, nmethods = _recvall(conn, 2)
            methods = _recvall(conn, nmethods)
            assert version == 5 and 0x02 in methods
            conn.sendall(b"\x05\x02")
            auth = _recvall(conn, 2)
            assert auth[0] == 0x01
            user = _recvall(conn, auth[1])
            plen = _recvall(conn, 1)[0]
            password = _recvall(conn, plen)
            seen["user"] = user.decode()
            seen["password"] = password.decode()
            conn.sendall(b"\x01\x00")
            ver, cmd, _rsv, atyp = _recvall(conn, 4)
            assert ver == 5 and cmd == 1 and atyp == 1
            host = socket.inet_ntoa(_recvall(conn, 4))
            dest_port = struct.unpack("!H", _recvall(conn, 2))[0]
            seen["dest"] = (host, dest_port)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00Z")
        finally:
            # Leave the socket open until the client has read Z.
            time.sleep(1)
            conn.close()
            listener.close()

    threading.Thread(target=run, daemon=True).start()
    proxy = parse_endpoint(f"socks5://alice:secret@127.0.0.1:{port}")
    assert proxy is not None
    sock = proxy_tunnel.open_tunnel(proxy, "203.0.113.10", 80, timeout=3)
    try:
        assert sock.recv(1) == b"Z"
    finally:
        sock.close()
    assert seen["user"] == "alice" and seen["password"] == "secret"
    assert seen["dest"] == ("203.0.113.10", 80)


def test_http_connect_leaves_the_first_payload_byte():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = {}

    def run():
        conn, _addr = listener.accept()
        try:
            data = bytearray()
            while b"\r\n\r\n" not in data:
                data += conn.recv(1)
            seen["head"] = bytes(data).decode()
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\nX")
            time.sleep(1)
        finally:
            conn.close()
            listener.close()

    threading.Thread(target=run, daemon=True).start()
    proxy = parse_endpoint(f"http://alice:secret@127.0.0.1:{port}")
    assert proxy is not None
    sock = proxy_tunnel.open_tunnel(proxy, "203.0.113.10", 443, timeout=3)
    try:
        assert sock.recv(1) == b"X"
    finally:
        sock.close()
    assert "CONNECT 203.0.113.10:443 HTTP/1.1" in seen["head"]
    token = base64.b64encode(b"alice:secret").decode()
    assert f"Proxy-Authorization: Basic {token}" in seen["head"]


def test_reachable_is_a_completed_handshake_and_a_closed_port_fails_at_once():
    """A slow accept() is not a dead proxy: the handshake already finished.
    A closed port refuses immediately, instead of burning the whole timeout."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def run():
        time.sleep(0.4)
        conn, _addr = listener.accept()
        conn.close()
        listener.close()

    threading.Thread(target=run, daemon=True).start()
    slow = parse_endpoint(f"socks5://127.0.0.1:{port}")
    assert slow is not None
    started = time.monotonic()
    assert proxy_tunnel.proxy_reachable(slow, 2.0) is True
    assert time.monotonic() - started < 0.3

    closed_sock = socket.socket()
    closed_sock.bind(("127.0.0.1", 0))
    closed_port = closed_sock.getsockname()[1]
    closed_sock.close()
    closed = parse_endpoint(f"socks5://127.0.0.1:{closed_port}")
    assert closed is not None
    started = time.monotonic()
    assert proxy_tunnel.proxy_reachable(closed, 2.0) is False
    assert time.monotonic() - started < 0.5


def test_open_tunnel_closes_when_the_proxy_refuses():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def run():
        conn, _addr = listener.accept()
        conn.recv(8)
        conn.sendall(b"\x05\xff")
        time.sleep(0.2)
        conn.close()
        listener.close()

    threading.Thread(target=run, daemon=True).start()
    proxy = parse_endpoint(f"socks5://127.0.0.1:{port}")
    assert proxy is not None
    with pytest.raises(proxy_tunnel.ProxyTunnelError):
        proxy_tunnel.open_tunnel(proxy, "203.0.113.10", 80, timeout=3)


# --- namespace ---------------------------------------------------------------

class _Proxy:
    """A localhost SOCKS4, SOCKS5, or HTTP proxy that records destinations.

    Port 53 is answered as DNS-over-TCP. The canary port speaks TLS and then
    the trace page, unless `cleartext` is set. Anything else is one ping/pong
    exchange with an echo socket, so the payload is not generated by the proxy
    itself. `blackhole` finishes the handshake, records the destination, and
    then never sends a byte. `mitm` presents a certificate the canary does not
    trust.
    """

    def __init__(
        self,
        scheme: str,
        accept_delay: float = 0.0,
        refuse: bool = False,
        blackhole: bool = False,
        *,
        mitm: bool = False,
        cleartext: bool = False,
        reject_guest: bool = False,
        blackhole_guest: bool = False,
    ):
        self.scheme = scheme
        self.accept_delay = accept_delay
        self.refuse = refuse
        self.blackhole = blackhole
        self.mitm = mitm
        self.cleartext = cleartext
        self.reject_guest = reject_guest
        self.blackhole_guest = blackhole_guest
        self.seen: list[tuple[str, int]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listen: socket.socket | None = None
        self.port = 0
        echo = socket.socket()
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo.bind(("127.0.0.1", 0))
        echo.listen(16)
        self._echo = echo
        self._echo_port = echo.getsockname()[1]
        threading.Thread(target=self._accept_echo, daemon=True).start()

    def start(self, port: int = 0) -> int:
        self._stop.clear()
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port or self.port))
        listener.listen(64)
        listener.settimeout(0.2)
        self._listen = listener
        self.port = listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._listen is not None:
            try:
                self._listen.close()
            except OSError:
                pass
            self._listen = None

    def close(self) -> None:
        self.stop()
        try:
            self._echo.close()
        except OSError:
            pass

    def _accept(self) -> None:
        listener = self._listen
        while listener is not None and not self._stop.is_set():
            if self.accept_delay and self._stop.wait(self.accept_delay):
                return
            try:
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _accept_echo(self) -> None:
        while True:
            try:
                conn, _addr = self._echo.accept()
            except OSError:
                return
            threading.Thread(target=self._echo_one, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo_one(conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            data = conn.recv(64)
            if data == b"ping":
                conn.sendall(b"pong")
        except OSError:
            pass
        finally:
            conn.close()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            if self.scheme == "socks5":
                dest = self._socks(conn)
            elif self.scheme == "socks4":
                dest = self._socks4(conn)
            else:
                dest = self._http(conn)
            if dest is None:
                return
            with self._lock:
                self.seen.append(dest)
            if self.refuse or (
                self.reject_guest and not (
                    dest[0] == proxy_config.CANARY_HOST
                    and int(dest[1]) == int(proxy_config.CANARY_PORT)
                )
            ):
                return
            if self.blackhole_guest and not (
                dest[0] == proxy_config.CANARY_HOST
                and int(dest[1]) == int(proxy_config.CANARY_PORT)
            ):
                self._swallow(conn)
                return
            if self.blackhole:
                # Handshake is done and the destination is recorded. No payload
                # ever comes back, which is what a dead public proxy looks like.
                self._swallow(conn)
                return
            if dest[1] == 53:
                self._dns(conn)
            elif dest[0] == proxy_config.CANARY_HOST and int(dest[1]) == int(proxy_config.CANARY_PORT):
                if self.cleartext:
                    self._trace(conn)
                else:
                    self._trace_tls(conn)
            else:
                self._bridge(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _socks(self, conn: socket.socket):
        version, nmethods = _recvall(conn, 2)
        if version != 5:
            return None
        _recvall(conn, nmethods)
        conn.sendall(b"\x05\x00")
        ver, cmd, _rsv, atyp = _recvall(conn, 4)
        if ver != 5 or cmd != 1:
            return None
        if atyp == 1:
            host = socket.inet_ntoa(_recvall(conn, 4))
        elif atyp == 3:
            length = _recvall(conn, 1)[0]
            host = _recvall(conn, length).decode()
        else:
            return None
        port = struct.unpack("!H", _recvall(conn, 2))[0]
        canary = (
            host == proxy_config.CANARY_HOST
            and port == int(proxy_config.CANARY_PORT)
        )
        if self.refuse or (self.reject_guest and not canary):
            conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        else:
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        return host, port

    def _socks4(self, conn: socket.socket):
        version, command, port, packed = struct.unpack("!BBH4s", _recvall(conn, 8))
        while _recvall(conn, 1) != b"\x00":
            pass
        if version != 4 or command != 1:
            return None
        conn.sendall(b"\x00\x5a\x00\x00\x00\x00\x00\x00")
        return socket.inet_ntoa(packed), port

    def _http(self, conn: socket.socket):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(1)
            if not chunk:
                return None
            data += chunk
        line = bytes(data).split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
        parts = line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            return None
        host, port_s = parts[1].rsplit(":", 1)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        return host, int(port_s)

    def _swallow(self, conn: socket.socket) -> None:
        conn.settimeout(0.5)
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    continue
                if not chunk:
                    return
        except OSError:
            return

    def _dns(self, conn: socket.socket) -> None:
        size = struct.unpack("!H", _recvall(conn, 2))[0]
        payload = _recvall(conn, size)
        answer = b"OK" + payload[:2]
        conn.sendall(struct.pack("!H", len(answer)) + answer)

    def _trace_tls(self, conn: socket.socket) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.mitm:
            ctx.load_cert_chain(_FORGED_CERT, _FORGED_KEY)
        else:
            ctx.load_cert_chain(_TRUSTED_CERT, _TRUSTED_KEY)
        conn.settimeout(3)
        tls = ctx.wrap_socket(conn, server_side=True)
        try:
            self._trace(tls)
        finally:
            tls.close()

    def _trace(self, conn: socket.socket) -> None:
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = conn.recv(256)
            if not chunk:
                return
            data += chunk
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
            b"fl=e2e\ncloudflare\n"
        )

    def _bridge(self, conn: socket.socket) -> None:
        echo = socket.create_connection(("127.0.0.1", self._echo_port), 2)
        try:
            data = conn.recv(64)
            if data:
                echo.sendall(data)
            echo.settimeout(3)
            reply = echo.recv(64)
            if reply:
                conn.sendall(reply)
        finally:
            echo.close()


def _guest(session, directory: Path, source: str, timeout: float = 8.0) -> bytes:
    script = directory / "guest.py"
    out = directory / f"out-{time.monotonic_ns()}"
    script.write_text(source, encoding="utf-8")
    proc = session.spawn([sys.executable, str(script), str(out)])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if out.exists():
            return out.read_bytes()
        if proc.poll() is not None:
            time.sleep(0.05)
            if out.exists():
                return out.read_bytes()
            raise AssertionError(f"guest exited {proc.poll()} without writing {out.name}")
        time.sleep(0.02)
    proc.kill()
    raise AssertionError("guest timed out")


_PING = """
import socket, sys
out = sys.argv[1]
try:
    conn = socket.create_connection(("203.0.113.10", 80), 3)
    conn.settimeout(3)
    conn.sendall(b"ping")
    data = conn.recv(16)
except Exception:
    data = b""
with open(out, "wb") as fh:
    fh.write(data)
"""


def _boot(directory: Path, proxy: _Proxy, *, kill: bool, source: str, port_maps=None):
    if source == "proxies":
        plan = proxy_config.load_plan(str(directory), "proxies")
    else:
        plan = proxy_config.load_plan(str(directory), source)
    session = proxy_runtime.ProxySession.start(
        plan, kill, list(port_maps or []), str(directory),
    )
    return session


def _wait(pred, timeout: float, detail: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError(detail)


@pytest.mark.parametrize("scheme", ["socks4", "socks5", "http"])
def test_guest_tcp_goes_through_the_proxy(tmp_path, scheme, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.1)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.3)
    proxy = _Proxy(scheme)
    session = None
    try:
        port = proxy.start()
        session = _boot(tmp_path, proxy, kill=False, source=f"{scheme}://127.0.0.1:{port}")
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert ("203.0.113.10", 80) in proxy.seen
    finally:
        if session is not None:
            session.close()
        proxy.close()


def test_dns_is_carried_as_tcp_and_the_reply_keeps_its_source(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.1)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.3)
    proxy = _Proxy("socks5")
    session = None
    source = """
import socket, sys
out = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(b"\\xab\\xcdquery", ("10.0.2.3", 53))
try:
    data, addr = sock.recvfrom(2048)
    text = f"{addr[0]}:{addr[1]}:{data!r}"
except Exception as exc:
    text = f"fail:{exc}"
open(out, "w", encoding="utf-8").write(text)
"""
    try:
        port = proxy.start()
        session = _boot(tmp_path, proxy, kill=False, source=f"socks5://127.0.0.1:{port}")
        text = _guest(session, tmp_path, source).decode()
        assert text.startswith("10.0.2.3:53:"), text
        assert "OK" in text
        assert ("1.1.1.1", 53) in proxy.seen
    finally:
        if session is not None:
            session.close()
        proxy.close()


def test_non_dns_udp_is_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.1)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.3)
    proxy = _Proxy("socks5")
    session = None
    source = """
import socket, sys, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"ntp", ("203.0.113.10", 123))
time.sleep(0.4)
open(sys.argv[1], "w", encoding="utf-8").write("sent")
"""
    try:
        port = proxy.start()
        session = _boot(tmp_path, proxy, kill=False, source=f"socks5://127.0.0.1:{port}")
        assert _guest(session, tmp_path, source) == b"sent"
        time.sleep(0.2)
        assert not any(port_n == 123 for _host, port_n in proxy.seen)
    finally:
        if session is not None:
            session.close()
        proxy.close()


def test_kill_switch_cuts_and_restores_guest_internet(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.1)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.3)
    proxy = _Proxy("socks5")
    session = None
    host_port = _free_port()
    try:
        port = proxy.start()
        session = _boot(
            tmp_path, proxy, kill=True, source=f"socks5://127.0.0.1:{port}",
            port_maps=[(22, host_port)],
        )
        assert _guest(session, tmp_path, _PING) == b"pong"
        proxy.stop()
        _wait(lambda: session.killed, 5, "kill switch did not cut the guest")
        assert _guest(session, tmp_path, _PING) != b"pong"
        _expect_hostfwd(session, tmp_path, host_port)
        proxy.start(port)
        _wait(lambda: not session.killed, 5, "proxy came back but the guest stayed cut")
        restored = b""
        for _ in range(8):
            restored = _guest(session, tmp_path, _PING)
            if restored == b"pong":
                break
            time.sleep(0.1)
        assert restored == b"pong"
        assert session.index == 0
    finally:
        if session is not None:
            session.close()
        proxy.close()


def test_a_down_proxy_does_not_fall_back_to_the_host(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.05)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.2)
    proxy = _Proxy("socks5")
    session = None
    try:
        port = proxy.start()
        session = _boot(tmp_path, proxy, kill=False, source=f"socks5://127.0.0.1:{port}")
        assert _guest(session, tmp_path, _PING) == b"pong"
        proxy.stop()
        time.sleep(0.7)
        assert session.index == 0
        assert session.killed is False
        assert _guest(session, tmp_path, _PING) != b"pong"
    finally:
        if session is not None:
            session.close()
        proxy.close()


def test_failover_moves_to_the_next_proxy_in_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.05)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.2)
    first = _Proxy("socks5")
    second = _Proxy("http")
    session = None
    try:
        one = first.start()
        two = second.start()
        (tmp_path / "proxies").write_text(
            f"# first\nsocks5://127.0.0.1:{one}\n\nhttp://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, first, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        winner = session.index
        (first, second)[winner].stop()
        other = (first, second)[1 - winner]
        _wait(lambda: session.index != winner, 5, "did not fail over to the other proxy")
        assert session.killed is False
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert ("203.0.113.10", 80) in other.seen
    finally:
        if session is not None:
            session.close()
        first.close()
        second.close()


def test_a_slower_working_proxy_is_saved_and_used_when_the_fastest_dies(
    tmp_path, monkeypatch, capfd,
):
    """Ten-wide race keeps every proxy that forwards, fastest first.

    The guest is pinned to the one that answered first. The slower one is
    remembered, and a later dial uses it without scanning the file again.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    fast = _Proxy("http")
    slow = _Proxy("socks5", accept_delay=0.15)
    session = None
    try:
        one = fast.start()
        two = slow.start()
        dead = _free_port()
        (tmp_path / "proxies").write_text(
            f"http://127.0.0.1:{one}\n"
            f"socks5://127.0.0.1:{two}\n"
            f"socks5://127.0.0.1:{dead}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, fast, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert session.index == 0
        _wait(
            lambda: any(key[2] == two for _latency, key in session._working),
            5,
            "the slower proxy was not saved",
        )
        time.sleep(0.2)
        err = capfd.readouterr().err
        assert f"Proxy using http://127.0.0.1:{one}." in err
        assert f"Proxy standby socks5://127.0.0.1:{two}" in err
        fast.stop()
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert session.index == 1
        assert ("203.0.113.10", 80) in slow.seen
        assert "Proxy trying" not in capfd.readouterr().err
    finally:
        if session is not None:
            session.close()
        fast.close()
        slow.close()


def test_a_saved_proxy_that_stops_answering_is_marked_down(tmp_path, monkeypatch):
    """Standbys are checked again. One that goes quiet leaves the saved list."""
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.05)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.4)
    monkeypatch.setattr(proxy_config, "DURABLE_S", 0.2)
    monkeypatch.setattr(proxy_config, "DURABLE_OK", 2)
    fast = _Proxy("http")
    slow = _Proxy("socks5", accept_delay=0.05)
    session = None
    try:
        one = fast.start()
        two = slow.start()
        (tmp_path / "proxies").write_text(
            f"http://127.0.0.1:{one}\n"
            f"socks5://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, fast, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        _wait(
            lambda: any(key[2] == two for _latency, key in session._working),
            5,
            "the second proxy was not saved",
        )
        slow.stop()
        _wait(
            lambda: not any(key[2] == two for _latency, key in session._working),
            5,
            "the dead standby was kept",
        )
        status = proxy_config.read_proxy_status(str(tmp_path))
        assert status is not None
        assert status["current"]["url"] == f"http://127.0.0.1:{one}"
        assert status["current"]["ok"] >= 2
        assert status["current"]["state"] in ("responsive", "durable")
        failed = " ".join(item["url"] for item in status.get("failed") or [])
        assert f"127.0.0.1:{two}" in failed
    finally:
        if session is not None:
            session.close()
        fast.close()
        slow.close()


def test_a_faster_saved_proxy_replaces_the_one_in_use(tmp_path, monkeypatch):
    """Background promotion moves the guest when a saved proxy is clearly faster."""
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    fast = _Proxy("http")
    slow = _Proxy("socks5", accept_delay=0.05)
    session = None
    try:
        one = fast.start()
        two = slow.start()
        (tmp_path / "proxies").write_text(
            f"http://127.0.0.1:{one}\n"
            f"socks5://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, fast, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        _wait(
            lambda: any(key[2] == two for _latency, key in session._working),
            5,
            "the second proxy was not saved",
        )
        assert session.index == 0
        # The proxy in use has gone slow. The saved one measured faster.
        session._remember_working(session._endpoints[0], 1.5)
        session._remember_working(session._endpoints[1], 0.08)
        session._promote_fastest()
        assert session.index == 1
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert ("203.0.113.10", 80) in slow.seen
    finally:
        if session is not None:
            session.close()
        fast.close()
        slow.close()


def test_configure_can_switch_to_the_next_saved_proxy(tmp_path, monkeypatch):
    """The configure screen's next-proxy command pins a saved proxy at once."""
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    fast = _Proxy("http")
    slow = _Proxy("socks5", accept_delay=0.1)
    session = None
    try:
        one = fast.start()
        two = slow.start()
        (tmp_path / "proxies").write_text(
            f"http://127.0.0.1:{one}\n"
            f"socks5://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, fast, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        _wait(
            lambda: any(key[2] == two for _latency, key in session._working),
            5,
            "the second proxy was not saved",
        )
        status = proxy_config.read_proxy_status(str(tmp_path))
        assert status is not None and status["running"] is True
        assert status["current"]["url"] == f"http://127.0.0.1:{one}"
        assert status["current"]["latency_ms"] is not None
        proxy_config.request_next_proxy(str(tmp_path))
        _wait(lambda: session.index == 1, 2, "next proxy was not applied")
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert ("203.0.113.10", 80) in slow.seen
    finally:
        if session is not None:
            session.close()
        fast.close()
        slow.close()


def test_a_proxy_that_refuses_the_guest_is_abandoned_for_the_next(
    tmp_path, monkeypatch,
):
    """The canary can succeed while every real guest destination is refused.

    That proxy is not kept. The same guest connection is carried by the next
    one, without waiting for a later health probe.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    bad = _Proxy("socks5", reject_guest=True)
    good = _Proxy("http", accept_delay=0.2)
    session = None
    try:
        one = bad.start()
        two = good.start()
        (tmp_path / "proxies").write_text(
            f"socks5://127.0.0.1:{one}\nhttp://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, bad, kill=False, source="proxies")
        started = time.monotonic()
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert time.monotonic() - started < 3.0
        assert session.index == 1
        assert ("203.0.113.10", 80) in good.seen
    finally:
        if session is not None:
            session.close()
        bad.close()
        good.close()


def test_a_silent_proxy_is_dropped_when_the_guest_gets_no_reply(
    tmp_path, monkeypatch,
):
    """A tunnel that accepts and then sends nothing is not a working proxy."""
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    bad = _Proxy("socks5", blackhole_guest=True)
    good = _Proxy("http", accept_delay=0.15)
    session = None
    try:
        one = bad.start()
        two = good.start()
        (tmp_path / "proxies").write_text(
            f"socks5://127.0.0.1:{one}\nhttp://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, bad, kill=False, source="proxies")
        started = time.monotonic()
        got = b""
        for _ in range(4):
            got = _guest(session, tmp_path, _PING)
            if got == b"pong":
                break
        assert got == b"pong"
        assert time.monotonic() - started < 8.0
        assert session.index == 1
        assert ("203.0.113.10", 80) in good.seen
    finally:
        if session is not None:
            session.close()
        bad.close()
        good.close()


def test_a_dead_proxy_fails_over_inside_the_dial(tmp_path, monkeypatch):
    """Health is parked, so only the guest dial can notice the proxy died."""
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 5)
    first = _Proxy("socks5")
    second = _Proxy("http")
    session = None
    try:
        one = first.start()
        two = second.start()
        (tmp_path / "proxies").write_text(
            f"socks5://127.0.0.1:{one}\nhttp://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, first, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        first.stop()
        started = time.monotonic()
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert time.monotonic() - started < 2.0
        assert session.index == 1
        assert ("203.0.113.10", 80) in second.seen
    finally:
        if session is not None:
            session.close()
        first.close()
        second.close()


def test_search_uses_the_first_working_tunnel_and_then_keeps_it(tmp_path, monkeypatch):
    """Both proxies are started together. The one that forwards first is kept.
    A later dial uses only that proxy, so the slow neighbour is not dialed again."""
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    slow = _Proxy("socks5", accept_delay=0.8)
    fast = _Proxy("http")
    session = None
    try:
        one = slow.start()
        two = fast.start()
        (tmp_path / "proxies").write_text(
            f"socks5://127.0.0.1:{one}\nhttp://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, slow, kill=False, source="proxies")
        started = time.monotonic()
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert time.monotonic() - started < 0.5
        assert session.index == 1
        time.sleep(1.0)
        slow_seen = len(slow.seen)
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert session.index == 1
        assert len(slow.seen) == slow_seen
        assert ("203.0.113.10", 80) in fast.seen
    finally:
        if session is not None:
            session.close()
        slow.close()
        fast.close()


def test_a_dead_group_is_followed_by_the_next_group(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PARALLEL_ATTEMPTS", 2)
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    live = _Proxy("http")
    session = None
    try:
        port = live.start()
        dead_a = _free_port()
        dead_b = _free_port()
        (tmp_path / "proxies").write_text(
            f"socks5://127.0.0.1:{dead_a}\n"
            f"socks5://127.0.0.1:{dead_b}\n"
            f"http://127.0.0.1:{port}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, live, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert session.index == 2
        assert ("203.0.113.10", 80) in live.seen
    finally:
        if session is not None:
            session.close()
        live.close()


def test_a_destination_refusal_does_not_block_the_rest_of_the_group(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    first = _Proxy("socks5", refuse=True)
    second = _Proxy("http")
    session = None
    try:
        one = first.start()
        two = second.start()
        (tmp_path / "proxies").write_text(
            f"socks5://127.0.0.1:{one}\nhttp://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, first, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert session.index == 1
        assert ("203.0.113.10", 80) in second.seen
    finally:
        if session is not None:
            session.close()
        first.close()
        second.close()


def test_forwarding_needs_a_payload_and_a_blackhole_does_not_count():
    """A finished handshake is not enough. Bytes have to come back."""
    good = _Proxy("socks5")
    hole = _Proxy("http", blackhole=True)
    try:
        good.start()
        hole.start()
        working = parse_endpoint(f"socks5://127.0.0.1:{good.port}")
        silent = parse_endpoint(f"http://127.0.0.1:{hole.port}")
        assert working is not None and silent is not None
        started = time.monotonic()
        assert proxy_tunnel.proxy_forwards(working, 0.5) is True
        assert time.monotonic() - started < 0.4
        assert ("1.1.1.1", 443) in good.seen
        started = time.monotonic()
        assert proxy_tunnel.proxy_forwards(silent, 0.4) is False
        elapsed = time.monotonic() - started
        assert elapsed >= 0.3, elapsed
        assert ("1.1.1.1", 443) in hole.seen
        closed_port = _free_port()
        closed = parse_endpoint(f"socks5://127.0.0.1:{closed_port}")
        assert closed is not None
        started = time.monotonic()
        assert proxy_tunnel.proxy_forwards(closed, 2.0) is False
        assert time.monotonic() - started < 0.5
    finally:
        good.close()
        hole.close()


def test_cleartext_http_is_not_a_working_proxy():
    """The trace body on cleartext HTTP used to pin a proxy that breaks HTTPS.

    A proxy that answers the canary in cleartext, with the same bytes a real
    host would send, is not forwarding. The guest's TLS never starts.
    """
    assert proxy_config.CANARY_PORT == 443
    plain = _Proxy("http", cleartext=True)
    try:
        plain.start()
        endpoint = parse_endpoint(f"http://127.0.0.1:{plain.port}")
        assert endpoint is not None
        assert proxy_tunnel.proxy_forwards(endpoint, 1.0) is False
        assert ("1.1.1.1", 443) in plain.seen
    finally:
        plain.close()


def test_a_substituted_certificate_is_not_forwarding():
    """A proxy that finishes TLS with its own certificate is not up.

    The body still contains the trace marker. The certificate is what fails
    it. The next proxy, whose certificate verifies, is up.
    """
    mitm = _Proxy("socks5", mitm=True)
    good = _Proxy("http")
    try:
        mitm.start()
        good.start()
        forged = parse_endpoint(f"socks5://127.0.0.1:{mitm.port}")
        real = parse_endpoint(f"http://127.0.0.1:{good.port}")
        assert forged is not None and real is not None
        assert proxy_tunnel.proxy_forwards(forged, 2.0) is False
        assert proxy_tunnel.proxy_forwards(real, 2.0) is True
        assert ("1.1.1.1", 443) in mitm.seen
        assert ("1.1.1.1", 443) in good.seen
    finally:
        mitm.close()
        good.close()


def test_selection_skips_a_proxy_that_substitutes_its_certificate(tmp_path, monkeypatch, capfd):
    """The proxies file must not pin an interceptor that rewrites HTTPS.

    It is listed first and it answers the canary. Its certificate is not the
    real one, so the guest is pinned to the proxy after it.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    mitm = _Proxy("socks5", mitm=True)
    good = _Proxy("http")
    session = None
    try:
        one = mitm.start()
        two = good.start()
        (tmp_path / "proxies").write_text(
            f"socks5://127.0.0.1:{one}\nhttp://127.0.0.1:{two}\n",
            encoding="utf-8",
        )
        session = _boot(tmp_path, good, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert session.index == 1
        assert ("203.0.113.10", 80) in good.seen
        assert ("203.0.113.10", 80) not in mitm.seen
        err = capfd.readouterr().err
        assert f"Proxy using http://127.0.0.1:{two}." in err
        assert f"Proxy using socks5://127.0.0.1:{one}." not in err
    finally:
        if session is not None:
            session.close()
        mitm.close()
        good.close()


def test_guest_https_sees_the_real_certificate(tmp_path, monkeypatch):
    """A process in the namespace has to see the canary's real certificate.

    The body has to come through unchanged. A proxy that swapped the
    certificate fails verification, and a relay that changed a byte fails
    the handshake.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 2.0)
    proxy = _Proxy("socks5")
    session = None
    script = (
        "import socket, ssl, sys\n"
        "out = sys.argv[1]\n"
        "try:\n"
        "    raw = socket.create_connection(('1.1.1.1', 443), 5)\n"
        "    raw.settimeout(5)\n"
        "    ctx = ssl.create_default_context()\n"
        f"    ctx.load_verify_locations({_TRUSTED_CA!r})\n"
        "    tls = ctx.wrap_socket(raw, server_hostname='1.1.1.1')\n"
        "    try:\n"
        "        tls.sendall(b'GET /cdn-cgi/trace HTTP/1.1\\r\\n"
        "Host: 1.1.1.1\\r\\nConnection: close\\r\\n\\r\\n')\n"
        "        data = bytearray()\n"
        "        while len(data) < 4096:\n"
        "            chunk = tls.recv(512)\n"
        "            if not chunk:\n"
        "                break\n"
        "            data += chunk\n"
        "    finally:\n"
        "        tls.close()\n"
        "except Exception as exc:\n"
        "    data = b'fail:' + str(exc).encode()\n"
        "open(out, 'wb').write(data)\n"
    )
    try:
        port = proxy.start()
        session = _boot(tmp_path, proxy, kill=False, source=f"socks5://127.0.0.1:{port}")
        body = _guest(session, tmp_path, script)
        assert b"fl=" in body, body
        assert b"fail:" not in body, body
        assert ("1.1.1.1", 443) in proxy.seen
    finally:
        if session is not None:
            session.close()
        proxy.close()


def _proxies_file(directory: Path, proxies: list) -> None:
    lines = [f"{proxy.scheme}://127.0.0.1:{proxy.port}" for proxy in proxies]
    (directory / "proxies").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_ten_are_started_and_only_a_forwarding_proxy_carries_the_guest(tmp_path, monkeypatch, capfd):
    """Nine proxies complete the handshake and then send nothing.

    All ten are started before one is chosen. The guest's ping comes back
    only through the proxy that returned a DNS payload, and a second ping
    does not touch the silent ones again.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.6)
    schemes = ("socks5", "socks4", "http")
    holes = [_Proxy(schemes[i % 3], blackhole=True) for i in range(9)]
    good = _Proxy("socks5")
    proxies = holes + [good]
    session = None
    try:
        for proxy in proxies:
            proxy.start()
        _proxies_file(tmp_path, proxies)
        session = _boot(tmp_path, good, kill=False, source="proxies")
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert session.index == 9
        _wait(
            lambda: all(hole.seen.count(("1.1.1.1", 443)) >= 2 for hole in holes),
            3,
            "a blackhole was never asked to forward",
        )
        counts = [len(hole.seen) for hole in holes]
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert [len(hole.seen) for hole in holes] == counts
        assert ("203.0.113.10", 80) in good.seen
        for hole in holes:
            assert ("203.0.113.10", 80) not in hole.seen
        err = capfd.readouterr().err
        trying = next(line for line in err.splitlines() if line.startswith("Proxy trying 10:"))
        listed = trying.split(": ", 1)[1].split(", ")
        assert listed == [f"{proxy.scheme}://127.0.0.1:{proxy.port}" for proxy in proxies]
        assert f"Proxy using socks5://127.0.0.1:{good.port}." in err
        for hole in holes:
            assert f"Proxy using {hole.scheme}://127.0.0.1:{hole.port}." not in err
    finally:
        if session is not None:
            session.close()
        for proxy in proxies:
            proxy.close()


def test_a_blackhole_batch_is_abandoned_before_the_next_batch(tmp_path, monkeypatch, capfd):
    """Ten silent proxies share one timeout, then the next proxy carries the ping.

    Serial timeouts would be several seconds. The guest still receives pong,
    and none of the silent proxies is announced as the one in use.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.4)
    monkeypatch.setattr(proxy_config, "PARALLEL_ATTEMPTS", 10)
    schemes = ("socks5", "http", "socks4")
    holes = [_Proxy(schemes[i % 3], blackhole=True) for i in range(10)]
    good = _Proxy("http")
    proxies = holes + [good]
    session = None
    try:
        for proxy in proxies:
            proxy.start()
        _proxies_file(tmp_path, proxies)
        session = _boot(tmp_path, good, kill=False, source="proxies")
        started = time.monotonic()
        _wait(lambda: session.index == 10, 5, "did not leave the blackhole batch")
        elapsed = time.monotonic() - started
        assert elapsed < 2.0, elapsed
        assert _guest(session, tmp_path, _PING) == b"pong"
        assert ("203.0.113.10", 80) in good.seen
        for hole in holes:
            assert ("203.0.113.10", 80) not in hole.seen
        _wait(
            lambda: all(hole.seen.count(("1.1.1.1", 443)) >= 2 for hole in holes),
            3,
            "a blackhole in the first batch was never contacted",
        )
        err = capfd.readouterr().err
        trying = next(line for line in err.splitlines() if line.startswith("Proxy trying 10:"))
        listed = trying.split(": ", 1)[1].split(", ")
        assert listed == [f"{hole.scheme}://127.0.0.1:{hole.port}" for hole in holes]
        assert f"Proxy trying 1: http://127.0.0.1:{good.port}" in err
        assert f"Proxy using http://127.0.0.1:{good.port}." in err
        for hole in holes:
            assert f"Proxy using {hole.scheme}://127.0.0.1:{hole.port}." not in err
    finally:
        if session is not None:
            session.close()
        for proxy in proxies:
            proxy.close()


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _expect_hostfwd(session, directory: Path, host_port: int) -> None:
    script = directory / "fwd.py"
    script.write_text(
        "import socket\n"
        "sock = socket.socket()\n"
        "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"sock.bind(('127.0.0.1', {host_port}))\n"
        "sock.listen(1)\n"
        "conn, _addr = sock.accept()\n"
        "conn.sendall(b'ssh-ok')\n"
        "conn.recv(8)\n",
        encoding="utf-8",
    )
    session.spawn([sys.executable, str(script)])
    deadline = time.monotonic() + 5
    last = ""
    while time.monotonic() < deadline:
        try:
            conn = socket.create_connection(("127.0.0.1", host_port), 0.3)
        except OSError as exc:
            last = str(exc)
            time.sleep(0.05)
            continue
        try:
            data = conn.recv(16)
        finally:
            conn.close()
        if data == b"ssh-ok":
            return
        last = repr(data)
    raise AssertionError(f"hostfwd did not answer: {last}")


def test_a_finished_guest_is_reaped_and_its_exit_code_is_visible(tmp_path, monkeypatch):
    """A guest that has exited must not stay 'alive'.

    The supervisor used to leave it as a zombie. os.kill(pid, 0) succeeds on a
    zombie, so the launcher waited forever after QEMU had already quit.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 30)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.3)
    proxy = _Proxy("socks5")
    session = None
    try:
        port = proxy.start()
        session = _boot(
            tmp_path, proxy, kill=False, source=f"socks5://127.0.0.1:{port}",
        )
        proc = session.spawn([sys.executable, "-c", "import sys; sys.exit(3)"])
        _wait(lambda: proc.poll() is not None, 5, "exit was not reaped")
        assert proc.poll() == 3
        assert proc.poll() == 3
    finally:
        if session is not None:
            session.close()
        proxy.close()


def test_hostfwd_is_published_on_the_host(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 0.2)
    monkeypatch.setattr(proxy_config, "PROBE_TIMEOUT_S", 0.3)
    proxy = _Proxy("socks5")
    session = None
    host_port = _free_port()
    try:
        port = proxy.start()
        session = _boot(
            tmp_path, proxy, kill=False, source=f"socks5://127.0.0.1:{port}",
            port_maps=[(22, host_port)],
        )
        _expect_hostfwd(session, tmp_path, host_port)
    finally:
        if session is not None:
            session.close()
        proxy.close()


# --- boot wiring -------------------------------------------------------------

def _stub_boot(monkeypatch):
    import checks
    for name in (
        "require_writable_dir", "require_qemu", "require_ovmf", "require_kvm",
        "require_viewer", "require_not_running",
    ):
        monkeypatch.setattr(checks, name, lambda *a, **k: None)
    monkeypatch.setattr(vm, "_write_viewer_ask_quit", lambda *a, **k: None)
    monkeypatch.setenv("DRYRUN", "1")


def test_prepare_proxy_forces_user_nat_and_refuses_a_bridge_bypass(tmp_path, capsys):
    cfg = make_cfg(str(tmp_path), network="br0", proxy="socks5://127.0.0.1:1080")
    updated, plan = vm._prepare_proxy(cfg)
    assert cfg.hcfg.network == "br0"
    assert updated.hcfg.network == "user"
    assert plan is not None and plan.enabled and not plan.from_file
    assert "user-mode NAT" in capsys.readouterr().err


def test_prepare_proxy_skips_a_guest_with_no_nic(tmp_path, capsys):
    cfg = make_cfg(str(tmp_path), network="none", proxy="http://127.0.0.1:8080")
    updated, plan = vm._prepare_proxy(cfg)
    assert plan is None and updated.hcfg.network == "none"
    assert "no NIC" in capsys.readouterr().err


def test_prepare_proxy_is_idle_when_proxy_is_off(tmp_path):
    cfg = make_cfg(str(tmp_path))
    updated, plan = vm._prepare_proxy(cfg)
    assert plan is None and updated is cfg


def test_dryrun_prints_user_nat_and_does_not_open_a_namespace(tmp_path, monkeypatch, capsys):
    _stub_boot(monkeypatch)
    started = []
    monkeypatch.setattr(
        proxy_runtime.ProxySession, "start",
        lambda *a, **k: started.append(True),
    )
    cfg = make_cfg(
        str(tmp_path), network="br0", proxy="socks5://127.0.0.1:1080",
        proxy_kill_switch=True,
    )
    open(cfg.vars, "wb").close()
    vm.do_run(cfg, headless=True)
    out = capsys.readouterr()
    assert "user,id=net0" in out.out
    assert "br=" not in out.out
    assert not started
    assert "Kill switch: on" in out.err


def test_dryrun_with_network_none_does_not_open_a_namespace(tmp_path, monkeypatch, capsys):
    _stub_boot(monkeypatch)
    started = []
    monkeypatch.setattr(proxy_runtime.ProxySession, "start", lambda *a, **k: started.append(True))
    cfg = make_cfg(str(tmp_path), network="none", proxy="socks5://127.0.0.1:1080")
    open(cfg.vars, "wb").close()
    vm.do_run(cfg, headless=True)
    out = capsys.readouterr()
    assert "user,id=net0" not in out.out
    assert "no NIC" in out.err
    assert not started


def test_a_bad_proxies_file_stops_the_boot(tmp_path, monkeypatch):
    import checks
    for name in (
        "require_writable_dir", "require_qemu", "require_ovmf", "require_kvm",
        "require_viewer", "require_not_running",
    ):
        monkeypatch.setattr(checks, name, lambda *a, **k: None)
    monkeypatch.setattr(vm, "_write_viewer_ask_quit", lambda *a, **k: None)
    (tmp_path / "proxies").write_text("not-a-proxy\n", encoding="utf-8")
    cfg = make_cfg(str(tmp_path), proxy="proxies")
    open(cfg.vars, "wb").close()
    with pytest.raises(HypervisorError, match="line 1"):
        vm.do_run(cfg, headless=True)


# --- the shipped proxy list --------------------------------------------------

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "proxies"
_E2E_LOG = Path("/tmp/qvm-proxy-e2e.log")

def _https_e2e_script() -> str:
    """Guest proof: verified TLS to the canary and to the model API.

    Cleartext port 80 is the wrong proof. A proxy that substitutes its
    certificate still answers it. The model API is resolved inside the
    namespace, over the proxy, and only as IPv4: the namespace has no IPv6,
    and a host-side anycast address is the wrong edge for the proxy.
    One dead dial fails the proxy over; the API call is tried again on the
    next one.
    """
    return (
        "import socket, ssl, sys, time\n"
        "out = sys.argv[1]\n"
        "ctx = ssl.create_default_context()\n"
        "def fetch(ip, server, payload):\n"
        "    raw = socket.create_connection((ip, 443), 20)\n"
        "    raw.settimeout(20)\n"
        "    try:\n"
        "        tls = ctx.wrap_socket(raw, server_hostname=server)\n"
        "    except Exception:\n"
        "        raw.close()\n"
        "        raise\n"
        "    try:\n"
        "        tls.sendall(payload)\n"
        "        chunks = []\n"
        "        while sum(len(c) for c in chunks) < 4096:\n"
        "            piece = tls.recv(512)\n"
        "            if not piece:\n"
        "                break\n"
        "            chunks.append(piece)\n"
        "        return b''.join(chunks)\n"
        "    finally:\n"
        "        tls.close()\n"
        "def api_ips():\n"
        "    socket.setdefaulttimeout(10)\n"
        "    found = []\n"
        "    for info in socket.getaddrinfo('api.x.ai', 443, socket.AF_INET, socket.SOCK_STREAM):\n"
        "        ip = info[4][0]\n"
        "        if ip not in found:\n"
        "            found.append(ip)\n"
        "    return found\n"
        "parts = []\n"
        "try:\n"
        "    trace = fetch(\n"
        "        '1.1.1.1', '1.1.1.1',\n"
        "        b'GET /cdn-cgi/trace HTTP/1.1\\r\\nHost: 1.1.1.1\\r\\n"
        "User-Agent: qvm-e2e\\r\\nConnection: close\\r\\n\\r\\n',\n"
        "    )\n"
        "    parts.append(trace.decode('latin1', 'replace'))\n"
        "    payload = (\n"
        "        b'GET /v1/models HTTP/1.1\\r\\nHost: api.x.ai\\r\\n"
        "User-Agent: qvm-e2e\\r\\nConnection: close\\r\\n\\r\\n'\n"
        "    )\n"
        "    last = 'fail:api was not tried'\n"
        "    for _ in range(2):\n"
        "        try:\n"
        "            ips = api_ips()\n"
        "        except Exception as exc:\n"
        "            last = 'fail:' + str(exc)\n"
        "            time.sleep(1)\n"
        "            continue\n"
        "        for ip in ips:\n"
        "            try:\n"
        "                api = fetch(ip, 'api.x.ai', payload)\n"
        "            except Exception as exc:\n"
        "                last = 'fail:' + ip + ' ' + str(exc)\n"
        "                continue\n"
        "            text = api.decode('latin1', 'replace')\n"
        "            parts.append('\\n---api---\\n' + ip + '\\n' + text)\n"
        "            if text.startswith('HTTP/1.1 401'):\n"
        "                last = ''\n"
        "                break\n"
        "            last = 'fail:api status ' + text.split('\\r\\n', 1)[0]\n"
        "        if not last:\n"
        "            break\n"
        "        time.sleep(1)\n"
        "    if last:\n"
        "        parts.append('\\n' + last)\n"
        "except Exception as exc:\n"
        "    parts.append('\\nfail:' + str(exc))\n"
        "open(out, 'w', encoding='utf-8').write(''.join(parts))\n"
    )


def test_the_shipped_proxy_list_parses():
    text = _FIXTURE.read_text(encoding="utf-8")
    endpoints, errors = proxy_config.parse_proxy_list(text)
    assert errors == []
    assert len(endpoints) >= 10
    assert endpoints[0].render() == "socks4://184.170.251.30:11288"
    assert endpoints[-1].render() == "http://61.29.96.146:80"


def _drain_e2e(capfd, chunks: list[str]) -> None:
    err = capfd.readouterr().err
    if not err:
        return
    chunks.append(err)
    with _E2E_LOG.open("a", encoding="utf-8") as fh:
        fh.write(err)


@pytest.mark.network
def test_guest_reaches_the_internet_through_the_proxy_list(tmp_path, monkeypatch, capfd):
    """Walk the shipped list 10 at a time and keep the first proxy that forwards.

    Proof is read from inside the guest namespace: a verified TLS trace from
    1.1.1.1, then a verified TLS GET /v1/models that comes back as the real
    401. A finished handshake is not enough, and connect() inside the
    namespace returns before the proxy has carried anything.
    """
    monkeypatch.setattr(proxy_config, "PROBE_EVERY_S", 60.0)

    def _prove_once(self) -> None:
        # Park after the first search. A long search already spends the probe
        # interval, so the production loop would open a second connection the
        # moment a proxy is pinned. Some public proxies allow only one.
        endpoints = self._refresh_endpoints()
        if endpoints:
            self._health_once(endpoints)
        self._stop.wait()

    monkeypatch.setattr(proxy_runtime.ProxySession, "_health_loop", _prove_once)
    (tmp_path / "proxies").write_bytes(_FIXTURE.read_bytes())
    plan = proxy_config.load_plan(str(tmp_path), "proxies")
    assert plan.from_file and len(plan.endpoints) >= 10
    _E2E_LOG.write_text(f"e2e start {len(plan.endpoints)} proxies\n", encoding="utf-8")
    session = None
    chunks: list[str] = []
    try:
        session = proxy_runtime.ProxySession.start(plan, False, [], str(tmp_path))
        deadline = time.monotonic() + 5400
        while time.monotonic() < deadline and not session._pinned:
            _drain_e2e(capfd, chunks)
            if any("none of the proxies forwarded" in part for part in chunks):
                break
            time.sleep(0.5)
        time.sleep(0.3)
        _drain_e2e(capfd, chunks)
        captured = "".join(chunks)
        assert session._pinned, "no proxy forwarded\n" + captured[-4000:]
        try:
            body = _guest(
                session, tmp_path, _https_e2e_script(), timeout=180,
            ).decode("latin1", "replace")
        except AssertionError as exc:
            _drain_e2e(capfd, chunks)
            raise AssertionError(f"{exc}\n{''.join(chunks)[-3000:]}") from exc
        _drain_e2e(capfd, chunks)
        captured = "".join(chunks)
        chosen = plan.endpoints[session.index].render()
        low = body.lower()
        assert "fail:" not in body, f"via {chosen}\n{body[:1200]}\n{captured[-2000:]}"
        assert "fl=" in body or "cloudflare" in low, (
            f"via {chosen}\n{body[:800]}\n{captured[-2000:]}"
        )
        api = body.split("---api---", 1)[-1]
        assert "HTTP/1.1 401" in api, (
            f"via {chosen} model API\n{api[:800]}\n{captured[-2000:]}"
        )
        assert "Invalid arguments passed to the model" not in api, (
            f"via {chosen}\n{api[:800]}"
        )
        trying = next(
            (line for line in captured.splitlines() if line.startswith("Proxy trying ")),
            "",
        )
        assert trying.startswith("Proxy trying 10:"), captured[-2000:]
        listed = trying.split(": ", 1)[1].split(", ")
        assert listed == [item.render() for item in plan.endpoints[:10]]
        using_at = captured.find("Proxy using ")
        trying_at = captured.find("Proxy trying 10:")
        assert trying_at != -1 and using_at != -1 and trying_at < using_at
        assert f"Proxy using {chosen}." in captured
    finally:
        if session is not None:
            session.close()
