"""Proxy settings, failover decisions, and the guest network namespace.

The namespace tests stay on 127.0.0.1. Guest destinations are documentation
addresses (203.0.113.0/24) or the slirp resolver (10.0.2.3). A fake proxy on
localhost is the only socket that may answer them. Nothing here is marked
`network`: a passing run does not dial the internet.
"""

from __future__ import annotations

import base64
import socket
import struct
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

    Port 53 is answered as DNS-over-TCP. Anything else is one ping/pong exchange
    with an echo socket, so the payload is not generated by the proxy itself.
    """

    def __init__(self, scheme: str, accept_delay: float = 0.0, refuse: bool = False):
        self.scheme = scheme
        self.accept_delay = accept_delay
        self.refuse = refuse
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
            if self.refuse:
                return
            if dest[1] == 53:
                self._dns(conn)
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
        if self.refuse:
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

    def _dns(self, conn: socket.socket) -> None:
        size = struct.unpack("!H", _recvall(conn, 2))[0]
        payload = _recvall(conn, size)
        answer = b"OK" + payload[:2]
        conn.sendall(struct.pack("!H", len(answer)) + answer)

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
    """Ten-wide (here, both) attempts run together. A later dial keeps the winner
    instead of racing again, so a slow neighbour is not dialed the second time."""
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
