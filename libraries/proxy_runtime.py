"""proxy_runtime.py - send a whole guest's IP traffic through the configured proxy.

QEMU user-mode networking makes the guest's outbound connections from the QEMU
process. This module forks a supervisor into its own user and network namespace
and runs QEMU there. The namespace has no route to the host's real NIC. Its
default route hairpins through a veth pair into a local TPROXY listener, and the
only way those packets leave is a socket the parent dials *to the proxy* (the
parent still lives in the host namespace, so it can reach the proxy, and the
connected fd is passed back with SCM_RIGHTS).

Nothing is forwarded except through that dial. TCP goes through SOCKS4, SOCKS5,
or HTTP CONNECT. DNS (UDP/53) is carried as DNS-over-TCP through the same proxy, and the
reply is written back so the guest still thinks it heard its resolver. Any other
UDP is discarded: an HTTP proxy cannot carry it, and dropping it is what keeps
it off the host's real route.

Proxy_Kill_Switch closes those tunnels and refuses new ones while the proxy is
down, then lets them through again once the proxy answers. With the switch off
and a proxies file, the parent moves one entry down the file after the proxy has
been unreachable for more than 10 seconds.

Host port forwards (SSH and Ports) are published back on the host: QEMU binds
them inside the namespace, and a unix socket bridges the host listener to that
bind. Unix sockets for SPICE and virtiofs are not network and are untouched.
"""

from __future__ import annotations

import ipaddress
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import proxy_config
import proxy_tunnel
from checks import die
from proxy_config import HealthState, ProxyEndpoint, ProxyPlan

_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNET = 0x40000000
_PR_SET_PDEATHSIG = 1

_SOL_IP = 0
_SO_ORIGINAL_DST = 80
_IP_TRANSPARENT = 19
_IP_RECVORIGDSTADDR = 20

_TCP_LISTEN = 12345
_UDP_LISTEN = 1053
_HAIRPIN_SRC = "10.77.0.1"
_HAIRPIN_DST = "10.77.0.2"

_libc = None


def _libc_so():
    global _libc
    if _libc is None:
        import ctypes
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return _libc


def _sockaddr_port_ip(raw: bytes) -> "tuple[str, int] | None":
    """Port and IPv4 address from a kernel sockaddr_in (family, then net-order)."""
    if len(raw) < 8:
        return None
    port, packed = struct.unpack_from("!H4s", raw, 2)
    return socket.inet_ntoa(packed), port


def _public_dns_target(ip: str) -> str:
    """A resolver the proxy can actually reach. A LAN resolver would fail through
    an external proxy and, if dialed directly, would leak. Public addresses are
    kept so the guest's own resolver is the one that answers."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "1.1.1.1"
    if (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    ):
        return "1.1.1.1"
    return ip


def _local_destination(ip: str) -> bool:
    """Addresses that belong to the namespace itself, not to a guest destination."""
    return ip.startswith("127.") or ip in (_HAIRPIN_SRC, _HAIRPIN_DST)


def fwd_socket_path(directory: str) -> str:
    """Pathname unix socket that bridges host port forwards into the namespace.

    Abstract sockets are per-netns, so this has to be a real path. sockaddr_un
    holds about 108 bytes; a very deep VM directory falls back to /tmp.
    """
    path = os.path.join(directory, "proxy-fwd.sock")
    if len(path.encode()) >= 100:
        path = f"/tmp/qvm-{os.getpid()}.proxy-fwd.sock"
    return path


def _send_fd(sock: socket.socket, fd: int, payload: bytes) -> None:
    sock.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))])


def _recv_fd(sock: socket.socket) -> tuple[bytes, "int | None"]:
    data, anc, _flags, _addr = sock.recvmsg(8192, socket.CMSG_SPACE(struct.calcsize("i")))
    got = None
    for level, typ, cdata in anc:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS and len(cdata) >= 4:
            got = struct.unpack("i", cdata[:4])[0]
    return data, got


class _Bag:
    """Sockets the namespace supervisor closes to cut the guest off.

    The parent's copy of a passed fd is not the copy the guest is spliced to, so
    the kill switch tells the supervisor to drop this set. While `drop` is set,
    a socket added here is closed at once and cannot sneak a tunnel through.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._socks: "set[socket.socket]" = set()
        self.drop = False

    def add(self, *socks: socket.socket) -> bool:
        with self._lock:
            if self.drop:
                for sock in socks:
                    try:
                        sock.close()
                    except OSError:
                        pass
                return False
            self._socks.update(socks)
            return True

    def discard(self, *socks: socket.socket) -> None:
        with self._lock:
            for sock in socks:
                self._socks.discard(sock)

    def drop_all(self) -> None:
        with self._lock:
            self.drop = True
            socks = list(self._socks)
            self._socks.clear()
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass

    def allow(self) -> None:
        with self._lock:
            self.drop = False


def _relay(left: socket.socket, right: socket.socket, bag: "_Bag | None" = None) -> None:
    """Copy bytes both ways until either side closes. Returns immediately; the
    pumps are daemon threads so a guest connection cannot pin the supervisor."""
    state = {"left": True, "right": True}
    gate = threading.Lock()

    def pump(src: socket.socket, dst: socket.socket, which: str) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    sent = dst.send(view)
                    view = view[sent:]
        except OSError:
            pass
        finally:
            for end, how in ((src, socket.SHUT_RD), (dst, socket.SHUT_WR)):
                try:
                    end.shutdown(how)
                except OSError:
                    pass
            finished = False
            with gate:
                state[which] = False
                finished = not state["left"] and not state["right"]
            if finished:
                if bag is not None:
                    bag.discard(left, right)
                for end in (left, right):
                    try:
                        end.close()
                    except OSError:
                        pass

    threading.Thread(target=pump, args=(left, right, "left"), daemon=True).start()
    threading.Thread(target=pump, args=(right, left, "right"), daemon=True).start()


class _RemoteProc:
    """The bit of subprocess.Popen that _launch uses, for a QEMU that is not our
    direct child (the namespace supervisor forked it)."""

    def __init__(self, pid: int):
        self.pid = pid
        self.returncode: "int | None" = None

    def poll(self) -> "int | None":
        if self.returncode is not None:
            return self.returncode
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            self.returncode = 0
            return 0
        except PermissionError:
            return None
        return None

    def kill(self) -> None:
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass


def _kill_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _write_id_maps(pid: int) -> None:
    """Make the child root inside its user namespace, mapped to our real uid.

    The child has already unshared. Retry because the proc entries appear a
    moment after unshare on a busy host.
    """
    uid = os.getuid()
    gid = os.getgid()
    last: "Exception | None" = None
    for _ in range(50):
        try:
            with open(f"/proc/{pid}/setgroups", "w", encoding="utf-8") as fh:
                fh.write("deny\n")
            with open(f"/proc/{pid}/uid_map", "w", encoding="utf-8") as fh:
                fh.write(f"0 {uid} 1\n")
            with open(f"/proc/{pid}/gid_map", "w", encoding="utf-8") as fh:
                fh.write(f"0 {gid} 1\n")
            return
        except OSError as exc:
            last = exc
            time.sleep(0.02)
    raise RuntimeError(f"could not map the proxy namespace uid: {last}")


def _close_extra_fds(keep: set[int]) -> None:
    """Close fds this process inherited across fork.

    The supervisor is forked from the launcher, so it starts with every socket
    the launcher had open. A listening proxy socket kept alive in here would
    still complete TCP handshakes after the launcher closed it, and the kill
    switch would think the proxy was up.
    """
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return
    for name in names:
        try:
            fd = int(name)
        except ValueError:
            continue
        if fd in keep:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _read_byte(fd: int, timeout: float) -> bytes:
    ready, _w, _x = select.select([fd], [], [], timeout)
    if not ready:
        raise TimeoutError("timed out waiting for the proxy namespace")
    return os.read(fd, 1)


class ProxySession:
    """Parent-side handle. `start` forks the namespace; `spawn` runs QEMU in it;
    `close` tears both down."""

    def __init__(self) -> None:
        self.plan = ProxyPlan(False, False, "", ())
        self.kill_switch = False
        self.directory = ""
        self._child = 0
        self._ctrl: "socket.socket | None" = None
        self._dial: "socket.socket | None" = None
        self._fwd_path = ""
        self._lock = threading.Lock()
        self._state = HealthState(0, None, False)
        self._endpoints: tuple[ProxyEndpoint, ...] = ()
        self._stop = threading.Event()
        self._closed = False
        self._pids: list[int] = []
        self._listeners: list[socket.socket] = []
        self._ctrl_lock = threading.Lock()
        self._ctrl_buf = bytearray()

    @property
    def killed(self) -> bool:
        with self._lock:
            return self._state.killed

    @property
    def index(self) -> int:
        with self._lock:
            return self._state.index

    @classmethod
    def start(
        cls,
        plan: ProxyPlan,
        kill_switch: bool,
        port_maps: list,
        directory: str,
    ) -> "ProxySession":
        if not plan.enabled or not plan.endpoints:
            die("Proxy is set but no proxy URL could be loaded")
        import shutil
        missing = [tool for tool in ("ip", "iptables") if shutil.which(tool) is None]
        if missing:
            die(
                "Proxy needs "
                + " and ".join(missing)
                + " on PATH to isolate the guest network"
            )

        session = cls()
        session.plan = plan
        session.kill_switch = kill_switch
        session.directory = directory
        session._endpoints = plan.endpoints
        session._fwd_path = fwd_socket_path(directory)

        ctrl_parent, ctrl_child = socket.socketpair()
        dial_parent, dial_child = socket.socketpair()
        for end in (ctrl_parent, ctrl_child, dial_parent, dial_child):
            end.set_inheritable(False)
        ready_r, ready_w = os.pipe()
        go_r, go_w = os.pipe()

        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            try:
                _libc_so().prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
            except Exception:
                pass
            if os.getppid() == 1:
                os._exit(1)
            for end in (ctrl_parent, dial_parent):
                end.close()
            os.close(ready_r)
            os.close(go_w)
            _close_extra_fds({
                ctrl_child.fileno(), dial_child.fileno(), ready_w, go_r, 0, 1, 2,
            })
            try:
                _child_main(
                    ctrl_child, dial_child, ready_w, go_r, session._fwd_path,
                )
            except SystemExit:
                raise
            except Exception as exc:
                try:
                    os.write(ready_w, b"E" + str(exc).encode("utf-8", "replace")[:800] + b"\n")
                except OSError:
                    pass
            os._exit(1)

        ctrl_child.close()
        dial_child.close()
        os.close(ready_w)
        os.close(go_r)
        session._child = pid
        session._ctrl = ctrl_parent
        session._dial = dial_parent
        try:
            mark = _read_byte(ready_r, 5)
            if mark != b"R":
                raise RuntimeError(f"proxy namespace sent {mark!r} instead of ready")
            _write_id_maps(pid)
            os.write(go_w, b"G")
            status = _read_byte(ready_r, 8)
            if status == b"E":
                err = b""
                while not err.endswith(b"\n") and len(err) < 2000:
                    chunk = os.read(ready_r, 2000)
                    if not chunk:
                        break
                    err += chunk
                raise RuntimeError(err.decode("utf-8", "replace").strip() or "proxy namespace failed")
            if status != b"U":
                raise RuntimeError("proxy namespace did not come up")
        except Exception as exc:
            _kill_pid(pid)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            os.close(ready_r)
            os.close(go_w)
            ctrl_parent.close()
            dial_parent.close()
            die(f"Proxy: {exc}")
        os.close(ready_r)
        os.close(go_w)

        threading.Thread(target=session._dial_loop, name="qvm-proxy-dial", daemon=True).start()
        threading.Thread(target=session._health_loop, name="qvm-proxy-health", daemon=True).start()
        for _guest, host_port in port_maps or []:
            session._listen_forward(host_port)
        return session

    def spawn(self, argv: list[str]) -> _RemoteProc:
        """Run `argv` inside the namespace. Used for QEMU."""
        response = self._ctrl_rpc({"op": "exec", "argv": argv})
        if not response.get("ok"):
            die(f"Proxy: could not start the guest: {response.get('error', 'unknown error')}")
        pid = int(response["pid"])
        self._pids.append(pid)
        return _RemoteProc(pid)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        for pid in self._pids:
            _kill_pid(pid)
        for listener in self._listeners:
            try:
                listener.close()
            except OSError:
                pass
        for end in (self._ctrl, self._dial):
            if end is not None:
                try:
                    end.close()
                except OSError:
                    pass
        if self._child:
            _kill_pid(self._child)
            try:
                os.waitpid(self._child, 0)
            except ChildProcessError:
                pass
        if self._fwd_path:
            try:
                os.unlink(self._fwd_path)
            except OSError:
                pass

    def _ctrl_rpc(self, payload: dict) -> dict:
        if self._ctrl is None:
            return {"ok": False, "error": "proxy namespace is gone"}
        raw = (json.dumps(payload) + "\n").encode()
        with self._ctrl_lock:
            try:
                self._ctrl.sendall(raw)
                data = self._readline(self._ctrl)
            except OSError as exc:
                return {"ok": False, "error": str(exc)}
        if not data:
            return {"ok": False, "error": "proxy namespace closed"}
        try:
            return json.loads(data.decode())
        except json.JSONDecodeError:
            return {"ok": False, "error": "proxy namespace sent a bad reply"}

    def _readline(self, sock: socket.socket) -> bytes:
        while b"\n" not in self._ctrl_buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            self._ctrl_buf += chunk
            if len(self._ctrl_buf) > 1_000_000:
                break
        line, _sep, rest = bytes(self._ctrl_buf).partition(b"\n")
        self._ctrl_buf = bytearray(rest)
        return line

    def _current_proxy(self) -> "ProxyEndpoint | None":
        with self._lock:
            if not self._endpoints:
                return None
            return self._endpoints[self._state.index % len(self._endpoints)]

    def _dial_loop(self) -> None:
        sock = self._dial
        if sock is None:
            return
        buf = bytearray()
        while not self._stop.is_set():
            try:
                chunk = sock.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, _sep, rest = bytes(buf).partition(b"\n")
                buf = bytearray(rest)
                self._dial_one(line)

    def _dial_one(self, line: bytes) -> None:
        sock = self._dial
        if sock is None:
            return
        try:
            request = json.loads(line.decode())
            host = str(request["host"])
            port = int(request["port"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            self._dial_fail(f"bad dial request: {exc}")
            return
        with self._lock:
            killed = self._state.killed
            proxy = None if not self._endpoints else self._endpoints[self._state.index % len(self._endpoints)]
        if killed or proxy is None:
            self._dial_fail("proxy kill switch: guest internet is off")
            return
        tunnel = None
        try:
            tunnel = proxy_tunnel.open_tunnel(proxy, host, port)
            with self._lock:
                if self._state.killed:
                    self._dial_fail("proxy kill switch: guest internet is off")
                    return
            _send_fd(sock, tunnel.fileno(), b'{"ok":true}\n')
        except OSError as exc:
            self._dial_fail(str(exc))
        finally:
            # sendmsg duplicated the fd into the namespace. Drop our copy either
            # way; the supervisor owns the one the guest is spliced to.
            if tunnel is not None:
                try:
                    tunnel.close()
                except OSError:
                    pass

    def _dial_fail(self, message: str) -> None:
        if self._dial is None:
            return
        try:
            self._dial.sendall((json.dumps({"ok": False, "error": message}) + "\n").encode())
        except OSError:
            pass

    def _refresh_endpoints(self) -> tuple[ProxyEndpoint, ...]:
        if self.plan.from_file:
            try:
                fresh = proxy_config.load_plan(self.directory, self.plan.source)
            except (OSError, ValueError):
                fresh = None
            if fresh is not None and fresh.endpoints:
                self.plan = fresh
        with self._lock:
            self._endpoints = self.plan.endpoints
            return self._endpoints

    def _health_loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            endpoints = self._refresh_endpoints()
            if endpoints:
                with self._lock:
                    state = self._state
                    if state.index >= len(endpoints):
                        state = HealthState(0, state.down_since, state.killed)
                        self._state = state
                    proxy = endpoints[state.index]
                ok = proxy_tunnel.proxy_reachable(proxy, proxy_config.PROBE_TIMEOUT_S)
                now = time.monotonic()
                new_state, action = proxy_config.note_probe(
                    state,
                    ok=ok,
                    now=now,
                    kill_switch=self.kill_switch,
                    from_file=self.plan.from_file,
                    count=len(endpoints),
                    failover_after=proxy_config.FAILOVER_AFTER_S,
                )
                self._apply(new_state, action, endpoints)
            wait = proxy_config.PROBE_EVERY_S - (time.monotonic() - started)
            if self._stop.wait(max(0.0, wait)):
                return

    def _apply(self, new_state: HealthState, action: str, endpoints: tuple) -> None:
        with self._lock:
            self._state = new_state
        if action == "kill":
            print("Proxy connection lost -- kill switch, guest internet cut.", file=sys.stderr)
            self._ctrl_rpc({"op": "drop"})
        elif action == "restore":
            self._ctrl_rpc({"op": "allow"})
            print("Proxy is answering again -- guest internet restored.", file=sys.stderr)
        elif action == "switch":
            chosen = endpoints[new_state.index % len(endpoints)]
            print(
                f"Proxy unreachable for more than {proxy_config.FAILOVER_AFTER_S:g}s "
                f"-- switching to {chosen.render()}.",
                file=sys.stderr,
            )

    def _listen_forward(self, host_port: int) -> None:
        """Publish one guest hostfwd port on the real host."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("0.0.0.0", host_port))
        except OSError as exc:
            listener.close()
            self.close()
            die(f"Proxy: could not publish host port {host_port}: {exc.strerror or exc}")
        listener.listen(64)
        self._listeners.append(listener)
        threading.Thread(
            target=self._accept_forward, args=(listener, host_port),
            name=f"qvm-fwd-{host_port}", daemon=True,
        ).start()

    def _accept_forward(self, listener: socket.socket, host_port: int) -> None:
        while not self._stop.is_set():
            try:
                client, _addr = listener.accept()
            except OSError:
                return
            threading.Thread(
                target=self._bridge_forward, args=(client, host_port), daemon=True,
            ).start()

    def _bridge_forward(self, client: socket.socket, host_port: int) -> None:
        remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            remote.connect(self._fwd_path)
            remote.sendall(f"{host_port}\n".encode())
        except OSError:
            client.close()
            remote.close()
            return
        _relay(client, remote)


def _run(args: list[str]) -> None:
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"{' '.join(args)} failed: {detail}")


def _child_main(ctrl, dial_sock, ready_w: int, go_r: int, fwd_path: str) -> None:
    libc = _libc_so()
    if libc.unshare(_CLONE_NEWUSER | _CLONE_NEWNET) != 0:
        err = __import__("ctypes").get_errno()
        raise RuntimeError(f"unshare failed (errno {err})")
    os.write(ready_w, b"R")
    if os.read(go_r, 1) != b"G":
        raise RuntimeError("parent did not finish the uid map")
    os.close(go_r)
    _setup_namespace()
    dial_lock = threading.Lock()
    bag = _Bag()

    def dial(host: str, port: int) -> socket.socket:
        if _local_destination(host):
            raise ConnectionError(f"refusing to dial namespace address {host}")
        request = (json.dumps({"host": host, "port": port}) + "\n").encode()
        with dial_lock:
            dial_sock.sendall(request)
            data, fd = _recv_fd(dial_sock)
        if fd is None:
            message = data.decode("utf-8", "replace").strip() or "dial failed"
            try:
                parsed = json.loads(message)
                message = parsed.get("error", message)
            except json.JSONDecodeError:
                pass
            raise ConnectionError(message)
        remote = socket.socket(fileno=fd)
        if not bag.add(remote):
            raise ConnectionError("proxy kill switch: guest internet is off")
        return remote

    _serve_capture(dial_fn=dial, bag=bag)
    _serve_forwards(fwd_path)
    os.write(ready_w, b"U")
    os.close(ready_w)
    _child_control(ctrl, bag)


def _setup_namespace() -> None:
    """Hairpin veth + TPROXY. Proven against this kernel: a connect() to a
    public address is delivered locally with the original destination intact,
    and with ip_forward left off anything TPROXY misses is dropped."""
    _run(["ip", "link", "set", "lo", "up"])
    for key in ("all", "default"):
        _sysctl(f"/proc/sys/net/ipv6/conf/{key}/disable_ipv6", "1")
    _run(["ip", "link", "add", "qv0", "type", "veth", "peer", "name", "qv1"])
    _run(["ip", "addr", "add", f"{_HAIRPIN_SRC}/24", "dev", "qv0"])
    _run(["ip", "addr", "add", f"{_HAIRPIN_DST}/24", "dev", "qv1"])
    _run(["ip", "link", "set", "qv0", "up"])
    _run(["ip", "link", "set", "qv1", "up"])
    for name in ("all", "qv0", "qv1", "lo"):
        _sysctl(f"/proc/sys/net/ipv4/conf/{name}/rp_filter", "0")
        _sysctl(f"/proc/sys/net/ipv4/conf/{name}/accept_local", "1")
    _run(["ip", "route", "add", "default", "via", _HAIRPIN_DST, "dev", "qv0"])
    _run(["ip", "rule", "add", "fwmark", "1", "lookup", "100"])
    _run(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"])
    _run([
        "iptables", "-t", "mangle", "-A", "PREROUTING", "-i", "qv1", "-p", "tcp",
        "-j", "TPROXY", "--on-port", str(_TCP_LISTEN), "--tproxy-mark", "0x1/0x1",
    ])
    _run([
        "iptables", "-t", "mangle", "-A", "PREROUTING", "-i", "qv1", "-p", "udp",
        "-j", "TPROXY", "--on-port", str(_UDP_LISTEN), "--tproxy-mark", "0x1/0x1",
    ])


def _sysctl(path: str, value: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(value + "\n")
    except OSError:
        pass


def _transparent_socket(kind: int, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, kind)
    sock.setsockopt(_SOL_IP, _IP_TRANSPARENT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if kind == socket.SOCK_DGRAM:
        sock.setsockopt(_SOL_IP, _IP_RECVORIGDSTADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.set_inheritable(False)
    return sock


def _serve_capture(dial_fn, bag: _Bag) -> None:
    tcp = _transparent_socket(socket.SOCK_STREAM, _TCP_LISTEN)
    tcp.listen(128)
    udp = _transparent_socket(socket.SOCK_DGRAM, _UDP_LISTEN)
    udp.settimeout(0.5)
    threading.Thread(
        target=_accept_tcp, args=(tcp, dial_fn, bag), name="qvm-proxy-tcp", daemon=True,
    ).start()
    threading.Thread(
        target=_recv_udp, args=(udp, dial_fn, bag), name="qvm-proxy-udp", daemon=True,
    ).start()


def _accept_tcp(listener: socket.socket, dial_fn, bag: _Bag) -> None:
    while True:
        try:
            client, _addr = listener.accept()
        except OSError:
            return
        threading.Thread(target=_handle_tcp, args=(client, dial_fn, bag), daemon=True).start()


def _original_tcp(client: socket.socket) -> "tuple[str, int] | None":
    """The guest's destination. TPROXY does not rewrite it, so getsockname()
    is that address. SO_ORIGINAL_DST is the NAT path and returns ENOENT here
    when nothing was rewritten."""
    try:
        host, port = client.getsockname()[:2]
    except OSError:
        host, port = "", 0
    if host and not (port == _TCP_LISTEN and host in ("0.0.0.0", "::")):
        return str(host), int(port)
    try:
        raw = client.getsockopt(_SOL_IP, _SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    return _sockaddr_port_ip(raw)


def _handle_tcp(client: socket.socket, dial_fn, bag: _Bag) -> None:
    try:
        if not bag.add(client):
            return
        parsed = _original_tcp(client)
        if parsed is None or _local_destination(parsed[0]):
            bag.discard(client)
            client.close()
            return
        host, port = parsed
        remote = dial_fn(host, port)
    except Exception:
        bag.discard(client)
        try:
            client.close()
        except OSError:
            pass
        return
    _relay(client, remote, bag)


def _recv_udp(listener: socket.socket, dial_fn, bag: _Bag) -> None:
    while True:
        try:
            data, anc, _flags, addr = listener.recvmsg(65535, 512)
        except socket.timeout:
            continue
        except OSError:
            return
        if bag.drop:
            continue
        parsed = None
        for _level, typ, cdata in anc:
            if typ == _IP_RECVORIGDSTADDR:
                parsed = _sockaddr_port_ip(cdata)
        if not data or parsed is None or parsed[1] != 53 or _local_destination(parsed[0]):
            continue
        threading.Thread(
            target=_handle_dns, args=(data, addr, parsed, dial_fn, bag), daemon=True,
        ).start()


def _handle_dns(payload: bytes, client_addr, orig: tuple, dial_fn, bag: _Bag) -> None:
    targets = []
    primary = _public_dns_target(orig[0])
    for candidate in (primary, "1.1.1.1", "8.8.8.8"):
        if candidate not in targets:
            targets.append(candidate)
    remote = None
    for target in targets:
        try:
            remote = dial_fn(target, 53)
            break
        except OSError:
            remote = None
    if remote is None or bag.drop:
        if remote is not None:
            bag.discard(remote)
            remote.close()
        return
    try:
        remote.settimeout(5)
        remote.sendall(struct.pack("!H", len(payload)) + payload)
        header = proxy_tunnel.recvall(remote, 2)
        size = struct.unpack("!H", header)[0]
        if size > 8192:
            return
        body = proxy_tunnel.recvall(remote, size) if size else b""
    except OSError:
        return
    finally:
        bag.discard(remote)
        remote.close()
    if body:
        _udp_reply(orig, client_addr, body)


def _udp_reply(orig: tuple, client_addr, payload: bytes) -> None:
    reply = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        reply.setsockopt(_SOL_IP, _IP_TRANSPARENT, 1)
        reply.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            reply.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        reply.bind(orig)
        reply.sendto(payload, client_addr)
    except OSError:
        pass
    finally:
        reply.close()


def _serve_forwards(path: str) -> None:
    if os.path.exists(path):
        os.unlink(path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.set_inheritable(False)
    server.bind(path)
    os.chmod(path, 0o666)
    server.listen(64)
    threading.Thread(target=_accept_forward, args=(server,), name="qvm-proxy-fwd", daemon=True).start()


def _accept_forward(server: socket.socket) -> None:
    while True:
        try:
            conn, _addr = server.accept()
        except OSError:
            return
        threading.Thread(target=_handle_forward, args=(conn,), daemon=True).start()


def _handle_forward(conn: socket.socket) -> None:
    try:
        buf = bytearray()
        while b"\n" not in buf:
            chunk = conn.recv(256)
            if not chunk:
                conn.close()
                return
            buf += chunk
            if len(buf) > 64:
                break
        line, _sep, rest = bytes(buf).partition(b"\n")
        port = int(line.strip())
        guest = socket.create_connection(("127.0.0.1", port), timeout=5)
        if rest:
            guest.sendall(rest)
    except (OSError, ValueError):
        conn.close()
        return
    _relay(conn, guest)


def _child_control(ctrl: socket.socket, bag: _Bag) -> None:
    buf = bytearray()
    while True:
        try:
            chunk = ctrl.recv(65536)
        except OSError:
            return
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, _sep, rest = bytes(buf).partition(b"\n")
            buf = bytearray(rest)
            _child_command(ctrl, line, bag)


def _child_command(ctrl: socket.socket, line: bytes, bag: _Bag) -> None:
    try:
        request = json.loads(line.decode())
    except json.JSONDecodeError as exc:
        _ctrl_reply(ctrl, {"ok": False, "error": str(exc)})
        return
    op = request.get("op")
    if op == "drop":
        bag.drop_all()
        _ctrl_reply(ctrl, {"ok": True})
        return
    if op == "allow":
        bag.allow()
        _ctrl_reply(ctrl, {"ok": True})
        return
    if op != "exec":
        _ctrl_reply(ctrl, {"ok": False, "error": "expected exec"})
        return
    argv = request.get("argv")
    if not isinstance(argv, list) or not argv:
        _ctrl_reply(ctrl, {"ok": False, "error": "expected exec"})
        return
    # posix_spawn, not fork: the supervisor already has capture threads, and a
    # fork from a multithreaded process can deadlock on a lock those threads hold.
    try:
        pid = os.posix_spawnp(str(argv[0]), [str(part) for part in argv], os.environ)
    except OSError as exc:
        _ctrl_reply(ctrl, {"ok": False, "error": str(exc)})
        return
    _ctrl_reply(ctrl, {"ok": True, "pid": pid})


def _ctrl_reply(ctrl: socket.socket, payload: dict) -> None:
    try:
        ctrl.sendall((json.dumps(payload) + "\n").encode())
    except OSError:
        pass
