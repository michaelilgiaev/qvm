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
not forwarding, then lets them through again once that same proxy forwards.
With the switch off and a proxies file, proxies are proved PARALLEL_ATTEMPTS
at a time. The whole group is started together. The one that first carries two
verified HTTPS replies is the fastest, and it is kept. Every other proxy in
that group that also carries them is saved, slowest last, and used in that
order when the current one stops forwarding. A handshake that never sends a
payload is not a win, and a substituted certificate is not a win. A guest
connection that fails, times out, or gets no reply abandons that proxy at
once and the next ones are tried together. Open sockets are not treated as
proof that the proxy still works.

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
import ssl
import struct
import subprocess
import sys
import threading
import time

import proxy_config
import proxy_tunnel
from checks import die
from proxy_config import HealthState, ProxyEndpoint, ProxyPlan, ProxyRecord

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


def _open_guest_tunnel(proxy: ProxyEndpoint, host: str, port: int) -> socket.socket:
    """Dial `proxy` for one guest destination. The budget is short on purpose.

    A proxy that cannot finish this tunnel inside it is abandoned. Retrying
    the same one, or waiting out the canary window, is what left the guest
    with no internet while the next proxy sat unused.
    """
    budget = proxy_config.GUEST_DIAL_TIMEOUT_S
    return proxy_tunnel.open_tunnel(
        proxy, host, port, timeout=budget, connect_timeout=budget,
    )


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

    def count(self) -> int:
        with self._lock:
            return len(self._socks)


def _relay(
    left: socket.socket, right: socket.socket, bag: "_Bag | None" = None,
    on_stall=None,
) -> None:
    """Copy bytes both ways until either side closes. Returns immediately; the
    pumps are daemon threads so a guest connection cannot pin the supervisor.

    `right` is the proxy side when `on_stall` is set. If that side sends
    nothing within the guest budget, the tunnel is closed and `on_stall`
    runs. A handshake that then stays silent is not a working proxy.
    """
    state = {"left": True, "right": True, "proxy": False}
    gate = threading.Lock()

    def pump(src: socket.socket, dst: socket.socket, which: str) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                if which == "right":
                    state["proxy"] = True
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
    if on_stall is None:
        return

    def watch() -> None:
        time.sleep(proxy_config.GUEST_DIAL_TIMEOUT_S)
        if state["proxy"]:
            return
        try:
            on_stall()
        except OSError:
            pass
        for end in (left, right):
            try:
                end.close()
            except OSError:
                pass

    threading.Thread(target=watch, daemon=True).start()


def _exit_code(status: int) -> int:
    """Turn a waitpid status into the same code subprocess.Popen uses."""
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return 1


class _RemoteProc:
    """The bit of subprocess.Popen that _launch uses, for a QEMU that is not our
    direct child (the namespace supervisor forked it).

    os.kill(pid, 0) succeeds on a zombie, so a QEMU that has already exited
    looked alive and _wait_any never returned. The supervisor is the parent
    that can waitpid it; poll asks that supervisor."""

    def __init__(self, pid: int, poll_fn=None):
        self.pid = pid
        self.returncode: "int | None" = None
        self._poll_fn = poll_fn

    def poll(self) -> "int | None":
        if self.returncode is not None:
            return self.returncode
        if self._poll_fn is not None:
            code = self._poll_fn(self.pid)
            if code is None:
                return None
            self.returncode = code
            return code
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
        self._pinned = False  # current index has forwarded real bytes
        self._announced = False
        self._pin_gen = 0
        # (latency seconds, endpoint key) for proxies that already forwarded.
        # Fastest first. The one in use stays here until it fails.
        self._working: list[tuple[float, tuple]] = []
        # Trace fields (loc, ip, colo) keyed the same way as _working.
        self._details: dict[tuple, dict] = {}
        # Repeated checks: uptime streak, success and failure counts, latency.
        self._ledger: dict[tuple, ProxyRecord] = {}
        self._recheck_at = 0
        self._pool_cursor = 0
        # Proxy keys with a background check running. The dial thread never
        # waits on these.
        self._inflight: set = set()
        self._note = ""
        self._finding = False
        self._find_cv = threading.Condition()
        self._endpoints: tuple[ProxyEndpoint, ...] = ()
        self._stop = threading.Event()
        self._closed = False
        self._pids: list[int] = []
        self._listeners: list[socket.socket] = []
        self._ctrl_lock = threading.Lock()
        self._ctrl_buf = bytearray()
        self._stall: "socket.socket | None" = None
        # Ignore stall notices until this time. A notice from the proxy we
        # just left must not abandon the one we just moved to.
        self._stall_until = 0.0

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
        stall_parent, stall_child = socket.socketpair()
        for end in (ctrl_parent, ctrl_child, dial_parent, dial_child, stall_parent, stall_child):
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
            for end in (ctrl_parent, dial_parent, stall_parent):
                end.close()
            os.close(ready_r)
            os.close(go_w)
            _close_extra_fds({
                ctrl_child.fileno(), dial_child.fileno(), stall_child.fileno(),
                ready_w, go_r, 0, 1, 2,
            })
            try:
                _child_main(
                    ctrl_child, dial_child, stall_child, ready_w, go_r,
                    session._fwd_path,
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
        stall_child.close()
        os.close(ready_w)
        os.close(go_r)
        session._child = pid
        session._ctrl = ctrl_parent
        session._dial = dial_parent
        session._stall = stall_parent
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
            stall_parent.close()
            die(f"Proxy: {exc}")
        os.close(ready_r)
        os.close(go_w)

        threading.Thread(target=session._dial_loop, name="qvm-proxy-dial", daemon=True).start()
        threading.Thread(target=session._stall_loop, name="qvm-proxy-stall", daemon=True).start()
        threading.Thread(target=session._command_loop, name="qvm-proxy-cmd", daemon=True).start()
        threading.Thread(target=session._pool_loop, name="qvm-proxy-pool", daemon=True).start()
        threading.Thread(target=session._health_loop, name="qvm-proxy-health", daemon=True).start()
        session._publish_status()
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
        return _RemoteProc(pid, self._poll_remote)

    def _poll_remote(self, pid: int) -> "int | None":
        """None while `pid` still runs. The supervisor reaps it and returns the code."""
        if self._closed or self._ctrl is None:
            return 0
        response = self._ctrl_rpc({"op": "poll", "pid": pid})
        if not response.get("ok"):
            return 0
        if response.get("running"):
            return None
        try:
            return int(response.get("status", 0))
        except (TypeError, ValueError):
            return 0

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
        for end in (self._ctrl, self._dial, self._stall):
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
        directory = getattr(self, "directory", "")
        if directory:
            for name in (proxy_config.STATUS_NAME, proxy_config.CMD_NAME):
                try:
                    os.unlink(os.path.join(directory, name))
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

    @staticmethod
    def _proxy_key(proxy: ProxyEndpoint) -> tuple:
        return (proxy.scheme, proxy.host, proxy.port, proxy.username, proxy.password)

    def _remember_working(
        self, proxy: ProxyEndpoint, latency: float, info: "dict | None" = None,
    ) -> None:
        """Keep a proxy that forwarded, fastest first. A repeat replaces its time."""
        key = self._proxy_key(proxy)
        now = time.monotonic()
        with self._lock:
            prior = self._ledger.get(key) or ProxyRecord()
            self._ledger[key] = proxy_config.note_health(
                prior, ok=True, now=now, latency=latency,
            )
            self._working = [item for item in self._working if item[1] != key]
            self._working.append((latency, key))
            self._working.sort(key=self._working_sort)
            if info:
                self._details[key] = {
                    "loc": str(info.get("loc") or ""),
                    "ip": str(info.get("ip") or ""),
                    "colo": str(info.get("colo") or ""),
                }
        self._publish_status()

    def _record_failure(self, proxy: ProxyEndpoint) -> None:
        """Count a failed check. The uptime streak ends."""
        key = self._proxy_key(proxy)
        now = time.monotonic()
        with self._lock:
            prior = self._ledger.get(key) or ProxyRecord()
            self._ledger[key] = proxy_config.note_health(prior, ok=False, now=now)
        self._publish_status()

    def _working_sort(self, item: tuple) -> tuple:
        """Fastest measured proxy first. A down proxy sorts last."""
        _latency, key = item
        return proxy_config.selection_key(self._ledger.get(key), time.monotonic())

    def _forget_working(self, proxy: ProxyEndpoint) -> None:
        key = self._proxy_key(proxy)
        with self._lock:
            self._working = [item for item in self._working if item[1] != key]
            self._details.pop(key, None)

    def _take_standby(self) -> "tuple[int, ProxyEndpoint] | None":
        """The fastest saved proxy that is still in the file and not down."""
        with self._lock:
            endpoints = self._endpoints
            if not endpoints or not self._working:
                return None
            now = time.monotonic()
            ranked = sorted(self._working, key=self._working_sort)
            by_key = {self._proxy_key(ep): (i, ep) for i, ep in enumerate(endpoints)}
            for _latency, key in ranked:
                if proxy_config.health_label(self._ledger.get(key), now) == "down":
                    continue
                found = by_key.get(key)
                if found is not None:
                    return found
        return None

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
            endpoints = self._endpoints
            index = 0 if not endpoints else self._state.index % len(endpoints)
        if killed or not endpoints:
            self._dial_fail("proxy kill switch: guest internet is off")
            return
        single = self.kill_switch or not self.plan.from_file or len(endpoints) < 2
        if single:
            self._dial_fixed(sock, endpoints, index, host, port)
            return
        self._dial_pinned(sock, endpoints, index, host, port)

    def _dial_fixed(self, dial_sock, endpoints, index: int, host: str, port: int) -> None:
        """One URL, or the kill switch: that proxy only. Never the host route."""
        proxy = endpoints[index]
        tunnel = None
        try:
            tunnel = _open_guest_tunnel(proxy, host, port)
            owned = tunnel
            tunnel = None
            self._pass_tunnel(dial_sock, index, proxy, owned)
        except proxy_tunnel.ProxyDown as exc:
            self._note_current(proxy, False)
            self._dial_fail(str(exc))
        except OSError as exc:
            self._dial_fail(str(exc))
        finally:
            if tunnel is not None:
                try:
                    tunnel.close()
                except OSError:
                    pass

    def _dial_pinned(self, dial_sock, endpoints, index: int, host: str, port: int) -> None:
        """Dial the proxy that has forwarded bytes. Prove one first if none has."""
        chosen = self._await_working(index)
        with self._lock:
            endpoints = self._endpoints
            killed = self._state.killed
            if endpoints and self._pinned:
                chosen = self._state.index % len(endpoints)
        if killed or not endpoints or chosen is None:
            self._dial_fail(
                "proxy kill switch: guest internet is off"
                if killed else "no proxy is forwarding"
            )
            return
        self._dial_through(dial_sock, endpoints, chosen, host, port, allow_search=True)

    def _dial_through(
        self, dial_sock, endpoints, index: int, host: str, port: int, allow_search: bool,
    ) -> None:
        proxy = endpoints[index % len(endpoints)]
        tunnel = None
        with self._lock:
            gen = self._pin_gen
        try:
            tunnel = _open_guest_tunnel(proxy, host, port)
            owned = tunnel
            tunnel = None
            self._pass_tunnel(dial_sock, index % len(endpoints), proxy, owned)
        except OSError as exc:
            # Timeout, refusal, and a dead proxy are the same to the guest:
            # this one is not carrying the connection. Try the next group
            # for this same destination instead of sitting on it.
            if not allow_search:
                self._dial_fail(str(exc))
                return
            failed = index % len(endpoints)
            self._abandon_if_current(failed, gen)
            fresh = self._endpoints or endpoints
            won = self._race_destination(
                fresh, (failed + 1) % len(fresh), host, port, exclude=failed,
            )
            if won is None:
                self._dial_fail(str(exc))
                return
            win_index, win_tunnel = won
            self._pass_tunnel(dial_sock, win_index, fresh[win_index], win_tunnel)
        finally:
            if tunnel is not None:
                try:
                    tunnel.close()
                except OSError:
                    pass

    def _await_working(self, start: int) -> "int | None":
        """Index of a proxy that has forwarded bytes.

        One search runs at a time. A guest dial and a health probe share it,
        so the two cannot pin two different proxies.
        """
        with self._find_cv:
            while True:
                with self._lock:
                    if self._state.killed or not self._endpoints:
                        return None
                    if self._pinned:
                        return self._state.index % len(self._endpoints)
                if not self._finding:
                    self._finding = True
                    break
                self._find_cv.wait()
        try:
            return self._search_forwarding(start)
        finally:
            with self._find_cv:
                self._finding = False
                self._find_cv.notify_all()

    def _search_forwarding(self, start: int) -> "int | None":
        """Start each group, then keep the first proxy that returns bytes.

        One pass. A proxy that only finishes a handshake, or that refuses the
        canary, is not pinned. The next group starts after this one fails.
        """
        with self._lock:
            endpoints = tuple(self._endpoints)
        count = len(endpoints)
        if count < 1:
            return None
        # A proxy that already forwarded beats scanning another cold group.
        standby = self._take_standby()
        if standby is not None:
            index, proxy = standby
            self._pin_forwarding(index, proxy)
            return index
        groups = proxy_config.batch_indexes(count, start, proxy_config.PARALLEL_ATTEMPTS)
        for group in groups:
            if self._stop.is_set():
                return None
            with self._lock:
                if self._state.killed:
                    return None
                if self._pinned and self._endpoints:
                    return self._state.index % len(self._endpoints)
            batch = [(i, endpoints[i]) for i in group]
            shown = ", ".join(proxy.render() for _i, proxy in batch)
            print(f"Proxy trying {len(batch)}: {shown}", file=sys.stderr, flush=True)
            winner = self._first_that_forwards(batch)
            if winner is None:
                continue
            self._pin_forwarding(winner, endpoints[winner])
            return winner
        if not self._stop.is_set():
            print("Proxy: none of the proxies forwarded traffic.", file=sys.stderr, flush=True)
        return None

    def _first_that_forwards(self, batch: list) -> "int | None":
        """Start every proxy in `batch`. The first one that forwards wins.

        The gate opens only after every attempt is running, so a fast handshake
        cannot settle the group before the others have been started. The call
        returns when the first payload arrives; a silent neighbour keeps
        running but does not delay that choice.
        """
        found = threading.Event()
        go = threading.Event()
        lock = threading.Lock()
        winner: list[int] = []
        timeout = proxy_config.PROBE_TIMEOUT_S

        def attempt(index: int, proxy: ProxyEndpoint) -> None:
            if not go.wait(2.0):
                return
            started = time.monotonic()
            try:
                info = proxy_tunnel.probe_details(proxy, timeout)
            except Exception:
                info = None
            if not info:
                return
            latency = time.monotonic() - started
            self._remember_working(proxy, latency, info)
            with lock:
                first = not winner
                if first:
                    winner.append(index)
                    found.set()
            if not first:
                loc = str(info.get("loc") or "")
                place = f", {proxy_config.country_name(loc)}" if loc else ""
                print(
                    f"Proxy standby {proxy.render()} ({latency:.2f}s{place}).",
                    file=sys.stderr, flush=True,
                )

        threads = []
        for index, proxy in batch:
            thread = threading.Thread(
                target=attempt, args=(index, proxy), name="qvm-proxy-race", daemon=True,
            )
            thread.start()
            threads.append(thread)
        go.set()
        # One budget for the whole group. A proxy that has not proved itself
        # by then is left behind, and the next group starts. Waiting out every
        # slow handshake is what made a dead batch feel stuck.
        deadline = time.monotonic() + timeout + 0.25
        while not found.is_set() and time.monotonic() < deadline:
            with self._lock:
                # The background bench may already have pinned a working proxy
                # while this cold group is still timing out.
                if self._pinned and self._endpoints:
                    return self._state.index % len(self._endpoints)
            if threads and all(not thread.is_alive() for thread in threads):
                break
            found.wait(0.02)
        return winner[0] if winner else None

    def _pin_forwarding(self, index: int, proxy: ProxyEndpoint) -> None:
        with self._lock:
            if self._state.killed:
                return
            self._state = HealthState(index, None, False)
            self._pinned = True
            self._pin_gen += 1
            self._stall_until = time.monotonic() + proxy_config.GUEST_DIAL_TIMEOUT_S
            announce = not self._announced
            self._announced = True
        if announce:
            print(f"Proxy using {proxy.render()}.", file=sys.stderr, flush=True)
        self._publish_status()

    def _drop_pin(self, index: int) -> None:
        proxy = None
        with self._lock:
            if self._endpoints and 0 <= index < len(self._endpoints):
                proxy = self._endpoints[index]
            if self._pinned and self._state.index == index:
                self._pinned = False
                self._announced = False
                self._pin_gen += 1
        if proxy is not None:
            self._forget_working(proxy)

    def _abandon_if_current(self, index: int, gen: int) -> None:
        """Drop `index` only when it is still the pinned proxy.

        A second guest connection failing at the same moment must not drop
        the proxy the first failure already moved to.
        """
        proxy = None
        with self._lock:
            if self._pin_gen != gen or not self._pinned or self._state.index != index:
                return
            if self._endpoints and 0 <= index < len(self._endpoints):
                proxy = self._endpoints[index]
            self._pinned = False
            self._announced = False
            self._pin_gen += 1
            self._stall_until = time.monotonic() + proxy_config.GUEST_DIAL_TIMEOUT_S
        if proxy is None:
            return
        self._record_failure(proxy)
        self._forget_working(proxy)
        print(f"Proxy stopped forwarding {proxy.render()}.", file=sys.stderr, flush=True)

    def _abandon_current(self) -> None:
        """The pinned proxy went silent. Move on, and drop the stuck tunnels."""
        if self.kill_switch or not self.plan.from_file:
            return
        with self._lock:
            endpoints = self._endpoints
            if not endpoints or len(endpoints) < 2 or not self._pinned:
                return
            if time.monotonic() < self._stall_until:
                return
            index = self._state.index % len(endpoints)
            gen = self._pin_gen
        self._abandon_if_current(index, gen)
        self._ctrl_rpc({"op": "drop"})
        self._ctrl_rpc({"op": "allow"})
        fresh = self._endpoints or endpoints
        self._await_working((index + 1) % len(fresh))

    def _stall_loop(self) -> None:
        sock = self._stall
        if sock is None:
            return
        sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data = sock.recv(64)
            except TimeoutError:
                continue
            except OSError:
                return
            if not data:
                return
            self._abandon_current()

    def _command_loop(self) -> None:
        """Pick up `proxy.cmd` from `qvm --configure` without waiting on a probe."""
        path = os.path.join(self.directory, proxy_config.CMD_NAME)
        while not self._stop.is_set():
            if os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8") as fh:
                        text = fh.read()
                    os.unlink(path)
                except OSError:
                    text = ""
                if "next" in text.lower():
                    self._force_next()
            if self._stop.wait(0.05):
                return

    def _force_next(self) -> None:
        """Drop the proxy in use and pin the next saved one, with no new canary."""
        if self.kill_switch:
            self._note = "Kill switch is on. This proxy stays."
            self._publish_status()
            return
        with self._lock:
            endpoints = tuple(self._endpoints)
            pinned = self._pinned
            index = 0 if not endpoints else self._state.index % len(endpoints)
            gen = self._pin_gen
        if not self.plan.from_file or len(endpoints) < 2:
            self._note = "Only one proxy is configured."
            self._publish_status()
            return
        if pinned:
            self._abandon_if_current(index, gen)
        standby = self._take_standby()
        self._ctrl_rpc({"op": "drop"})
        self._ctrl_rpc({"op": "allow"})
        if standby is not None:
            nxt, proxy = standby
            self._pin_forwarding(nxt, proxy)
            self._note = f"Switched to {proxy.render()}."
            self._publish_status()
            return
        self._note = "No saved proxy. Trying the next 10."
        self._publish_status()
        self._await_working((index + 1) % len(endpoints))
        self._publish_status()

    def _health_fields(self, key: tuple, latency: "float | None", now: float) -> dict:
        record = self._ledger.get(key)
        label = proxy_config.health_label(record, now)
        up = 0
        if record is not None and record.streak_since is not None and record.streak_ok:
            up = int(max(0.0, now - record.streak_since))
        shown = latency
        if shown is None and record is not None:
            shown = record.latency
        return {
            "latency_ms": None if shown is None else int(round(shown * 1000)),
            "state": label,
            "uptime_s": up,
            "ok": 0 if record is None else record.ok_count,
            "fail": 0 if record is None else record.fail_count,
            "responsive": label in ("responsive", "durable"),
            "durable": label == "durable",
        }

    def _status_document(self) -> dict:
        now = time.monotonic()
        with self._lock:
            endpoints = tuple(self._endpoints)
            pinned = self._pinned
            index = 0 if not endpoints else self._state.index % len(endpoints)
            working = list(self._working)
            details = dict(self._details)
            note = self._note
            by_key = {self._proxy_key(ep): ep for ep in endpoints}

            def row(key: tuple, latency: "float | None") -> "dict | None":
                proxy = by_key.get(key)
                if proxy is None:
                    return None
                info = details.get(key) or {}
                loc = str(info.get("loc") or "")
                fields = self._health_fields(key, latency, now)
                fields.update({
                    "url": proxy.render(),
                    "country": loc,
                    "country_name": proxy_config.country_name(loc),
                    "exit_ip": str(info.get("ip") or ""),
                    "colo": str(info.get("colo") or ""),
                })
                return fields

            current = None
            current_key = None
            if pinned and endpoints:
                current_key = self._proxy_key(endpoints[index])
                latency = next((lat for lat, key in working if key == current_key), None)
                current = row(current_key, latency)
            standbys = []
            for latency, key in working:
                if key == current_key:
                    continue
                item = row(key, latency)
                if item is not None and item.get("state") != "down":
                    standbys.append(item)
            failed = []
            for key, record in self._ledger.items():
                if proxy_config.health_label(record, now) != "down":
                    continue
                item = row(key, record.latency)
                if item is not None:
                    failed.append((record.last_fail or 0, item))
            failed.sort(key=lambda pair: pair[0], reverse=True)
        return {
            "running": True,
            "current": current,
            "standbys": standbys,
            "failed": [item for _when, item in failed[:8]],
            "note": note,
        }

    def _publish_status(self) -> None:
        directory = getattr(self, "directory", "")
        if not directory:
            return
        path = os.path.join(directory, proxy_config.STATUS_NAME)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._status_document(), fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _next_candidates(self, endpoints, start: int, exclude: int) -> list:
        """Up to PARALLEL_ATTEMPTS proxies to try for one guest destination.

        Saved proxies come first. The rest of the file fills the group. The
        proxy that just failed is not in the group.
        """
        chosen: list = []
        seen = {exclude}
        with self._lock:
            working = list(self._working)
        by_key = {self._proxy_key(ep): i for i, ep in enumerate(endpoints)}
        for _latency, key in working:
            index = by_key.get(key)
            if index is None or index in seen:
                continue
            seen.add(index)
            chosen.append((index, endpoints[index]))
            if len(chosen) >= proxy_config.PARALLEL_ATTEMPTS:
                return chosen
        # Saved proxies are tried on their own. A cold scan only happens when
        # none of them is left, and that scan is the one that is announced.
        if chosen:
            return chosen
        for group in proxy_config.batch_indexes(
            len(endpoints), start, proxy_config.PARALLEL_ATTEMPTS,
        ):
            for index in group:
                if index in seen:
                    continue
                seen.add(index)
                chosen.append((index, endpoints[index]))
                if len(chosen) >= proxy_config.PARALLEL_ATTEMPTS:
                    break
            break
        if chosen:
            shown = ", ".join(ep.render() for _i, ep in chosen)
            print(f"Proxy trying {len(chosen)}: {shown}", file=sys.stderr, flush=True)
        return chosen

    def _race_destination(self, endpoints, start: int, host: str, port: int, exclude: int):
        """First proxy in the next group that opens `host:port`. None if none do."""
        candidates = self._next_candidates(endpoints, start, exclude)
        if not candidates:
            return None
        found = threading.Event()
        lock = threading.Lock()
        winner: list = []

        def attempt(index: int, proxy: ProxyEndpoint) -> None:
            tunnel = None
            try:
                tunnel = _open_guest_tunnel(proxy, host, port)
            except OSError:
                self._record_failure(proxy)
                self._forget_working(proxy)
                return
            with lock:
                if winner:
                    try:
                        tunnel.close()
                    except OSError:
                        pass
                    return
                winner.append((index, tunnel))
                found.set()

        for index, proxy in candidates:
            threading.Thread(
                target=attempt, args=(index, proxy), name="qvm-proxy-dial", daemon=True,
            ).start()
        found.wait(proxy_config.GUEST_DIAL_TIMEOUT_S + 0.4)
        if not winner:
            return None
        index, tunnel = winner[0]
        self._remember_working(endpoints[index], proxy_config.GUEST_DIAL_TIMEOUT_S)
        self._pin_forwarding(index, endpoints[index])
        return index, tunnel

    def _pass_tunnel(
        self, dial_sock: socket.socket, index: int, proxy: ProxyEndpoint, tunnel: socket.socket,
    ) -> bool:
        """Hand `tunnel` to the namespace. Say which proxy, at most once per pin."""
        try:
            announce = False
            failed = ""
            with self._lock:
                if self._state.killed:
                    failed = "proxy kill switch: guest internet is off"
                elif self._pinned and self._state.index != index:
                    failed = "proxy changed"
                else:
                    self._state = HealthState(index, None, False)
                    self._pinned = True
                    self._pin_gen += 1
                    self._stall_until = time.monotonic() + proxy_config.GUEST_DIAL_TIMEOUT_S
                    announce = not self._announced
                    self._announced = True
            if failed:
                self._dial_fail(failed)
                return False
            if announce:
                print(f"Proxy using {proxy.render()}.", file=sys.stderr, flush=True)
            _send_fd(dial_sock, tunnel.fileno(), b'{"ok":true}\n')
            return True
        finally:
            # sendmsg duplicated the fd. Drop our copy; the namespace owns the
            # one the guest is spliced to.
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

    def _guest_sockets(self) -> int:
        """How many sockets the namespace is holding for the guest.

        A non-zero count is not proof the proxy works: those sockets may be
        stuck. The health check still runs, and it asks for a fast answer.
        """
        response = self._ctrl_rpc({"op": "active"})
        if not response.get("ok"):
            return 0
        try:
            return int(response.get("n") or 0)
        except (TypeError, ValueError):
            return 0

    def _health_loop(self) -> None:
        while not self._stop.is_set():
            endpoints = self._refresh_endpoints()
            if endpoints:
                self._health_once(endpoints)
            # Always the full interval. A search can take much longer than
            # one probe, and probing again the instant it returns opens a
            # connection on top of the guest's first dial.
            if self._stop.wait(proxy_config.PROBE_EVERY_S):
                return

    def _health_once(self, endpoints: tuple) -> None:
        """Watch the proxy that is allowed to carry the guest.

        A kill switch and a single URL stay on that one proxy: forwarding
        restores the guest, silence cuts it, and nothing falls through to the
        host. A proxies file proves PARALLEL_ATTEMPTS at a time, then watches
        only the one that returned bytes. When that one stops, the next group
        is started.
        """
        single = self.kill_switch or not self.plan.from_file or len(endpoints) < 2
        with self._lock:
            index = self._state.index % len(endpoints)
            proxy = endpoints[index]
            pinned = self._pinned
            gen = self._pin_gen
        if single:
            if not self._guest_sockets():
                started = time.monotonic()
                info = proxy_tunnel.probe_details(proxy, proxy_config.PROBE_TIMEOUT_S)
                if info is not None:
                    self._remember_working(proxy, time.monotonic() - started, info)
                else:
                    self._record_failure(proxy)
                self._note_current(proxy, info is not None)
            return
        if not pinned:
            self._await_working(index)
            return
        # A short budget here drops a proxy the guest is using just because
        # the check was slow, which opens a gap. Refusals still fail at once.
        # A tunnel that accepts and then says nothing is closed by the stall
        # watch, and the background bench already has the replacement.
        timeout = proxy_config.PROBE_TIMEOUT_S
        started = time.monotonic()
        info = proxy_tunnel.probe_details(proxy, timeout)
        latency = time.monotonic() - started
        ok = info is not None
        with self._lock:
            if self._pin_gen != gen or not self._pinned or not self._endpoints:
                return
            current = self._endpoints[self._state.index % len(self._endpoints)]
            if current != proxy:
                return
            if not ok:
                self._pinned = False
                self._announced = False
                self._pin_gen += 1
                self._stall_until = time.monotonic() + proxy_config.GUEST_DIAL_TIMEOUT_S
                nxt = (index + 1) % len(self._endpoints)
        if ok:
            self._remember_working(proxy, latency, info)
            return
        self._record_failure(proxy)
        self._forget_working(proxy)
        print(f"Proxy stopped forwarding {proxy.render()}.", file=sys.stderr, flush=True)
        # Cut tunnels that are stuck on the proxy we just left, then allow
        # the guest to dial again through the next one.
        self._ctrl_rpc({"op": "drop"})
        self._ctrl_rpc({"op": "allow"})
        self._await_working(nxt)

    def _pool_loop(self) -> None:
        """Keep proving proxies for the whole time the VM is up.

        Up to BACKGROUND_WIDTH checks run at once. Finished slots are filled
        immediately from the saved list and then from the next part of the
        file. The guest dial never joins these threads. A clearly faster
        result takes over as soon as it is measured.
        """
        while not self._stop.is_set():
            if self._stop.wait(proxy_config.PROBE_EVERY_S):
                return
            if self.kill_switch or not self.plan.from_file:
                continue
            try:
                self._pool_launch()
                self._promote_fastest()
            except Exception:
                continue

    def _pool_targets(self, endpoints: tuple, room: int) -> list:
        """Saved proxies, then the next file window, skipping checks in flight."""
        if room < 1:
            return []
        with self._lock:
            if not endpoints or not self._pinned:
                current_key = None
            else:
                current_key = self._proxy_key(endpoints[self._state.index % len(endpoints)])
            saved = [key for _lat, key in self._working if key != current_key]
            by_key = {self._proxy_key(ep): ep for ep in endpoints}
            inflight = set(self._inflight)
            cursor = self._pool_cursor
            now = time.monotonic()
            saved.sort(key=lambda key: proxy_config.selection_key(self._ledger.get(key), now))
        # Recheck the proxies a failure would actually switch to, and spend the
        # rest of the wave looking for new ones. A full saved list must not
        # stop the file walk.
        saved_room = min(proxy_config.SAVED_RECHECK, max(0, room // 2))
        chosen: list = []
        seen: set = set(inflight)
        if current_key is not None:
            seen.add(current_key)
        for key in saved:
            if len(chosen) >= saved_room:
                break
            proxy = by_key.get(key)
            if proxy is None or key in seen:
                continue
            seen.add(key)
            chosen.append(proxy)
        count = len(endpoints)
        if count < 1:
            return chosen
        start = cursor % count
        cold = 0
        for offset in range(count):
            proxy = endpoints[(start + offset) % count]
            key = self._proxy_key(proxy)
            if key in seen:
                continue
            seen.add(key)
            chosen.append(proxy)
            cold += 1
            if len(chosen) >= room:
                break
        self._pool_cursor = (start + max(1, cold)) % count
        return chosen

    def _pool_launch(self) -> None:
        endpoints = tuple(self._refresh_endpoints())
        if len(endpoints) < 2:
            return
        with self._lock:
            room = proxy_config.BACKGROUND_WIDTH - len(self._inflight)
        targets = self._pool_targets(endpoints, room)
        for proxy in targets:
            key = self._proxy_key(proxy)
            with self._lock:
                if key in self._inflight:
                    continue
                self._inflight.add(key)

            def check(proxy: ProxyEndpoint = proxy, key: tuple = key) -> None:
                try:
                    started = time.monotonic()
                    try:
                        info = proxy_tunnel.probe_details(
                            proxy, proxy_config.PROBE_TIMEOUT_S,
                        )
                    except Exception:
                        info = None
                    if info is not None:
                        self._remember_working(proxy, time.monotonic() - started, info)
                        return
                    self._record_failure(proxy)
                    self._forget_working(proxy)
                finally:
                    with self._lock:
                        self._inflight.discard(key)

            threading.Thread(
                target=check, name="qvm-proxy-pool", daemon=True,
            ).start()

    def _promote_fastest(self) -> None:
        """Move the guest onto a saved proxy that measured clearly faster."""
        if self.kill_switch or not self.plan.from_file:
            return
        with self._lock:
            endpoints = tuple(self._endpoints)
            if not endpoints or len(endpoints) < 2:
                return
            pinned = self._pinned
            index = self._state.index % len(endpoints) if pinned else None
            gen = self._pin_gen
            current_latency = None
            if index is not None:
                current_key = self._proxy_key(endpoints[index])
                current_latency = next(
                    (lat for lat, key in self._working if key == current_key), None,
                )
        standby = self._take_standby()
        if standby is None:
            return
        nxt, proxy = standby
        if index is not None and nxt == index:
            return
        key = self._proxy_key(proxy)
        with self._lock:
            if self._pin_gen != gen:
                return
            if pinned and not self._pinned:
                return
            candidate = next((lat for lat, item in self._working if item == key), None)
        with self._lock:
            candidate_record = self._ledger.get(key)
        proven = proxy_config.is_proven(candidate_record, time.monotonic())
        if pinned and not proxy_config.should_promote(
            current_latency, candidate, candidate_proven=proven,
        ):
            return
        self._pin_forwarding(nxt, proxy)
        self._note = f"Faster proxy {proxy.render()}."
        # Leave sockets that are already carrying bytes alone. New dials use
        # the faster proxy. Cutting them here is what dropped a live stream.
        milliseconds = 0 if candidate is None else int(round(candidate * 1000))
        print(
            f"Proxy using {proxy.render()} ({milliseconds} ms).",
            file=sys.stderr, flush=True,
        )
        self._publish_status()

    def _note_current(self, proxy: ProxyEndpoint, ok: bool) -> None:
        """Record one result for `proxy`, but only if it is still current.

        A probe that started before a switch must not mark the new proxy down,
        and a second failure of the same proxy must not switch twice.
        """
        with self._lock:
            endpoints = self._endpoints
            if not endpoints:
                return
            state = self._state
            if state.index >= len(endpoints):
                state = HealthState(0, state.down_since, state.killed)
            current = endpoints[state.index % len(endpoints)]
            if current != proxy:
                return
            new_state, action = proxy_config.note_probe(
                state,
                ok=ok,
                now=time.monotonic(),
                kill_switch=self.kill_switch,
                from_file=self.plan.from_file,
                count=len(endpoints),
            )
            self._state = new_state
        if action == "kill":
            print("Proxy connection lost -- kill switch, guest internet cut.", file=sys.stderr)
            self._ctrl_rpc({"op": "drop"})
        elif action == "restore":
            self._ctrl_rpc({"op": "allow"})
            print("Proxy is answering again -- guest internet restored.", file=sys.stderr)
        elif action == "switch":
            chosen = endpoints[new_state.index % len(endpoints)]
            print(f"Proxy stopped answering -- switching to {chosen.render()}.", file=sys.stderr)

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


def _child_main(ctrl, dial_sock, stall_sock, ready_w: int, go_r: int, fwd_path: str) -> None:
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

    def stalled() -> None:
        try:
            stall_sock.send(b"\n")
        except OSError:
            pass

    _serve_capture(dial_fn=dial, bag=bag, on_stall=stalled)
    _serve_forwards(fwd_path)
    os.write(ready_w, b"U")
    os.close(ready_w)
    _child_control(ctrl, bag, {})


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


def _serve_capture(dial_fn, bag: _Bag, on_stall=None) -> None:
    tcp = _transparent_socket(socket.SOCK_STREAM, _TCP_LISTEN)
    tcp.listen(128)
    udp = _transparent_socket(socket.SOCK_DGRAM, _UDP_LISTEN)
    udp.settimeout(0.5)
    threading.Thread(
        target=_accept_tcp, args=(tcp, dial_fn, bag, on_stall), name="qvm-proxy-tcp", daemon=True,
    ).start()
    threading.Thread(
        target=_recv_udp, args=(udp, dial_fn, bag, on_stall), name="qvm-proxy-udp", daemon=True,
    ).start()


def _accept_tcp(listener: socket.socket, dial_fn, bag: _Bag, on_stall=None) -> None:
    while True:
        try:
            client, _addr = listener.accept()
        except OSError:
            return
        threading.Thread(
            target=_handle_tcp, args=(client, dial_fn, bag, on_stall), daemon=True,
        ).start()


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


def _handle_tcp(client: socket.socket, dial_fn, bag: _Bag, on_stall=None) -> None:
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
    _relay(client, remote, bag, on_stall)


def _recv_udp(listener: socket.socket, dial_fn, bag: _Bag, on_stall=None) -> None:
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
            target=_handle_dns, args=(data, addr, parsed, dial_fn, bag, on_stall), daemon=True,
        ).start()


def _dns_answer(query: bytes, answer: bytes) -> bool:
    """True when `answer` is a DNS message for this query.

    The transaction id is the first two bytes. A proxy that accepted TCP/53
    and then sent an error page must not be handed to the guest as a reply.
    """
    return len(query) >= 2 and len(answer) >= 12 and answer[:2] == query[:2]


def _read_http_body(sock: socket.socket, limit: int = 8192) -> bytes:
    """Response body after the headers. Honors Content-Length when present."""
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    head, _, body = bytes(data).partition(b"\r\n\r\n")
    length = None
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                length = None
    if length is None:
        while len(body) < limit:
            try:
                chunk = sock.recv(1024)
            except OSError:
                break
            if not chunk:
                break
            body += chunk
        return body[:limit]
    while len(body) < length and len(body) < limit:
        chunk = sock.recv(min(1024, length - len(body)))
        if not chunk:
            break
        body += chunk
    return body[:length] if length <= limit else body[:limit]


def _dns_over_https(dial_fn, payload: bytes, bag: _Bag) -> bytes:
    """Resolve `payload` through the proxy on port 443.

    Many proxies carry HTTPS and refuse port 53. The canary already proved
    that a selected proxy can open TLS to 1.1.1.1, so DNS rides that path
    when TCP/53 does not return a real answer.
    """
    request_for = (
        "POST /dns-query HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Length: {length}\r\n"
        "Connection: close\r\n\r\n"
    )
    for host in ("1.1.1.1", "8.8.8.8"):
        remote = None
        tls = None
        try:
            remote = dial_fn(host, 443)
            if bag.drop:
                return b""
            remote.settimeout(proxy_config.GUEST_DIAL_TIMEOUT_S)
            tls = ssl.create_default_context().wrap_socket(remote, server_hostname=host)
            tls.sendall(request_for.format(host=host, length=len(payload)).encode() + payload)
            body = _read_http_body(tls)
            if _dns_answer(payload, body):
                return body
        except OSError:
            pass
        finally:
            if remote is not None:
                bag.discard(remote)
            for end in (tls, remote):
                if end is None:
                    continue
                try:
                    end.close()
                except OSError:
                    pass
    return b""


def _handle_dns(payload: bytes, client_addr, orig: tuple, dial_fn, bag: _Bag, on_stall=None) -> None:
    targets = []
    primary = _public_dns_target(orig[0])
    for candidate in (primary, "1.1.1.1", "8.8.8.8"):
        if candidate not in targets:
            targets.append(candidate)
    remote = None
    body = b""
    for target in targets:
        try:
            remote = dial_fn(target, 53)
            break
        except OSError:
            remote = None
    if remote is not None and not bag.drop:
        try:
            remote.settimeout(proxy_config.GUEST_DIAL_TIMEOUT_S)
            remote.sendall(struct.pack("!H", len(payload)) + payload)
            header = proxy_tunnel.recvall(remote, 2)
            size = struct.unpack("!H", header)[0]
            if size <= 8192:
                body = proxy_tunnel.recvall(remote, size) if size else b""
        except TimeoutError:
            body = b""
            if on_stall is not None:
                on_stall()
        except OSError:
            body = b""
        finally:
            bag.discard(remote)
            remote.close()
    if _dns_answer(payload, body):
        _udp_reply(orig, client_addr, body)
        return
    # Port 53 refused or closed: carry the query inside HTTPS instead.
    # A non-DNS body is still delivered (a test proxy answers with its own
    # marker). A real resolver answer from DoH wins only when 53 gave nothing.
    if not body and not bag.drop:
        body = _dns_over_https(dial_fn, payload, bag)
    if body and not bag.drop:
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


def _child_control(ctrl: socket.socket, bag: _Bag, exited: dict) -> None:
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
            _child_command(ctrl, line, bag, exited)


def _reap(pid: int, exited: dict) -> "int | None":
    """Reap `pid` if it has exited. None means it is still running.

    A zombie still answers kill(pid, 0), which is why the parent cannot use
    that to notice the exit. Only this process, its parent, can waitpid it.
    """
    try:
        got, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return exited.get(pid, 0)
    if got == 0:
        return None
    code = _exit_code(status)
    exited[pid] = code
    return code


def _child_command(ctrl: socket.socket, line: bytes, bag: _Bag, exited: dict) -> None:
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
    if op == "active":
        _ctrl_reply(ctrl, {"ok": True, "n": bag.count()})
        return
    if op == "poll":
        try:
            pid = int(request.get("pid", 0))
        except (TypeError, ValueError):
            _ctrl_reply(ctrl, {"ok": False, "error": "expected pid"})
            return
        code = _reap(pid, exited)
        if code is None:
            _ctrl_reply(ctrl, {"ok": True, "running": True})
            return
        _ctrl_reply(ctrl, {"ok": True, "running": False, "status": code})
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
