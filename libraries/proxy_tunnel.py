"""proxy_tunnel.py - open one TCP stream through a SOCKS4, SOCKS5, or HTTP proxy.

The guest never speaks this protocol. proxy_runtime captures the guest's own
TCP (and DNS) and asks this module to dial the destination through whatever
proxy is current. Handshake bytes are consumed here so the relay that follows
sees only the destination's bytes.
"""

from __future__ import annotations

import base64
import socket
import ssl
import struct

import proxy_config
from proxy_config import ProxyEndpoint


class ProxyTunnelError(ConnectionError):
    """The proxy answered, but refused the tunnel."""


class ProxyDown(ProxyTunnelError):
    """The proxy itself is gone or is not speaking its protocol.

    A slow answer is not this, and neither is a normal rejection of the
    destination (SOCKS reply code, HTTP status). Those keep the current proxy.
    """


def recvall(sock: socket.socket, count: int) -> bytes:
    """Read exactly `count` bytes, or raise if the peer closes early.

    A timeout is left as TimeoutError: the proxy accepted and is merely slow,
    or it is still dialing the destination. A reset or an early close is
    ProxyDown, because the proxy itself dropped the session.
    """
    buf = bytearray()
    while len(buf) < count:
        try:
            chunk = sock.recv(count - len(buf))
        except TimeoutError:
            raise
        except OSError as exc:
            raise ProxyDown(f"proxy closed the connection: {exc}") from exc
        if not chunk:
            raise ProxyDown("proxy closed the connection")
        buf += chunk
    return bytes(buf)


def _socks5_auth(sock: socket.socket, username: str, password: str) -> None:
    """Greeting and auth. This is the proxy itself, not the destination.

    The budget is the probe window. A proxy that accepts TCP and then never
    speaks is down. One that answers inside the window is up, however slow.
    """
    previous = sock.gettimeout()
    # A guest dial already put a short budget on the socket. Do not stretch it
    # back to the canary window, or a dead proxy blocks the guest for seconds.
    if previous is None:
        sock.settimeout(proxy_config.PROBE_TIMEOUT_S)
    try:
        if username:
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")
        version, method = recvall(sock, 2)
        if version != 5:
            raise ProxyDown(f"proxy is not SOCKS5 (version {version})")
        if method == 0xFF:
            raise ProxyDown("proxy rejected every auth method")
        if method == 0x02:
            user = username.encode()
            secret = password.encode()
            if len(user) > 255 or len(secret) > 255:
                raise ProxyTunnelError("SOCKS5 username or password is too long")
            sock.sendall(bytes((0x01, len(user))) + user + bytes((len(secret),)) + secret)
            auth_ver, status = recvall(sock, 2)
            if auth_ver != 0x01 or status != 0x00:
                raise ProxyDown("SOCKS5 username/password rejected")
        elif method != 0x00:
            raise ProxyDown(f"SOCKS5 auth method {method} is not supported")
    except TimeoutError as exc:
        raise ProxyDown("SOCKS5 proxy did not answer") from exc
    finally:
        sock.settimeout(previous)


def _socks5_request(host: str, port: int) -> bytes:
    try:
        packed = socket.inet_aton(host)
    except OSError:
        name = host.encode()
        if len(name) > 255:
            raise ProxyTunnelError("destination host name is too long")
        return b"\x05\x01\x00\x03" + bytes((len(name),)) + name + struct.pack("!H", port)
    return b"\x05\x01\x00\x01" + packed + struct.pack("!H", port)


def _socks5_reply(sock: socket.socket) -> None:
    version, reply, _reserved, atyp = recvall(sock, 4)
    if atyp == 1:
        recvall(sock, 6)
    elif atyp == 4:
        recvall(sock, 18)
    elif atyp == 3:
        length = recvall(sock, 1)[0]
        recvall(sock, length + 2)
    else:
        raise ProxyTunnelError(f"SOCKS5 reply address type {atyp} is unknown")
    if version != 5 or reply != 0:
        raise ProxyTunnelError(f"SOCKS5 connect failed (reply {reply})")


def socks4_connect(
    sock: socket.socket, host: str, port: int, username: str = ""
) -> None:
    """SOCKS4 CONNECT. The userid is `username` (SOCKS4 has no password).

    The request carries a 4-byte IPv4 address, which is what a captured guest
    packet always is. A name or an IPv6 destination cannot be encoded.
    """
    try:
        packed = socket.inet_aton(host)
    except OSError:
        raise ProxyTunnelError("SOCKS4 can only connect to an IPv4 address") from None
    user = username.encode()
    if b"\x00" in user or len(user) > 255:
        raise ProxyTunnelError("SOCKS4 userid is too long or contains a NUL")
    sock.sendall(b"\x04\x01" + struct.pack("!H", port) + packed + user + b"\x00")
    _version, reply, _port, _ip = struct.unpack("!BBH4s", recvall(sock, 8))
    if reply != 90:
        raise ProxyTunnelError(f"SOCKS4 connect failed (reply {reply})")


def socks5_connect(
    sock: socket.socket, host: str, port: int, username: str = "", password: str = ""
) -> None:
    """Turn an already-connected proxy socket into a tunnel to host:port."""
    _socks5_auth(sock, username, password)
    sock.sendall(_socks5_request(host, port))
    _socks5_reply(sock)


def http_connect(
    sock: socket.socket, host: str, port: int, username: str = "", password: str = ""
) -> None:
    """HTTP CONNECT. Reads only the response headers, one byte at a time, so the
    tunnel's first payload byte is never swallowed."""
    shown = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [
        f"CONNECT {shown} HTTP/1.1",
        f"Host: {shown}",
    ]
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    data = bytearray()
    while b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(1)
        except TimeoutError:
            raise
        except OSError as exc:
            raise ProxyDown(f"HTTP proxy closed during CONNECT: {exc}") from exc
        if not chunk:
            raise ProxyDown("HTTP proxy closed during CONNECT")
        data += chunk
        if len(data) > 65536:
            raise ProxyTunnelError("proxy CONNECT response is too large")
    status = bytes(data).split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
    parts = status.split()
    if len(parts) < 2 or parts[1] != "200":
        raise ProxyTunnelError(f"HTTP CONNECT failed: {status}")


def open_tunnel(
    proxy: ProxyEndpoint, host: str, port: int, timeout: float = 20.0,
    connect_timeout: "float | None" = None,
) -> socket.socket:
    """Connect to `proxy` and return a socket whose stream is host:port.

    The caller owns the socket. On any failure the socket is closed and the
    error propagates -- a half-open proxy socket must not be relayed.
    """
    # The connect budget is the probe window, not `timeout`, unless the caller
    # is a guest dial that has already decided this proxy is out of time.
    # `timeout` covers the destination the proxy dials after it has answered.
    connect_budget = (
        proxy_config.PROBE_TIMEOUT_S if connect_timeout is None else connect_timeout
    )
    try:
        sock = socket.create_connection(
            (proxy.host, proxy.port), timeout=connect_budget,
        )
    except OSError as exc:
        raise ProxyDown(f"proxy is not answering: {exc}") from exc
    try:
        sock.settimeout(timeout)
        if proxy.scheme == "socks4":
            socks4_connect(sock, host, port, proxy.username)
        elif proxy.scheme == "socks5":
            socks5_connect(sock, host, port, proxy.username, proxy.password)
        else:
            http_connect(sock, host, port, proxy.username, proxy.password)
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def _proves_forwarding(payload: bytes) -> bool:
    """True when `payload` is a real reply from the canary, not an empty read.

    Cloudflare's trace page contains ``fl=``. A redirect from the same host
    names ``cloudflare`` in the headers. The caller has already checked the
    certificate, so this body is from that host.
    """
    if b"fl=" in payload:
        return True
    return b"cloudflare" in payload.lower()


def _trace_fields(payload: bytes) -> dict:
    """`loc`, `ip`, and `colo` from a Cloudflare trace body. Empty when absent."""
    _head, _sep, body = payload.partition(b"\r\n\r\n")
    source = body if _sep else payload
    fields: dict[str, str] = {}
    for line in source.splitlines():
        if b"=" not in line or line.lower().startswith(b"http"):
            continue
        key, _, value = line.partition(b"=")
        fields[key.decode("latin1", "replace").strip()] = value.decode(
            "latin1", "replace"
        ).strip()
    return fields


def _read_http_proof(sock: socket.socket, timeout: float) -> "dict | None":
    """Trace fields when the reply is really from the canary, else None."""
    host = proxy_config.CANARY_HOST
    request = (
        f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: qvm\r\nConnection: close\r\n\r\n"
    ).encode()
    sock.settimeout(timeout)
    sock.sendall(request)
    data = bytearray()
    while len(data) < 8192:
        try:
            chunk = sock.recv(1024)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
        if _proves_forwarding(bytes(data)) and b"loc=" in data and b"ip=" in data:
            break
    if not _proves_forwarding(bytes(data)):
        return None
    return _trace_fields(bytes(data))


def _tls_context() -> ssl.SSLContext:
    """Trust store for the canary. A test can add its own CA.

    The system store is what a guest uses for HTTPS. CANARY_CAFILE is extra,
    so a test certificate verifies and a substituted one still does not.
    """
    ctx = ssl.create_default_context()
    cafile = proxy_config.CANARY_CAFILE
    if cafile:
        ctx.load_verify_locations(cafile)
    return ctx


def probe_details(proxy: ProxyEndpoint, timeout: float) -> "dict | None":
    """Trace fields when `proxy` carries two verified HTTPS replies at once.

    None unless both tunnels finish TLS to the canary and the certificate
    checks out. A proxy that substitutes its own certificate is None, the
    same as one that accepts TCP and then stays silent. `loc`, `ip`, and
    `colo` come from the trace body when the canary sends them.
    """
    host = proxy_config.CANARY_HOST
    port = int(proxy_config.CANARY_PORT)
    opened: list[socket.socket] = []
    secure: list[ssl.SSLSocket] = []
    try:
        for _ in range(2):
            opened.append(open_tunnel(proxy, host, port, timeout=timeout))
        ctx = _tls_context()
        for raw in opened:
            # open_tunnel clears the timeout. Set it again before the
            # handshake, or a proxy that accepts and then says nothing hangs.
            raw.settimeout(timeout)
            secure.append(ctx.wrap_socket(raw, server_hostname=host))
        first: dict | None = None
        for sock in secure:
            fields = _read_http_proof(sock, timeout)
            if not fields:
                return None
            if first is None:
                first = fields
        return first or {}
    except OSError:
        return None
    finally:
        for sock in secure:
            try:
                sock.close()
            except OSError:
                pass
        for sock in opened:
            try:
                sock.close()
            except OSError:
                pass


def proxy_forwards(proxy: ProxyEndpoint, timeout: float) -> bool:
    """True only when `proxy` carries two verified HTTPS replies at once."""
    return probe_details(proxy, timeout) is not None


def proxy_reachable(proxy: ProxyEndpoint, timeout: float) -> bool:
    """True when a TCP handshake to the proxy itself finishes.

    Latency is not a failure: any handshake that completes inside `timeout`
    is success, however long it took. Connection refused fails immediately,
    which is a dead proxy. This does not open a tunnel, so a probe cannot be
    confused with guest traffic, and it does not rank proxies by speed.
    """
    try:
        sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    except OSError:
        return False
    sock.close()
    return True
