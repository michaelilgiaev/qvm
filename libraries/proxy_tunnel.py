"""proxy_tunnel.py - open one TCP stream through a SOCKS4, SOCKS5, or HTTP proxy.

The guest never speaks this protocol. proxy_runtime captures the guest's own
TCP (and DNS) and asks this module to dial the destination through whatever
proxy is current. Handshake bytes are consumed here so the relay that follows
sees only the destination's bytes.
"""

from __future__ import annotations

import base64
import socket
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
    proxy: ProxyEndpoint, host: str, port: int, timeout: float = 20.0
) -> socket.socket:
    """Connect to `proxy` and return a socket whose stream is host:port.

    The caller owns the socket. On any failure the socket is closed and the
    error propagates -- a half-open proxy socket must not be relayed.
    """
    # The connect budget is the probe window, not `timeout`. `timeout` covers
    # the destination the proxy dials after it has answered. A connect that
    # finishes inside the window keeps this proxy; how long it took does not.
    try:
        sock = socket.create_connection(
            (proxy.host, proxy.port), timeout=proxy_config.PROBE_TIMEOUT_S,
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
