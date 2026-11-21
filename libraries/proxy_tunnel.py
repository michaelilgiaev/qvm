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

from proxy_config import ProxyEndpoint


class ProxyTunnelError(ConnectionError):
    """The proxy answered, but refused the tunnel."""


def recvall(sock: socket.socket, count: int) -> bytes:
    """Read exactly `count` bytes, or raise if the peer closes early."""
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def _socks5_auth(sock: socket.socket, username: str, password: str) -> None:
    if username:
        sock.sendall(b"\x05\x02\x00\x02")
    else:
        sock.sendall(b"\x05\x01\x00")
    version, method = recvall(sock, 2)
    if version != 5:
        raise ProxyTunnelError(f"proxy is not SOCKS5 (version {version})")
    if method == 0xFF:
        raise ProxyTunnelError("proxy rejected every auth method")
    if method == 0x02:
        user = username.encode()
        secret = password.encode()
        if len(user) > 255 or len(secret) > 255:
            raise ProxyTunnelError("SOCKS5 username or password is too long")
        sock.sendall(bytes((0x01, len(user))) + user + bytes((len(secret),)) + secret)
        auth_ver, status = recvall(sock, 2)
        if auth_ver != 0x01 or status != 0x00:
            raise ProxyTunnelError("SOCKS5 username/password rejected")
    elif method != 0x00:
        raise ProxyTunnelError(f"SOCKS5 auth method {method} is not supported")


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
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("proxy closed during CONNECT")
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
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
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
    """True when a TCP handshake to the proxy itself succeeds.

    This is the 'proxy connection' the kill switch and the 10 second failover
    watch. It does not open a tunnel, so a probe cannot be confused with guest
    traffic.
    """
    try:
        sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    except OSError:
        return False
    sock.close()
    return True
