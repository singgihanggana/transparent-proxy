#!/usr/bin/env python3
"""Domain-aware transparent TCP router for proxy-transparent.

When DIRECT_DOMAINS is set, entrypoint.sh redirects outbound TCP to this
listener instead of GOST. For each intercepted connection this router:

1. Reads the original destination from SO_ORIGINAL_DST.
2. Peeks at the first client bytes to sniff TLS SNI or HTTP Host.
3. Routes matching DIRECT_DOMAINS directly from this container.
4. CONNECTs everything else through UPSTREAM_PROXY.

All outbound sockets are marked with SO_MARK so the iptables REDIRECT rule does
not loop router egress back into the listener.
"""

from __future__ import annotations

import base64
import os
import select
import socket
import struct
import sys
import threading
import time
from urllib.parse import unquote, urlparse

LISTEN_HOST = os.environ.get("ROUTER_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("REDIRECT_PORT", os.environ.get("ROUTER_PORT", "12345")))
UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY", "http://proxy:3128")
SO_MARK = int(os.environ.get("SO_MARK", "100"), 0)
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "20"))
SNIFF_TIMEOUT = float(os.environ.get("SNIFF_TIMEOUT", "5"))
IDLE_TIMEOUT = float(os.environ.get("IDLE_TIMEOUT", "120"))
LOG_LEVEL = os.environ.get("ROUTER_LOG_LEVEL", "info").lower()
SO_ORIGINAL_DST = 80


def parse_direct_domains(raw: str) -> tuple[str, ...]:
    domains: list[str] = []
    for item in raw.replace("\n", ",").split(","):
        d = item.strip().lower().rstrip(".")
        if not d:
            continue
        if d.startswith("*."):
            d = "." + d[2:]
        domains.append(d)
    return tuple(dict.fromkeys(domains))


DIRECT_DOMAINS = parse_direct_domains(os.environ.get("DIRECT_DOMAINS", ""))
UP = urlparse(UPSTREAM_PROXY)
if UP.scheme not in {"http", ""}:
    raise SystemExit(f"unsupported UPSTREAM_PROXY scheme: {UP.scheme}; use an HTTP proxy URL")
UP_HOST = UP.hostname or "proxy"
UP_PORT = UP.port or 3128
UP_AUTH = ""
if UP.username is not None:
    user = unquote(UP.username)
    pw = unquote(UP.password or "")
    UP_AUTH = base64.b64encode(f"{user}:{pw}".encode()).decode()


def log(level: str, msg: str) -> None:
    levels = {"debug": 10, "info": 20, "warn": 30, "error": 40}
    if levels.get(level, 20) < levels.get(LOG_LEVEL, 20):
        return
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} level={level} {msg}", flush=True)


def mark_socket(sock: socket.socket) -> None:
    if SO_MARK <= 0:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, SO_MARK)
    except PermissionError as exc:
        raise RuntimeError(
            "failed to set SO_MARK; container needs root/CAP_NET_ADMIN or SO_MARK=0"
        ) from exc


def create_marked_connection(host: str, port: int) -> socket.socket:
    last_error: Exception | None = None
    for family, socktype, proto, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        sock = socket.socket(family, socktype, proto)
        try:
            mark_socket(sock)
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect(sockaddr)
            sock.settimeout(None)
            return sock
        except Exception as exc:
            last_error = exc
            sock.close()
    raise OSError(f"could not connect to {host}:{port}: {last_error}")


def is_direct_host(host: str | None) -> bool:
    h = (host or "").split(":", 1)[0].lower().rstrip(".")
    for rule in DIRECT_DOMAINS:
        if rule.startswith("."):
            if h.endswith(rule):
                return True
        elif h == rule:
            return True
    return False


def original_dst(conn: socket.socket) -> tuple[str, int]:
    try:
        data = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        # struct sockaddr_in: family (native endian), port (network endian), addr
        port = struct.unpack_from("!H", data, 2)[0]
        ip = socket.inet_ntoa(data[4:8])
        return ip, port
    except Exception as exc:
        peer = conn.getpeername()
        log("warn", f"client={peer[0]}:{peer[1]} original_dst_error={type(exc).__name__}:{exc}")
        return conn.getsockname()[0], conn.getsockname()[1]


def read_initial(conn: socket.socket) -> bytes:
    conn.settimeout(SNIFF_TIMEOUT)
    try:
        return conn.recv(8192)
    except socket.timeout:
        return b""
    finally:
        conn.settimeout(None)


def sniff_http_host(data: bytes) -> str | None:
    if not data:
        return None
    head = data[:8192].decode("latin1", "ignore")
    if "\r\n" not in head:
        return None
    first = head.split("\r\n", 1)[0]
    if not any(first.startswith(m + " ") for m in ("GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT")):
        return None
    for line in head.split("\r\n")[1:]:
        name, sep, value = line.partition(":")
        if sep and name.lower() == "host":
            return value.strip().split(":", 1)[0].lower().rstrip(".")
    return None


def sniff_tls_sni(data: bytes) -> str | None:
    # Minimal TLS ClientHello parser for SNI extension. Returns None on any parse miss.
    try:
        if len(data) < 5 or data[0] != 0x16:  # handshake record
            return None
        record_len = int.from_bytes(data[3:5], "big")
        if len(data) < 5 + record_len:
            return None
        pos = 5
        if data[pos] != 0x01:  # ClientHello
            return None
        hs_len = int.from_bytes(data[pos + 1 : pos + 4], "big")
        pos += 4
        end = min(len(data), pos + hs_len)
        pos += 2 + 32  # version + random
        if pos >= end:
            return None
        session_len = data[pos]
        pos += 1 + session_len
        if pos + 2 > end:
            return None
        cipher_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= end:
            return None
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > end:
            return None
        ext_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        ext_end = min(end, pos + ext_len)
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_size = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            ext_data = data[pos : pos + ext_size]
            pos += ext_size
            if ext_type != 0x0000 or len(ext_data) < 5:  # server_name
                continue
            names_len = int.from_bytes(ext_data[0:2], "big")
            npos = 2
            names_end = min(len(ext_data), npos + names_len)
            while npos + 3 <= names_end:
                name_type = ext_data[npos]
                name_len = int.from_bytes(ext_data[npos + 1 : npos + 3], "big")
                npos += 3
                name = ext_data[npos : npos + name_len]
                npos += name_len
                if name_type == 0:
                    return name.decode("idna").lower().rstrip(".")
    except Exception:
        return None
    return None


def sniff_hostname(data: bytes) -> str | None:
    return sniff_tls_sni(data) or sniff_http_host(data)


def connect_via_upstream(target: str) -> socket.socket:
    remote = create_marked_connection(UP_HOST, UP_PORT)
    req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if UP_AUTH:
        req += f"Proxy-Authorization: Basic {UP_AUTH}\r\n"
    req += "\r\n"
    remote.sendall(req.encode())
    resp = b""
    remote.settimeout(CONNECT_TIMEOUT)
    try:
        while b"\r\n\r\n" not in resp and len(resp) < 65536:
            chunk = remote.recv(4096)
            if not chunk:
                break
            resp += chunk
    finally:
        remote.settimeout(None)
    if not (resp.startswith(b"HTTP/1.1 200") or resp.startswith(b"HTTP/1.0 200")):
        raise RuntimeError(f"upstream CONNECT failed: {resp[:120]!r}")
    return remote


def pump(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], IDLE_TIMEOUT)
            if not readable:
                return
            for s in readable:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    finally:
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass


def handle(conn: socket.socket, addr) -> None:
    try:
        dst_ip, dst_port = original_dst(conn)
        initial = read_initial(conn)
        sniffed_host = sniff_hostname(initial)
        route_host = sniffed_host or dst_ip
        connect_target = f"{route_host}:{dst_port}" if sniffed_host else f"{dst_ip}:{dst_port}"
        if is_direct_host(sniffed_host):
            route = "DIRECT"
            remote = create_marked_connection(route_host, dst_port)
        else:
            route = "UPSTREAM"
            remote = connect_via_upstream(connect_target)
        if initial:
            remote.sendall(initial)
        log("info", f"client={addr[0]}:{addr[1]} dst={dst_ip}:{dst_port} host={sniffed_host or '-'} route={route}")
        pump(conn, remote)
    except Exception as exc:
        log("error", f"client={addr[0]}:{addr[1]} error={type(exc).__name__}:{exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> int:
    log(
        "info",
        "listening=%s:%s mode=transparent direct_domains=%s default_upstream=%s:%s so_mark=%s"
        % (LISTEN_HOST, LISTEN_PORT, ";".join(DIRECT_DOMAINS) or "<none>", UP_HOST, UP_PORT, SO_MARK),
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(512)
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
    except Exception as exc:
        print(f"fatal: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise
