"""Minimal Zabbix sender (trapper protocol) - no zabbix_sender binary needed.

Packet: b"ZBXD\\x01" + <4 byte LE data length> + <4 byte reserved> + JSON
"""
from __future__ import annotations

import json
import socket
import struct

HEADER = b"ZBXD\x01"


def build_packet(host: str, items: dict[str, object]) -> bytes:
    payload = json.dumps(
        {
            "request": "sender data",
            "data": [{"host": host, "key": k, "value": str(v)} for k, v in items.items()],
        },
        ensure_ascii=False,
    ).encode("utf-8")
    return HEADER + struct.pack("<II", len(payload), 0) + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def send(server: str, port: int, host: str, items: dict[str, object], timeout: float = 5.0) -> dict:
    """Send items to a Zabbix server/proxy. Returns the parsed server response."""
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall(build_packet(host, items))
        header = _recv_exact(sock, 13)
        if len(header) < 13 or not header.startswith(b"ZBXD"):
            raise ConnectionError("Invalid response header from Zabbix")
        length = struct.unpack("<I", header[5:9])[0]
        body = _recv_exact(sock, length)
    return json.loads(body.decode("utf-8"))
