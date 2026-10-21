"""Connection observations, never packets or per-process byte measurements."""

from __future__ import annotations

import ipaddress
import socket
from typing import Protocol

import psutil

from .models import Connection, Process


def classify_address(address: str | None) -> str:
    if not address:
        return "none"
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_loopback:
            return "loopback"
        if ip.is_link_local:
            return "link-local"
        if ip.is_multicast:
            return "multicast"
        if ip.is_unspecified:
            return "unspecified"
        if ip.is_reserved:
            return "reserved"
        if ip.is_global:
            return "public"
        if ip.is_private:
            return "private"
        return "special"
    except ValueError:
        return "invalid"


class NetworkAdapter(Protocol):
    source: str
    capabilities: tuple[str, ...]

    def collect(self, processes: dict[int, Process], timestamp: str) -> list[Connection]: ...


class PsutilNetwork:
    source = "psutil socket snapshot"
    capabilities = ("TCP/UDP endpoints", "best-effort PID ownership", "no packets or process bytes")

    def collect(self, processes: dict[int, Process], timestamp: str) -> list[Connection]:
        rows = psutil.net_connections(kind="inet")
        # Verify the lifetime AFTER reading sockets; never attach a reused PID to an older process.
        verified: dict[int, Process] = {}
        observed_pids = {r.pid for r in rows if r.pid is not None}
        for pid in observed_pids:
            p = processes.get(pid)
            if p is None or p.started is None:
                continue
            try:
                if psutil.Process(pid).create_time() == p.started:
                    verified[pid] = p
            except (psutil.Error, OSError):
                pass
        for pid, process in processes.items():
            # A failed ownership check is a visibility gap, not an observed zero.
            if process.started is None or (pid in observed_pids and pid not in verified):
                process.limitations.append("network ownership unavailable")
        result = []
        for row in rows:
            if not row.laddr:
                continue
            owner = verified.get(row.pid)
            remote = row.raddr
            result.append(
                Connection(
                    protocol=("TCP" if row.type == socket.SOCK_STREAM else "UDP")
                    + ("6" if row.family == socket.AF_INET6 else "4"),
                    local_ip=str(row.laddr[0]),
                    local_port=int(row.laddr[1]),
                    remote_ip=str(remote[0]) if remote else None,
                    remote_port=int(remote[1]) if remote else None,
                    status=row.status or "NONE",
                    pid=row.pid,
                    process_key=owner.key if owner else None,
                    process_name=owner.name if owner else None,
                    address_class=classify_address(str(remote[0]) if remote else None),
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
        return result


class ConnectionTracker:
    def __init__(self) -> None:
        self.previous: dict[str, Connection] = {}
        self.initialized = False

    def update(self, connections: list[Connection], processes: list[Process]) -> None:
        # SO_REUSEPORT and platform APIs can expose identical tuples more than once.
        connections[:] = list({connection.key: connection for connection in connections}.values())
        by_process: dict[str, list[Connection]] = {}
        current = {}
        for connection in connections:
            previous = self.previous.get(connection.key)
            connection.new = self.initialized and previous is None
            if previous:
                connection.first_seen = previous.first_seen
            current[connection.key] = connection
            if connection.process_key:
                by_process.setdefault(connection.process_key, []).append(connection)
        for process in processes:
            if "network ownership unavailable" in process.limitations:
                process.connections = process.new_connections = None
                process.destinations = []
                process.ports = []
                continue
            rows = by_process.get(process.key, [])
            process.connections = len(rows)
            process.destinations = sorted(
                {c.remote_ip for c in rows if c.address_class == "public" and c.remote_ip}
            )
            process.ports = sorted({c.remote_port for c in rows if c.remote_port is not None})
            process.new_connections = sum(c.new and c.remote_ip is not None for c in rows)
        self.previous = current
        self.initialized = True
