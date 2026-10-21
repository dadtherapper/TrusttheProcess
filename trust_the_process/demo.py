"""Deterministic scenarios through the production collector contract and rule engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .models import Connection, Process, Snapshot, digest
from .network import ConnectionTracker, classify_address


class DemoCollector:
    source = "SIMULATED • deterministic socket observations"

    def __init__(self, learning_samples: int = 20, start: datetime | None = None) -> None:
        self.tick = 0
        self.transition = learning_samples + 4
        self.start = start or datetime.now(UTC)
        self.tracker = ConnectionTracker()

    def collect(self) -> Snapshot:
        self.tick += 1
        timestamp = (self.start + timedelta(seconds=self.tick * 3)).isoformat(
            timespec="milliseconds"
        )
        changed = self.tick > self.transition
        specs = [
            (100, "explorer.exe", r"C:\Windows\explorer.exe", 80, 1.0, None),
            (
                240,
                "browser.exe",
                r"C:\Program Files\Browser\browser.exe",
                430 + self.tick % 8,
                4.0,
                100,
            ),
            (360, "svchost.exe", r"C:\Windows\System32\svchost.exe", 62, 0.3, None),
            (
                480,
                "renderer.exe",
                r"C:\Program Files\Studio\renderer.exe",
                1350 if changed else 180,
                87.0 if changed else 2.0,
                100,
            ),
            (620, "updater.exe", r"C:\Users\Demo\AppData\Local\Temp\updater.exe", 95, 3.0, 100),
        ]
        processes = [
            Process(
                pid=pid,
                started=self.start.timestamp()
                - {100: 3600, 240: 900, 360: 7200, 480: 1800, 620: 300}[pid],
                name=name,
                ppid=parent,
                exe=path,
                command=f'"{path}" --simulated',
                username="DEMO\\Analyst",
                cpu=cpu,
                rss=memory * 1024**2,
                memory_percent=round(memory / 163.84, 2),
                status="running",
                sha256=digest(path),
                file_identity="simulated-file-v1",
            )
            for pid, name, path, memory, cpu, parent in specs
        ]
        by_pid = {p.pid: p for p in processes}
        for p in processes:
            if p.ppid in by_pid:
                p.parent_identity = by_pid[p.ppid].identity
                p.parent_key = by_pid[p.ppid].key
        connections = []
        # These are real public resolver addresses used as synthetic endpoints only.
        # No socket is opened and no reputation claim is made about these addresses.
        destinations = [(240, "1.1.1.1", 443), (240, "8.8.8.8", 443)]
        if changed:
            destinations += [
                (620, ip, 443)
                for ip in ("9.9.9.9", "8.8.4.4", "1.0.0.1", "208.67.222.222", "208.67.220.220")
            ]
        for i, (pid, remote, port) in enumerate(destinations):
            p = by_pid[pid]
            # Remote sockets rotate to demonstrate newly observed connections after the transition.
            local_port = 50000 + i + ((self.tick * 10) % 14000 if pid == 620 else 0)
            connections.append(
                Connection(
                    "TCP4",
                    "192.168.10.20",
                    local_port,
                    remote,
                    port,
                    "ESTABLISHED",
                    pid,
                    p.key,
                    p.name,
                    classify_address(remote),
                    timestamp,
                    timestamp,
                    source=self.source,
                )
            )
        self.tracker.update(connections, processes)
        return Snapshot(
            timestamp,
            processes,
            connections,
            self.source,
            simulated=True,
            system_cpu=26 if changed else 8,
            system_memory=41 if changed else 30,
            limitations=["All process, network, and reputation data is SIMULATED."],
            interval_seconds=3.0 if self.tick > 1 else None,
        )

    def close(self) -> None:
        pass
