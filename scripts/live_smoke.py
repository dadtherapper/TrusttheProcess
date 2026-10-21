"""Finite real-host validation; stores telemetry only in a private temporary directory."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from trust_the_process.collector import HostCollector
from trust_the_process.config import Config
from trust_the_process.engine import Engine
from trust_the_process.storage import Store


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ttp-live-check-") as directory:
        folder = Path(directory)
        engine = Engine(
            Config(interval=1, min_samples=5), Store(folder / "history.db"), HostCollector()
        )
        durations = []
        try:
            for index in range(6):
                started = time.monotonic()
                state = engine.cycle(persist=True)
                durations.append(time.monotonic() - started)
                if index < 5:
                    time.sleep(1)
            own = next(p for p in state.snapshot.processes if p.pid == os.getpid())
            assert own.exe and own.started is not None and own.cpu is not None and own.rss
            assert own.sha256 and state.baselines[own.key]["ready"]
            assert state.snapshot.network_available
            attributed = sum(c.process_key is not None for c in state.snapshot.connections)
            assert attributed > 0
            path = folder / "investigation.json"
            engine.export(path, "investigation", False, own.key)
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert not payload["simulated"] and payload["current_process"]["pid"] == os.getpid()
            assert len(payload["observations"]) == 6 and payload["current_process"]["sha256"]
            print(
                json.dumps(
                    {
                        "cycles": 6,
                        "processes": len(state.snapshot.processes),
                        "connections": len(state.snapshot.connections),
                        "attributed_connections": attributed,
                        "processes_with_cpu": sum(
                            p.cpu is not None for p in state.snapshot.processes
                        ),
                        "processes_with_hash": sum(
                            bool(p.sha256) for p in state.snapshot.processes
                        ),
                        "own_baseline_samples": state.baselines[own.key]["samples"],
                        "max_cycle_seconds": round(max(durations), 3),
                        "last_cycle_seconds": round(durations[-1], 3),
                        "investigation_export": "passed",
                    }
                )
            )
        finally:
            engine.close()


if __name__ == "__main__":
    main()
