"""Bounded machine-local learning. Compare before learning the current observation."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from .config import Config
from .models import Process, utc_now


@dataclass
class Distribution:
    count: int
    median: float | None
    mad: float | None
    p95: float | None


def distribution(values: list[float]) -> Distribution:
    if not values:
        return Distribution(0, None, None, None)
    ordered = sorted(values)
    median = statistics.median(ordered)
    return Distribution(
        len(values),
        median,
        statistics.median(abs(v - median) for v in ordered),
        ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))],
    )


class Baselines:
    def __init__(self, config: Config, state: dict[str, dict] | None = None) -> None:
        self.config = config
        self.state = state or {}

    def get(self, process: Process) -> dict:
        return self.state.get(process.identity, {})

    def metric(self, process: Process, name: str) -> Distribution:
        return distribution(self.get(process).get(name, []))

    def ready(self, process: Process) -> bool:
        data = self.get(process)
        return data.get("samples", 0) >= self.config.min_samples and any(
            len(data.get(metric, [])) >= self.config.min_samples
            for metric in ("cpu", "rss", "connections")
        )

    def learn(
        self,
        processes: list[Process],
        frozen: set[tuple[str, str]] | None = None,
        timestamp: str | None = None,
    ) -> None:
        # One sample per executable identity per poll; many browser children do not accelerate learning.
        grouped: dict[str, list[Process]] = {}
        for p in processes:
            if p.identity:
                grouped.setdefault(p.identity, []).append(p)
        for identity, group in grouped.items():
            data = self.state.setdefault(
                identity,
                {
                    "samples": 0,
                    "cpu": [],
                    "rss": [],
                    "connections": [],
                    "destinations": [],
                    "ports": [],
                    "parents": [],
                    "path": group[0].exe,
                    "sha256": group[0].sha256,
                },
            )
            data["samples"] += 1
            data["last_seen"] = timestamp or utc_now()
            data["sha256"] = group[0].sha256 or data.get("sha256")
            for metric in ("cpu", "rss", "connections"):
                values = [getattr(p, metric) for p in group if getattr(p, metric) is not None]
                if values and (identity, metric) not in (frozen or set()):
                    data[metric] = (data[metric] + [max(values)])[-self.config.baseline_window :]
            for feature, values in (
                ("destinations", [d for p in group for d in p.destinations]),
                ("ports", [v for p in group for v in p.ports]),
                ("parents", [p.parent_identity for p in group if p.parent_identity]),
            ):
                # Recency-ordered distinct features, bounded to avoid indefinite identifier growth.
                # Move re-observed entries to the end; otherwise frequently used destinations
                # are incorrectly evicted before stale ones.
                observed = list(dict.fromkeys(values))
                data[feature] = [v for v in data[feature] if v not in observed] + observed
                data[feature] = data[feature][-512:]
