"""Validated, non-secret preferences. User data lives outside the source checkout."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .files import atomic_text


def data_directory(demo: bool = False) -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
    return base / "TrustTheProcess" / ("demo" if demo else "live")


@dataclass
class Config:
    interval: float = 3.0
    retention_days: int = 14
    min_samples: int = 20
    sustained_samples: int = 3
    memory_ratio: float = 2.5
    memory_delta_mb: float = 100.0
    cpu_delta: float = 40.0
    connection_burst: int = 5
    baseline_window: int = 120
    abuseipdb_enabled: bool = False
    virustotal_enabled: bool = False
    reputation_ttl_hours: int = 24
    rule_weights: dict[str, int] = field(default_factory=dict)

    def validate(self) -> None:
        bounds = {
            "interval": (1, 300),
            "retention_days": (1, 90),
            "min_samples": (5, 500),
            "sustained_samples": (2, 30),
            "memory_ratio": (1.5, 20),
            "memory_delta_mb": (10, 100000),
            "cpu_delta": (10, 10000),
            "connection_burst": (2, 1000),
            "baseline_window": (20, 1000),
            "reputation_ttl_hours": (1, 168),
        }
        for key, (low, high) in bounds.items():
            value = getattr(self, key)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not low <= value <= high
            ):
                raise ValueError(f"{key} must be between {low} and {high}")
            if key not in {"interval", "memory_ratio", "memory_delta_mb", "cpu_delta"}:
                if not isinstance(value, int):
                    raise ValueError(f"{key} must be a whole number")
        if self.baseline_window < self.min_samples:
            raise ValueError("baseline_window must be at least min_samples")
        for key in ("abuseipdb_enabled", "virustotal_enabled"):
            if not isinstance(getattr(self, key), bool):
                raise ValueError(f"{key} must be true or false")
        # Import on validation rather than at module load: rules use Config as their interface.
        from .detection import RULES

        if not isinstance(self.rule_weights, dict) or set(self.rule_weights) - RULES.keys():
            raise ValueError("rule_weights must map known rule IDs to integer weights")
        for weight in self.rule_weights.values():
            if isinstance(weight, bool) or not isinstance(weight, int) or not 0 <= weight <= 100:
                raise ValueError("Rule evidence weights must be whole numbers from 0 to 100")

    @classmethod
    def load(cls, path: Path) -> Config:
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Configuration must be a JSON object")
        result = cls(**raw)
        result.validate()
        return result

    def save(self, path: Path) -> None:
        self.validate()
        path.parent.mkdir(parents=True, exist_ok=True)
        with atomic_text(path) as stream:
            json.dump(asdict(self), stream, indent=2)


def configure_logging(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        folder / "application.log", maxBytes=500_000, backupCount=2, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
