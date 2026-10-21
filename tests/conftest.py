from __future__ import annotations

import pytest

from trust_the_process.config import Config
from trust_the_process.models import Process, Snapshot


@pytest.fixture
def config():
    return Config(min_samples=5, sustained_samples=2, baseline_window=20)


@pytest.fixture
def process():
    return Process(
        123,
        1000.0,
        "app.exe",
        ppid=1,
        exe=r"C:\Program Files\App\app.exe",
        cpu=2.0,
        rss=100 * 1024**2,
        file_identity="100:123:1",
        connections=0,
        new_connections=0,
        parent_identity="known-parent",
    )


@pytest.fixture
def snapshot(process):
    return Snapshot("2026-10-19T18:00:00.000+00:00", [process], [], "test", simulated=True)
