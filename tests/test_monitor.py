from __future__ import annotations

import threading
import time

from trust_the_process.config import Config
from trust_the_process.demo import DemoCollector
from trust_the_process.engine import Monitor
from trust_the_process.intelligence import Reputation
from trust_the_process.models import utc_now


def test_slow_manual_lookup_does_not_block_collection_or_pause(tmp_path, monkeypatch):
    from trust_the_process import collector, engine

    started, release = threading.Event(), threading.Event()
    synthetic = DemoCollector(5)
    monkeypatch.setattr(collector, "HostCollector", lambda: synthetic)

    class SlowProvider:
        name, interval = "VirusTotal", 0

        def lookup(self, indicator, kind):
            started.set()
            assert release.wait(5)
            return Reputation(self.name, indicator, "not_found", False, "No report", utc_now())

    constructed = []

    def provider(name):
        constructed.append(name)
        return SlowProvider()

    monkeypatch.setattr(engine, "configured_provider", provider)
    monitor = Monitor(Config(interval=1, min_samples=5, virustotal_enabled=True), tmp_path)
    monitor.start()
    try:
        first = monitor.states.get(timeout=5)
        assert first.snapshot.simulated and not constructed  # No automatic enrichment.
        monitor.submit("lookup", provider="VirusTotal", indicator="8.8.8.8", kind="ip")
        assert started.wait(3)
        later = monitor.states.get(timeout=3)
        assert later.snapshot.timestamp != first.snapshot.timestamp
        monitor.submit("pause")
        deadline = time.monotonic() + 2
        while not monitor.paused.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert monitor.paused.is_set() and not release.is_set()
        assert constructed == ["VirusTotal"]
    finally:
        release.set()
        monitor.shutdown()
        monitor.thread.join(timeout=5)
    assert not monitor.thread.is_alive()


def test_resume_takes_a_sample_without_waiting_for_the_old_interval(tmp_path, monkeypatch):
    from trust_the_process import collector

    synthetic = DemoCollector(5)
    monkeypatch.setattr(collector, "HostCollector", lambda: synthetic)
    monitor = Monitor(Config(interval=300, min_samples=5), tmp_path)
    monitor.start()
    try:
        first = monitor.states.get(timeout=5)
        monitor.submit("pause")
        deadline = time.monotonic() + 2
        while not monitor.paused.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert monitor.paused.is_set()
        monitor.submit("resume")
        later = monitor.states.get(timeout=3)
        assert first.snapshot.timestamp != later.snapshot.timestamp
    finally:
        monitor.shutdown()
        monitor.thread.join(timeout=5)
    assert not monitor.thread.is_alive()
