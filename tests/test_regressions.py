from __future__ import annotations

import copy
import json
import sqlite3
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from trust_the_process.baseline import Baselines, distribution
from trust_the_process.config import Config
from trust_the_process.detection import Detector
from trust_the_process.engine import Engine, Monitor
from trust_the_process.intelligence import (
    AbuseIPDB,
    Intelligence,
    Reputation,
    VirusTotal,
    retry_delay,
)
from trust_the_process.models import Connection, Finding, utc_now
from trust_the_process.network import ConnectionTracker
from trust_the_process.reporting import export_findings_csv, export_json, report
from trust_the_process.storage import Store


class FixedCollector:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def collect(self):
        return copy.deepcopy(self.snapshot)

    def close(self):
        pass


def make_finding(process, **kwargs):
    return Finding(
        "EXEC-TEMP",
        "Example",
        utc_now(),
        process.key,
        process.identity,
        process.name,
        "Low",
        10,
        "Observed",
        None,
        {},
        "Context",
        "Inspect",
        "test",
        **kwargs,
    )


def test_inactive_baseline_does_not_get_a_new_last_seen(config, process, snapshot):
    store = Store(":memory:")
    baselines = Baselines(config)
    old = (datetime.now(UTC) - timedelta(days=20)).isoformat()
    baselines.learn([process], timestamp=old)
    store.save_snapshot(snapshot, baselines.state)
    assert store.db.execute("SELECT updated FROM baselines").fetchone()[0] == old
    store.prune(14)
    assert store.load_baselines() == {}
    store.close()


def test_expired_baseline_is_removed_before_detection(config, process, snapshot):
    store = Store(":memory:")
    baseline = Baselines(config)
    old = (datetime.now(UTC) - timedelta(days=20)).isoformat()
    for _ in range(config.min_samples):
        baseline.learn([process], timestamp=old)
    store.save_snapshot(snapshot, baseline.state)
    engine = Engine(config, store, FixedCollector(snapshot))
    try:
        assert not engine.baselines.state
    finally:
        engine.close()


def test_pruning_keeps_baselines_learned_since_history_flush(config, snapshot):
    collector = FixedCollector(snapshot)
    engine = Engine(config, Store(":memory:"), collector)
    try:
        engine.cycle()
        previous = snapshot.processes[0].identity
        snapshot.processes[0].file_identity = "new-file"
        new = snapshot.processes[0].identity
        engine.last_persist = time.monotonic()
        engine.last_prune = time.monotonic() - 61
        engine.cycle()
        assert previous in engine.baselines.state and new in engine.baselines.state
        assert new in engine.store.load_baselines()
    finally:
        engine.close()


def test_scores_use_retained_evidence_outside_the_visible_page(config, process, snapshot):
    engine = Engine(config, Store(":memory:"), FixedCollector(snapshot))
    try:
        early = make_finding(process)
        early.timestamp = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        engine.store.save_finding(early)
        for index in range(1002):
            engine.store.save_finding(replace(make_finding(process), process_key=f"other:{index}"))
        state = engine.cycle()
        assert early.id not in {f["id"] for f in engine.store.findings(limit=1000)}
        assert early.id in {f["id"] for f in state.findings}
        assert state.risks[process.key] == 10
        assert state.process_findings[process.key][0]["id"] == early.id
    finally:
        engine.close()


def test_file_change_resets_a_resource_streak(config, process, snapshot):
    baselines = Baselines(config)
    for _ in range(config.min_samples):
        baselines.learn([process])
    detector = Detector(config, baselines)
    process.rss *= 20
    assert "RES-MEM" not in {f.rule_id for f in detector.evaluate(snapshot)}
    process.file_identity = "changed"
    for _ in range(config.min_samples):
        process.rss = 100 * 1024**2
        detector.evaluate(snapshot)
        baselines.learn([process])
    process.rss *= 20
    assert "RES-MEM" not in {f.rule_id for f in detector.evaluate(snapshot)}
    assert "RES-MEM" in {f.rule_id for f in detector.evaluate(snapshot)}


def test_unknown_metrics_do_not_become_an_established_zero_baseline(config, process):
    process.cpu = process.rss = process.connections = None
    baselines = Baselines(config)
    for _ in range(config.min_samples + 1):
        baselines.learn([process])
    assert not baselines.ready(process)
    assert distribution([]).median is None


def test_feature_window_preserves_recently_reobserved_destinations(config, process):
    baselines = Baselines(config)
    process.destinations = [str(i) for i in range(512)]
    baselines.learn([process])
    process.destinations = ["0"]
    baselines.learn([process])
    process.destinations = ["new"]
    baselines.learn([process])
    assert "0" in baselines.get(process)["destinations"]
    assert "1" not in baselines.get(process)["destinations"]


def test_duplicate_socket_rows_are_counted_once(process):
    connection = Connection(
        "UDP4",
        "0.0.0.0",
        100,
        None,
        None,
        "NONE",
        process.pid,
        process.key,
        process.name,
        "none",
        utc_now(),
        utc_now(),
    )
    connections = [connection, copy.deepcopy(connection)]
    ConnectionTracker().update(connections, [process])
    assert len(connections) == 1 and process.connections == 1


@pytest.mark.parametrize("export", [export_json, export_findings_csv])
def test_failed_export_preserves_the_old_report_and_cleans_temporary_files(tmp_path, export):
    target = tmp_path / "report.json"
    target.write_text("original", encoding="utf-8")
    payload = {"bad": float("nan")} if export is export_json else [{"title": object()}]
    # CSV accepts unknown objects as strings, so force a failure after the header is written.
    if export is export_findings_csv:

        class Broken:
            def __str__(self):
                raise ValueError("cannot serialize")

        payload = [{"title": Broken()}]
    with pytest.raises(ValueError):
        export(target, payload)
    assert target.read_text(encoding="utf-8") == "original"
    assert not list(tmp_path.glob(".ttp-*.tmp"))


def test_export_cannot_overwrite_the_active_database(tmp_path, config, snapshot):
    path = tmp_path / "history.db"
    engine = Engine(config, Store(path), FixedCollector(snapshot))
    try:
        engine.cycle()
        with pytest.raises(ValueError, match="destination"):
            engine.export(path, "json", False)
        assert engine.store.history()
    finally:
        engine.close()


def test_future_schema_is_not_modified(tmp_path):
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT)")
        db.execute("INSERT INTO metadata VALUES ('schema_version','2')")
    with pytest.raises(ValueError, match="Unsupported"):
        Store(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [
            ("metadata",)
        ]


def test_report_metadata_cannot_be_overridden_by_context():
    payload = report({"schema": "wrong", "simulated": False}, simulated=True)
    assert payload["schema"].endswith("/v1") and payload["simulated"] is True


def test_lookup_retains_exited_process_context_and_separate_indicators(config, process, snapshot):
    snapshot.simulated = False
    monitor = Monitor(config, None)
    monitor.engine = Engine(config, Store(":memory:"), FixedCollector(snapshot))
    try:
        monitor.engine.cycle()
        captured = copy.deepcopy(process)
        monitor.engine.snapshot.processes = []
        result = Reputation(
            "VirusTotal", "8.8.8.8", "reported", True, "Provider context", utc_now()
        )
        monitor._reputation_done(result, captured)
        monitor._reputation_done(replace(result, indicator="1.1.1.1"), captured)
        records = monitor.engine.store.findings(process.key)
        assert len(records) == 2
        assert all(f["timestamp"] >= result.looked_up for f in records)
        assert all(f["source"] == "VirusTotal" for f in records)
    finally:
        monitor.lookup_pool.shutdown()
        monitor.engine.close()


def test_cache_uses_canonical_indicators():
    store = Store(":memory:")
    intelligence = Intelligence(store)
    try:
        digest = "AB" * 32
        intelligence.remember(
            Reputation("VirusTotal", digest, "reported", False, "Context", utc_now()), now=100
        )
        assert intelligence.prepare(
            VirusTotal("unused"), digest.lower(), "sha256", True, now=101
        ).cached
    finally:
        store.close()


@pytest.mark.parametrize("provider", [VirusTotal, AbuseIPDB])
@pytest.mark.parametrize("indicator", ["127.0.0.1", "https://example.com", "10.0.0.1"])
def test_provider_adapters_reject_unsafe_inputs_before_any_request(provider, indicator):
    get = Mock()
    with pytest.raises(ValueError):
        provider("unused", get).lookup(indicator, "ip")
    get.assert_not_called()


def test_retry_after_accepts_http_dates(monkeypatch):
    monkeypatch.setattr("trust_the_process.intelligence.time.time", lambda: 0)
    assert retry_delay("Thu, 01 Jan 1970 01:00:00 GMT") == 3600
    assert retry_delay("nan") == 60


def test_configuration_rejects_non_object_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        Config.load(path)


def test_a_short_lived_process_has_history_between_resource_flushes(config, snapshot):
    snapshot.simulated = False
    collector = FixedCollector(snapshot)
    engine = Engine(config, Store(":memory:"), collector)
    try:
        engine.cycle()
        newcomer = replace(snapshot.processes[0], pid=999, started=2000)
        collector.snapshot.processes.append(newcomer)
        engine.last_persist = time.monotonic()
        engine.cycle()
        collector.snapshot.processes.remove(newcomer)
        assert engine.store.history(newcomer.key)
    finally:
        engine.close()
