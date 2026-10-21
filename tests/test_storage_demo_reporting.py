from __future__ import annotations

import copy
import csv
import json
from datetime import UTC, datetime, timedelta

import pytest

from trust_the_process.config import Config
from trust_the_process.demo import DemoCollector
from trust_the_process.detection import Detector
from trust_the_process.engine import Engine
from trust_the_process.models import clean, utc_now
from trust_the_process.reporting import export_findings_csv, report
from trust_the_process.storage import Store


def test_persistence_acknowledgment_and_dedup(tmp_path, config, process, snapshot):
    path = tmp_path / "history.db"
    store = Store(path)
    from trust_the_process.baseline import Baselines

    baseline = Baselines(config)
    process.exe = r"C:\Temp\app.exe"
    detector = Detector(config, baseline)
    first = detector.evaluate(snapshot)[0]
    store.save_finding(first)
    store.acknowledge(first.id)
    original_time = first.timestamp
    snapshot.timestamp = "2026-10-19T18:01:00.000+00:00"
    second = detector.evaluate(snapshot)[0]
    store.save_finding(second)
    baseline.learn([process])
    store.save_snapshot(snapshot, baseline.state)
    store.close()
    reopened = Store(path)
    try:
        findings = reopened.findings()
        assert len(findings) == 1 and findings[0]["occurrences"] == 2
        assert findings[0]["acknowledged"] and findings[0]["timestamp"] == original_time
        assert findings[0]["last_seen"] == snapshot.timestamp
        assert reopened.history(process.key)[0]["rss"] == process.rss
        assert reopened.load_baselines()[process.identity]["samples"] == 1
        reopened.reset_baselines()
        assert not reopened.load_baselines()
        assert reopened.history(process.key)
    finally:
        reopened.close()


def test_deterministic_demo_full_engine_and_export(tmp_path, config):
    start = datetime.now(UTC)
    a, b = DemoCollector(config.min_samples, start), DemoCollector(config.min_samples, start)
    assert a.collect() == b.collect()
    store = Store(tmp_path / "demo.db")
    engine = Engine(config, store, DemoCollector(config.min_samples, start))
    try:
        early = engine.cycle(persist=True)
        assert all(f["rule_id"] == "EXEC-TEMP" for f in early.findings)
        for _ in range(16):
            state = engine.cycle(persist=True)
        rules = {f["rule_id"] for f in state.findings}
        assert {
            "RES-MEM",
            "RES-CPU",
            "NET-FIRST",
            "NET-DEST",
            "TI-REPUTATION",
            "CTX-TEMP-NET",
        } <= rules
        assert all(f["simulated"] and f["evidence"] for f in state.findings)
        assert state.risks[next(p.key for p in state.snapshot.processes if p.pid == 620)] == 100
        p = state.snapshot.processes[-1]
        raw_path, redacted_path = tmp_path / "raw.json", tmp_path / "redacted.json"
        engine.export(raw_path, "investigation", False, p.key)
        engine.export(redacted_path, "investigation", True, p.key)
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        redacted = redacted_path.read_text(encoding="utf-8")
        assert raw["simulated"] and raw["schema"].endswith("/v1")
        assert raw["current_process"]["pid"] == 620
        assert raw["observations"] and raw["connections"] and raw["findings"]
        assert "Demo" not in redacted and "9.9.9.9" not in redacted and p.sha256 not in redacted
        assert json.loads(redacted)["current_process"]["pid"] == "[REDACTED]"
        engine.export(tmp_path / "findings.csv", "csv", True)
        with (tmp_path / "findings.csv").open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        assert rows and all(row["process_name"] == "[REDACTED]" for row in rows)
        engine.reset_baselines()
        assert not engine.baselines.state and not engine.store.load_baselines()
    finally:
        engine.close()


def test_report_redacts_identifiers_in_free_text():
    payload = report(
        {
            "process_key": "100:123",
            "current_process": {
                "username": "SECRET",
                "exe": "C:\\Users\\SECRET\\app.exe",
                "command": "SECRET secret.example",
            },
            "findings": [
                {
                    "observed": "SECRET connected to 10.0.0.1",
                    "evidence": {"destinations": ["10.0.0.1"], "baseline_samples": 20},
                }
            ],
        },
        False,
        True,
    )
    assert "SECRET" not in json.dumps(payload) and "10.0.0.1" not in json.dumps(payload)
    assert payload["findings"][0]["evidence"]["baseline_samples"] == 20


def test_csv_formula_and_control_safety(tmp_path):
    path = tmp_path / "out.csv"
    export_findings_csv(path, [{"title": '\t=HYPERLINK("evil")', "observed": "\x1b[31mtest\u202e"}])
    with path.open(encoding="utf-8-sig", newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["title"].startswith("'")
    assert "\x1b" not in row["observed"] and "\u202e" not in row["observed"]
    assert clean("a\x00b") == "ab"


def test_retention_removes_expired_rows(config):
    store = Store(":memory:")
    engine = Engine(config, store, DemoCollector(config.min_samples))
    try:
        state = engine.cycle(persist=True)
        old = copy.deepcopy(state.snapshot)
        old.timestamp = (datetime.now(UTC) - timedelta(days=100)).isoformat()
        store.save_snapshot(old, {})
        store.prune(14)
        assert all(r["timestamp"] != old.timestamp for r in store.history())
    finally:
        engine.close()


@pytest.mark.parametrize(
    "override",
    [
        {"interval": 0},
        {"retention_days": 0},
        {"interval": float("nan")},
        {"min_samples": 3},
        {"memory_ratio": 1},
        {"virustotal_enabled": "true"},
        {"min_samples": 20.5},
        {"min_samples": 50, "baseline_window": 20},
    ],
)
def test_invalid_config(override):
    config = Config(**override)
    with pytest.raises(ValueError):
        config.validate()


def test_config_roundtrip(tmp_path):
    path = tmp_path / "config.json"
    config = Config(interval=5, min_samples=15)
    config.save(path)
    assert Config.load(path) == config
    assert utc_now().endswith("+00:00")


@pytest.mark.parametrize(
    "weights", [{"TYPO": 10}, {"EXEC-TEMP": -1}, {"RES-CPU": True}, {"RES-MEM": 1.5}, [], None]
)
def test_invalid_rule_weights(weights):
    with pytest.raises(ValueError):
        Config(rule_weights=weights).validate()


def test_restarted_baseline_uses_persisted_samples(tmp_path, config):
    path = tmp_path / "history.db"
    start = datetime.now(UTC)
    engine = Engine(config, Store(path), DemoCollector(config.min_samples, start))
    for _ in range(7):
        engine.cycle(persist=True)
    assert all(b["ready"] for b in engine.view().baselines.values())
    engine.close()
    restarted = Engine(config, Store(path), DemoCollector(config.min_samples, start))
    try:
        assert len(restarted.baselines.state) == 5
        assert all(b["samples"] == 7 for b in restarted.baselines.state.values())
        state = restarted.cycle()
        assert all(b["ready"] for b in state.baselines.values())
        assert len(restarted.store.executions()) == 5
    finally:
        restarted.close()
