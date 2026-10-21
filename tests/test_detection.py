from __future__ import annotations

import copy

from trust_the_process.baseline import Baselines, distribution
from trust_the_process.detection import Detector, risk_score
from trust_the_process.models import severity_for


def learn(baselines, process, n=5):
    for _ in range(n):
        baselines.learn([process])


def test_robust_distribution():
    result = distribution([1, 2, 2, 2, 3, 1000])
    assert result.median == 2 and result.mad == 0.5 and result.count == 6
    assert distribution([]).count == 0


def test_learning_minimum_and_pooling(config, process):
    baselines = Baselines(config)
    other = copy.deepcopy(process)
    other.pid = 999
    baselines.learn([process, other])
    assert baselines.get(process)["samples"] == 1
    assert not baselines.ready(process)
    learn(baselines, process, 4)
    assert baselines.ready(process)
    assert baselines.metric(process, "cpu").count == 5
    learn(baselines, process, 40)
    assert baselines.metric(process, "cpu").count == config.baseline_window


def test_resource_requires_baseline_and_sustained_context(config, process, snapshot):
    baselines = Baselines(config)
    detector = Detector(config, baselines)
    original = process.rss
    process.rss *= 20
    assert not detector.evaluate(snapshot)
    process.rss = original
    learn(baselines, process)
    process.rss *= 20
    process.cpu = 99
    assert not detector.evaluate(snapshot)
    findings = detector.evaluate(snapshot)
    assert {f.rule_id for f in findings} == {"RES-MEM", "RES-CPU"}
    assert all(f.expected and f.evidence["baseline_samples"] == 5 for f in findings)
    assert risk_score(findings) == 20
    assert all("malicious" in f.explanation or "Workload" in f.explanation for f in findings)
    # Outliers do not immediately poison the baseline.
    baselines.learn([process], detector.frozen)
    assert baselines.metric(process, "rss").median == original
    process.rss = None
    process.cpu = None
    assert not detector.evaluate(snapshot)
    assert not detector.streak[(process.key, "RES-MEM")]


def test_network_context_and_insufficient_visibility(config, process, snapshot):
    baselines = Baselines(config)
    detector = Detector(config, baselines)
    process.exe = r"C:\Users\Demo\AppData\Local\Temp\app.exe"
    learn(baselines, process)
    process.destinations = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"]
    process.connections, process.new_connections = 5, 5
    found = detector.evaluate(snapshot)
    assert {f.rule_id for f in found} == {
        "EXEC-TEMP",
        "NET-FIRST",
        "NET-DEST",
        "NET-BURST",
        "CTX-TEMP-NET",
    }
    assert risk_score(found) == 85
    snapshot.network_available = False
    assert [f.rule_id for f in detector.evaluate(snapshot)] == ["EXEC-TEMP"]


def test_network_samples_must_exist(config, process, snapshot):
    baselines = Baselines(config)
    process.connections = None
    learn(baselines, process)
    process.destinations = ["8.8.8.8"]
    process.connections = 1
    assert not Detector(config, baselines).evaluate(snapshot)


def test_execution_and_unseen_parent(config, process, snapshot, monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    process.exe = r"C:\Downloads\svchost.exe"
    baseline = Baselines(config)
    learn(baseline, process)
    process.parent_identity = "new-parent"
    ids = {f.rule_id for f in Detector(config, baseline).evaluate(snapshot)}
    assert ids == {"EXEC-TEMP", "EXEC-SYSTEM", "EXEC-PARENT"}
    process.exe = r"C:\Windows\System32\svchost.exe"
    assert not Detector(config, baseline).evaluate(snapshot)


def test_new_file_at_known_path_and_no_identity(config, process, snapshot):
    baselines = Baselines(config)
    learn(baselines, process)
    process.file_identity = "changed"
    assert {f.rule_id for f in Detector(config, baselines).evaluate(snapshot)} == {"EXEC-CHANGE"}
    process.exe = None
    process.cpu = None
    process.rss = None
    assert not Detector(config, baselines).evaluate(snapshot)


def test_risk_deduplicates_rule_weights_and_caps():
    findings = [
        {"rule_id": "one", "weight": 40},
        {"rule_id": "one", "weight": 40},
        {"rule_id": "two", "weight": 30},
    ]
    assert risk_score(findings) == 70
    assert risk_score(findings + [{"rule_id": "three", "weight": 50}]) == 100
    assert [severity_for(i) for i in (0, 10, 30, 60)] == ["Informational", "Low", "Medium", "High"]


def test_configured_evidence_weights(config, process, snapshot):
    process.exe = r"C:\Temp\app.exe"
    config.rule_weights = {"EXEC-TEMP": 5}
    config.validate()
    findings = Detector(config, Baselines(config)).evaluate(snapshot)
    assert len(findings) == 1 and findings[0].weight == 5
    assert findings[0].severity == "Informational" and risk_score(findings) == 5
