"""Context rules and a transparent weighted evidence score, not a malware probability."""

from __future__ import annotations

import ntpath
import os
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from .baseline import Baselines
from .config import Config
from .models import Finding, Process, Snapshot, severity_for


def writable_location(path: str | None) -> bool:
    if not path:
        return False
    normalized = path.replace("\\", "/").casefold()
    return any(
        part in normalized for part in ("/temp/", "/tmp/", "/downloads/", "/appdata/local/temp/")
    )


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    weight: int
    explanation: str
    recommendation: str


RULES = {
    r.id: r
    for r in (
        Rule(
            "RES-MEM",
            "Sustained memory change",
            10,
            "Memory is persistently above this executable's learned range. Workload changes can explain it.",
            "Compare workload and recent updates; review the process timeline.",
        ),
        Rule(
            "RES-CPU",
            "Sustained CPU change",
            10,
            "CPU use persistently exceeds the local baseline. Resource consumption alone is not malicious.",
            "Check legitimate work, child processes, and recent application changes.",
        ),
        Rule(
            "EXEC-TEMP",
            "Executable in a transient directory",
            10,
            "Temporary and download directories are common for installers and also warrant context.",
            "Verify the publisher, origin, executable hash, and reason for execution.",
        ),
        Rule(
            "EXEC-SYSTEM",
            "System name outside the expected directory",
            30,
            "A Windows system executable name is being used outside standard system directories.",
            "Verify the full path, signature using Windows tools, hash, and parent process.",
        ),
        Rule(
            "EXEC-PARENT",
            "Previously unseen parent relationship",
            10,
            "This executable has a parent identity absent from its established local history.",
            "Review the parent path, command line, and legitimate launch workflows.",
        ),
        Rule(
            "EXEC-CHANGE",
            "New executable identity at a known path",
            10,
            "File metadata differs at a previously observed path. Updates are a common explanation.",
            "Compare hashes and update history; confirm the expected software publisher.",
        ),
        Rule(
            "NET-FIRST",
            "New external network behavior",
            20,
            "This executable previously had no observed public destinations during the learning window.",
            "Review destination ownership, the command line, and the application's network purpose.",
        ),
        Rule(
            "NET-DEST",
            "New external destination pattern",
            20,
            "Several public destinations are absent from the learned history. CDNs can cause this.",
            "Review destination context, timing, expected updates, and other findings.",
        ),
        Rule(
            "NET-BURST",
            "Increase in observed socket activity",
            15,
            "New remote socket tuples and concurrent connection counts increased together.",
            "Review destinations and workload. Socket observations are not packet or request counts.",
        ),
        Rule(
            "CTX-TEMP-NET",
            "Transient executable with changed network behavior",
            20,
            "A temporary executable and a change in established network behavior occur together.",
            "Investigate executable origin, parent, hash, and destinations before drawing conclusions.",
        ),
        Rule(
            "TI-REPUTATION",
            "Provider-reported reputation indicator",
            40,
            "A reputation provider reported an adverse indicator. Reputation can be stale or mistaken.",
            "Review provider attribution, lookup time, destination context, and independent evidence.",
        ),
    )
}


def risk_score(findings: list[dict | Finding]) -> int:
    weights = {}
    for f in findings:
        rule = f.rule_id if isinstance(f, Finding) else f["rule_id"]
        weight = f.weight if isinstance(f, Finding) else f["weight"]
        weights[rule] = max(weights.get(rule, 0), weight)
    return min(100, sum(weights.values()))


class Detector:
    def __init__(self, config: Config, baselines: Baselines) -> None:
        self.config = config
        self.baselines = baselines
        self.streak: dict[tuple[str, str], int] = defaultdict(int)
        self.rules: list[Callable[[Process, Snapshot], list[Finding]]] = [self._process_rules]
        self.frozen: set[tuple[str, str]] = set()
        self.identities: dict[str, str | None] = {}

    def finding(
        self,
        rule_id: str,
        p: Process,
        s: Snapshot,
        observed: str,
        expected: str | None = None,
        **evidence,
    ) -> Finding:
        rule = RULES[rule_id]
        weight = self.config.rule_weights.get(rule.id, rule.weight)
        return Finding(
            rule.id,
            rule.title,
            s.timestamp,
            p.key,
            p.identity,
            p.name,
            severity_for(weight),
            weight,
            observed,
            expected,
            {"executable": p.exe, "sha256": p.sha256, **evidence},
            rule.explanation,
            rule.recommendation,
            s.source,
            simulated=s.simulated,
        )

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        self.frozen = set()
        current = {p.key for p in snapshot.processes}
        changed = {
            p.key
            for p in snapshot.processes
            if self.identities.get(p.key) != p.identity or not self.baselines.ready(p)
        }
        self.streak = defaultdict(
            int, {k: v for k, v in self.streak.items() if k[0] in current and k[0] not in changed}
        )
        self.identities = {p.key: p.identity for p in snapshot.processes}
        return [f for p in snapshot.processes for rule in self.rules for f in rule(p, snapshot)]

    def _process_rules(self, p: Process, s: Snapshot) -> list[Finding]:
        found = []
        baseline = self.baselines.get(p)
        ready = self.baselines.ready(p)
        if writable_location(p.exe):
            found.append(self.finding("EXEC-TEMP", p, s, f"Executable path: {p.exe}"))
        system_names = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe"}
        if os.name == "nt" or s.simulated:
            root = os.environ.get("SystemRoot", "C:\\Windows")
            expected_dirs = {
                ntpath.normcase(ntpath.join(root, folder)) for folder in ("System32", "SysWOW64")
            }
            if p.exe and ntpath.basename(p.exe).casefold() in system_names:
                if ntpath.normcase(ntpath.dirname(p.exe)) not in expected_dirs:
                    found.append(
                        self.finding(
                            "EXEC-SYSTEM",
                            p,
                            s,
                            f"System-like name at {p.exe}",
                            "Windows System32 or SysWOW64",
                        )
                    )
        if p.identity and not baseline:
            old = [
                v
                for k, v in self.baselines.state.items()
                if k != p.identity and v.get("path", "").casefold() == p.exe.casefold()
            ]
            if old:
                found.append(
                    self.finding(
                        "EXEC-CHANGE",
                        p,
                        s,
                        "Executable file identity changed",
                        "Previously observed executable metadata",
                        previous_sha256=old[-1].get("sha256"),
                    )
                )
        if ready:
            for metric, rule_id in (("rss", "RES-MEM"), ("cpu", "RES-CPU")):
                dist = self.baselines.metric(p, metric)
                value = getattr(p, metric)
                token = (p.key, rule_id)
                if value is None or dist.count < self.config.min_samples:
                    self.streak[token] = 0
                    continue
                threshold = (
                    max(
                        dist.median * self.config.memory_ratio,
                        dist.median + self.config.memory_delta_mb * 1024**2,
                        dist.p95 + 6 * dist.mad,
                    )
                    if metric == "rss"
                    else max(dist.p95 + self.config.cpu_delta, dist.median + 6 * dist.mad)
                )
                above = value > threshold
                self.streak[token] = self.streak[token] + 1 if above else 0
                if above:
                    self.frozen.add((p.identity, metric))
                if self.streak[token] >= self.config.sustained_samples:
                    found.append(
                        self.finding(
                            rule_id,
                            p,
                            s,
                            f"{metric}={value:,.1f} for {self.streak[token]} consecutive samples",
                            f"Median {dist.median:,.1f}; p95 {dist.p95:,.1f}",
                            metric=metric,
                            measured=value,
                            threshold=threshold,
                            baseline_samples=dist.count,
                            sustained_samples=self.streak[token],
                        )
                    )
            parents = baseline.get("parents", [])
            if p.parent_identity and parents and p.parent_identity not in parents:
                found.append(
                    self.finding(
                        "EXEC-PARENT",
                        p,
                        s,
                        "Unseen parent executable identity",
                        "Established parent identities",
                        parent_key=p.parent_key,
                        parent_identity=p.parent_identity,
                    )
                )
            # Require valid network metric samples, not merely elapsed process samples.
            net = self.baselines.metric(p, "connections")
            if s.network_available and net.count >= self.config.min_samples:
                new = sorted(set(p.destinations) - set(baseline.get("destinations", [])))
                if p.destinations and not baseline.get("destinations"):
                    found.append(
                        self.finding(
                            "NET-FIRST",
                            p,
                            s,
                            f"{len(p.destinations)} public destinations observed",
                            "No public destinations",
                            destinations=p.destinations,
                            baseline_samples=net.count,
                        )
                    )
                if len(new) >= self.config.connection_burst:
                    found.append(
                        self.finding(
                            "NET-DEST",
                            p,
                            s,
                            f"{len(new)} unseen public destinations",
                            "Previously learned destinations",
                            destinations=new,
                        )
                    )
                if (
                    p.new_connections is not None
                    and p.new_connections >= self.config.connection_burst
                    and p.connections is not None
                    and p.connections > max(net.p95 * 2, net.p95 + 3)
                ):
                    found.append(
                        self.finding(
                            "NET-BURST",
                            p,
                            s,
                            f"{p.new_connections} newly observed remote socket tuples this interval",
                            f"Typical concurrent sockets: median {net.median}; p95 {net.p95}",
                            new_connections=p.new_connections,
                            interval_seconds=s.interval_seconds,
                        )
                    )
                if writable_location(p.exe) and any(f.rule_id.startswith("NET-") for f in found):
                    found.append(
                        self.finding(
                            "CTX-TEMP-NET",
                            p,
                            s,
                            "Transient executable with changed external network behavior",
                            "Established executable/network baseline",
                            destinations=p.destinations,
                        )
                    )
        return found
