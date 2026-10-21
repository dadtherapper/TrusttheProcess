"""Monitoring orchestration. The UI exchanges immutable-by-convention messages through queues."""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Protocol

from .baseline import Baselines
from .config import Config
from .demo import DemoCollector
from .detection import Detector, risk_score
from .intelligence import (
    Intelligence,
    MockProvider,
    ProviderFailure,
    Reputation,
    configured_provider,
    normalize_indicator,
)
from .models import Process, Snapshot, utc_now
from .reporting import export_findings_csv, export_json, report
from .storage import Store


class Collector(Protocol):
    def collect(self) -> Snapshot: ...
    def close(self) -> None: ...


@dataclass
class ViewState:
    snapshot: Snapshot
    findings: list[dict]
    risks: dict[str, int]
    baselines: dict[str, dict]
    history: list[dict]
    executions: list[dict]
    process_findings: dict[str, list[dict]] = field(default_factory=dict)


@dataclass
class LookupTask:
    future: Future
    provider: str
    process: Process | None


class Engine:
    def __init__(self, config: Config, store: Store, collector: Collector) -> None:
        self.config, self.store, self.collector = config, store, collector
        store.prune(config.retention_days)
        self.baselines = Baselines(config, store.load_baselines())
        self.detector = Detector(config, self.baselines)
        self.snapshot: Snapshot | None = None
        self.last_persist = float("-inf")
        self.last_prune = time.monotonic()
        self.demo_reputation_done = False
        self.intelligence = Intelligence(store, config.reputation_ttl_hours)
        self.history = store.history()
        self.executions = store.executions()
        self.previous_processes: set[str] = set()

    def cycle(self, persist: bool = False) -> ViewState:
        snapshot = self.collector.collect()
        findings = self.detector.evaluate(snapshot)
        if isinstance(self.collector, DemoCollector):
            if (
                self.collector.tick > self.collector.transition + 1
                and not self.demo_reputation_done
            ):
                process = next(p for p in snapshot.processes if p.pid == 620)
                reputation = MockProvider().lookup("9.9.9.9", "ip")
                # A local mock only; these sample addresses carry no real reputation assertion.
                reputation.looked_up = snapshot.timestamp
                findings.append(
                    self.detector.finding(
                        "TI-REPUTATION",
                        process,
                        snapshot,
                        reputation.summary,
                        "SIMULATED provider context",
                        **asdict(reputation),
                    )
                )
                self.demo_reputation_done = True
        for finding in findings:
            self.store.save_finding(finding)
        self.baselines.learn(snapshot.processes, self.detector.frozen, snapshot.timestamp)
        self.snapshot = snapshot
        now = time.monotonic()
        if persist or snapshot.simulated or now - self.last_persist >= 15:
            self.persist()
        else:
            first_seen = [p for p in snapshot.processes if p.key not in self.previous_processes]
            if first_seen:
                self.store.save_processes(snapshot.timestamp, first_seen)
                self.executions = self.store.executions()
        self.previous_processes = {p.key for p in snapshot.processes}
        self.store.save_connections(snapshot)
        if now - self.last_prune >= 60:
            self.persist()  # Include identities learned since the previous history flush.
            self.store.prune(self.config.retention_days)
            # Drop identities pruned by age/caps from the in-memory learner as well.
            stored = self.store.load_baselines()
            self.baselines.state = {k: v for k, v in self.baselines.state.items() if k in stored}
            self.history = self.store.history()
            self.executions = self.store.executions()
            self.last_prune = now
        return self.view()

    def persist(self) -> None:
        if self.snapshot:
            self.store.save_snapshot(self.snapshot, self.baselines.state)
            self.last_persist = time.monotonic()
            self.history = self.store.history()
            self.executions = self.store.executions()

    def view(self) -> ViewState:
        if self.snapshot is None:
            raise RuntimeError("No observations collected yet")
        findings = self.store.findings(limit=None)
        process_findings = self.store.process_findings([p.key for p in self.snapshot.processes])
        risks = {p.key: risk_score(process_findings[p.key]) for p in self.snapshot.processes}
        baselines = {}
        for p in self.snapshot.processes:
            data = self.baselines.get(p)
            baselines[p.key] = {
                "samples": data.get("samples", 0),
                "ready": self.baselines.ready(p),
                "identity": p.identity,
                "known_destinations": data.get("destinations", []),
                "known_ports": data.get("ports", []),
                "known_parents": data.get("parents", []),
                **{
                    name: asdict(self.baselines.metric(p, name))
                    for name in ("rss", "cpu", "connections")
                },
            }
        return ViewState(
            self.snapshot,
            findings,
            risks,
            baselines,
            self.history,
            self.executions,
            process_findings,
        )

    def reset_baselines(self) -> None:
        self.store.reset_baselines()
        self.baselines.state.clear()
        self.detector.streak.clear()
        self.detector.identities.clear()

    def export(self, path: Path, mode: str, redacted: bool, process_key: str | None = None) -> None:
        if self.store.path:
            protected = [
                self.store.path,
                Path(str(self.store.path) + "-wal"),
                Path(str(self.store.path) + "-shm"),
                self.store.path.parent / "config.json",
                self.store.path.parent / "application.log",
            ]
            if path.resolve() in protected:
                raise ValueError(
                    "Choose a report destination outside the application's data files."
                )
        self.persist()
        simulated = bool(self.snapshot and self.snapshot.simulated)
        if mode == "csv":
            export_findings_csv(path, self.store.findings(process_key, 10000), redacted)
        else:
            context = (
                self.store.process_context(process_key)
                if process_key
                else {"findings": self.store.findings(limit=10000), "history": self.store.history()}
            )
            if process_key and self.snapshot:
                process = next((p for p in self.snapshot.processes if p.key == process_key), None)
                context["current_process"] = asdict(process) if process else None
                context["current_connections"] = [
                    asdict(c) for c in self.snapshot.connections if c.process_key == process_key
                ]
                context["baseline"] = self.view().baselines.get(process_key)
            export_json(path, report(context, simulated, redacted))

    def close(self) -> None:
        try:
            self.persist()
        finally:
            try:
                self.collector.close()
            finally:
                self.store.close()


class Monitor:
    """All disk work and collection stay off the Tk thread; HTTP has its own bounded worker."""

    def __init__(self, config: Config, folder: Path, demo: bool = False) -> None:
        self.config, self.folder, self.demo = config, folder, demo
        self.commands: queue.Queue = queue.Queue(maxsize=64)
        self.states: queue.Queue[ViewState] = queue.Queue(maxsize=1)
        self.messages: queue.Queue = queue.Queue(maxsize=64)
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.paused = threading.Event()
        self.thread = threading.Thread(target=self._run, name="ttp-monitor", daemon=False)
        self.engine: Engine | None = None
        self.lookup_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ttp-reputation")
        self.lookup: LookupTask | None = None

    def start(self) -> None:
        self.thread.start()

    def submit(self, command: str, **kwargs) -> None:
        try:
            self.commands.put_nowait((command, kwargs))
            self.wake.set()
        except queue.Full:
            self.message("error", "The command queue is busy. Please retry shortly.")

    def message(self, kind: str, payload) -> None:
        try:
            self.messages.put_nowait((kind, payload))
        except queue.Full:
            pass

    def publish(self, state: ViewState | None = None) -> None:
        if self.engine and self.engine.snapshot:
            state = state or self.engine.view()
            try:
                self.states.get_nowait()
            except queue.Empty:
                pass
            self.states.put_nowait(state)

    def _reputation_done(self, result: Reputation, process: Process | None) -> None:
        engine = self.engine
        if not result.cached:
            engine.intelligence.remember(result)
        if result.flagged and process and engine.snapshot:
            finding = engine.detector.finding(
                "TI-REPUTATION",
                process,
                replace(engine.snapshot, timestamp=utc_now()),
                result.summary,
                "Provider-reported context",
                **asdict(result),
            )
            finding.source = result.provider
            engine.store.save_finding(finding)
        self.message("reputation", asdict(result))
        self.publish()

    def _command(self, name: str, args: dict) -> None:
        engine = self.engine
        if name == "pause":
            self.paused.set()
            engine.detector.streak.clear()
            engine.persist()
            self.message("status", "Paused • last observed values remain visible")
        elif name == "resume":
            if self.paused.is_set():
                resume_collection = getattr(engine.collector, "resume", None)
                if resume_collection:
                    resume_collection()
            self.paused.clear()
            self.message("status", "Monitoring")
        elif name == "acknowledge":
            engine.store.acknowledge(args["finding_id"])
            self.publish()
        elif name == "reset":
            engine.reset_baselines()
            self.publish()
            self.message(
                "status", "Baselines reset • learning restarted; investigation history retained"
            )
        elif name == "history":
            self.message("history", engine.store.process_context(args["process_key"]))
        elif name == "export":
            engine.export(**args)
            self.message("status", f"Export saved: {args['path']}")
        elif name == "settings":
            config = Config(**args["config"])
            config.validate()
            if self.demo:
                config.abuseipdb_enabled = config.virustotal_enabled = False
            config.save(self.folder / "config.json")
            self.config = engine.config = engine.baselines.config = engine.detector.config = config
            engine.detector.streak.clear()
            for baseline in engine.baselines.state.values():
                for metric in ("cpu", "rss", "connections"):
                    baseline[metric] = baseline.get(metric, [])[-config.baseline_window :]
            engine.intelligence.ttl_hours = config.reputation_ttl_hours
            self.message("settings", asdict(config))
            self.message("status", "Settings saved")
        elif name == "lookup":
            if self.demo:
                raise ValueError("Demo mode uses local simulated reputation only.")
            if self.lookup:
                raise ValueError("A reputation lookup is already running.")
            name, indicator, kind = args["provider"], args["indicator"], args["kind"]
            enabled = (
                engine.config.virustotal_enabled
                if name == "VirusTotal"
                else engine.config.abuseipdb_enabled
            )
            # Check consent before touching provider credentials or constructing any HTTP request.
            if not enabled:
                raise ValueError("Enable the selected provider in Settings first.")
            provider = configured_provider(name)
            indicator = normalize_indicator(indicator, kind)
            cached = engine.intelligence.prepare(provider, indicator, kind, enabled)
            process = next(
                (
                    p
                    for p in (engine.snapshot.processes if engine.snapshot else [])
                    if p.key == args.get("process_key")
                ),
                None,
            )
            if cached:
                self._reputation_done(cached, process)
            else:
                self.lookup = LookupTask(
                    self.lookup_pool.submit(provider.lookup, indicator, kind),
                    provider.name,
                    process,
                )
                self.message("status", "Looking up the selected indicator…")

    def _run(self) -> None:
        store = collector = None
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
            if self.demo:
                # Independent sessions preserve deterministic learning and cannot mix with host data.
                demo_path = self.folder / f"session-{time.time_ns()}.db"
                for old in sorted(self.folder.glob("session-*.db"))[:-4]:
                    for candidate in (old, Path(str(old) + "-wal"), Path(str(old) + "-shm")):
                        try:
                            candidate.unlink(missing_ok=True)
                        except OSError:
                            pass  # Another demo window may still own this session.
                store = Store(demo_path)
                collector = DemoCollector(self.config.min_samples)
            else:
                from .collector import HostCollector

                store = Store(self.folder / "history.db")
                collector = HostCollector()
            self.engine = Engine(self.config, store, collector)
            due = 0.0
            while not self.stop.is_set():
                self.wake.clear()
                for _ in range(16):
                    try:
                        name, args = self.commands.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        self._command(name, args)
                        if name in {"settings", "resume"}:
                            due = 0.0
                    except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
                        self.message("error", str(error))
                if self.lookup and self.lookup.future.done():
                    task = self.lookup
                    self.lookup = None
                    try:
                        self._reputation_done(task.future.result(), task.process)
                    except ProviderFailure as error:
                        self.engine.intelligence.failure(task.provider, error)
                        self.message(
                            "error", f"{task.provider}: {error.status}. No reputation conclusion."
                        )
                    except Exception:
                        self.message(
                            "error", "Provider response could not be processed. No conclusion."
                        )
                if not self.paused.is_set() and time.monotonic() >= due:
                    try:
                        self.publish(self.engine.cycle())
                    except Exception as error:
                        self.engine.detector.streak.clear()
                        logging.error("Collection cycle failed: %s", type(error).__name__)
                        self.message(
                            "error", f"Observation failed ({type(error).__name__}); retrying."
                        )
                    due = time.monotonic() + self.config.interval
                self.wake.wait(0.2)
        except Exception as error:
            logging.error("Monitoring failed: %s", type(error).__name__)
            self.message(
                "error", f"Monitoring could not start ({type(error).__name__}). Check data access."
            )
        finally:
            self.lookup_pool.shutdown(wait=True, cancel_futures=True)
            try:
                if self.engine:
                    self.engine.close()
                else:
                    if collector:
                        collector.close()
                    if store:
                        store.close()
            except Exception as error:
                logging.error("Final history flush failed: %s", type(error).__name__)
                self.message(
                    "error", "Final history flush failed; the last observations may be missing."
                )

    def shutdown(self) -> None:
        self.stop.set()
        self.wake.set()
