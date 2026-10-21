"""Local SQLite persistence. A single monitoring worker owns the connection."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import Finding, Process, Snapshot


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).resolve() if str(path) != ":memory:" else None
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), timeout=10)
        try:
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE name='metadata'").fetchone():
                version = self.db.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                if not version or version[0] != "1":
                    raise ValueError("Unsupported history schema; use a new data directory.")
        except Exception:
            self.db.close()
            raise
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT OR IGNORE INTO metadata VALUES ('schema_version', '1');
            CREATE TABLE IF NOT EXISTS observations (
                ts TEXT NOT NULL, process_key TEXT NOT NULL, identity TEXT, payload TEXT NOT NULL,
                PRIMARY KEY(ts, process_key));
            CREATE INDEX IF NOT EXISTS observations_process ON observations(process_key, ts);
            CREATE TABLE IF NOT EXISTS frames (ts TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY, process_key TEXT, first_seen TEXT, last_seen TEXT,
                payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS connection_process ON connections(process_key, last_seen);
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, process_key TEXT, last_seen TEXT, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS findings_process ON findings(process_key);
            CREATE TABLE IF NOT EXISTS baselines (
                identity TEXT PRIMARY KEY, updated TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reputation (
                provider TEXT, indicator TEXT, expires REAL, payload TEXT,
                PRIMARY KEY(provider, indicator));
            CREATE TABLE IF NOT EXISTS provider_limits (
                provider TEXT PRIMARY KEY, next_allowed REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS provider_daily (
                provider TEXT, day TEXT, attempts INTEGER NOT NULL,
                PRIMARY KEY(provider, day));
        """)
        version = self.db.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
        if version[0] != "1":
            self.db.close()
            raise ValueError("Unsupported history schema; use a new data directory.")
        self.db.commit()

    def save_snapshot(self, snapshot: Snapshot, baselines: dict[str, dict[str, Any]]) -> None:
        with self.db:
            self.db.executemany(
                "INSERT OR REPLACE INTO observations VALUES (?, ?, ?, ?)",
                [
                    (snapshot.timestamp, p.key, p.identity, json.dumps(asdict(p)))
                    for p in snapshot.processes
                ],
            )
            frame = {
                "processes": len(snapshot.processes),
                "connections": len(snapshot.connections),
                "cpu": snapshot.system_cpu,
                "memory": snapshot.system_memory,
                "source": snapshot.source,
                "simulated": snapshot.simulated,
                "network_available": snapshot.network_available,
                "interval_seconds": snapshot.interval_seconds,
            }
            self.db.execute(
                "INSERT OR REPLACE INTO frames VALUES (?, ?)",
                (snapshot.timestamp, json.dumps(frame)),
            )
            self.db.executemany(
                "INSERT OR REPLACE INTO baselines VALUES (?, ?, ?)",
                [
                    (identity, value.get("last_seen", snapshot.timestamp), json.dumps(value))
                    for identity, value in baselines.items()
                ],
            )

    def save_connections(self, snapshot: Snapshot) -> None:
        with self.db:
            self.db.executemany(
                """INSERT INTO connections VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen, payload=excluded.payload
                """,
                [
                    (
                        c.key + ":" + c.first_seen,
                        c.process_key,
                        c.first_seen,
                        c.last_seen,
                        json.dumps(asdict(c)),
                    )
                    for c in snapshot.connections
                ],
            )

    def save_processes(self, timestamp: str, processes: list[Process]) -> None:
        """Preserve first sightings between the less frequent full resource flushes."""
        with self.db:
            self.db.executemany(
                "INSERT OR REPLACE INTO observations VALUES (?, ?, ?, ?)",
                [(timestamp, p.key, p.identity, json.dumps(asdict(p))) for p in processes],
            )

    def save_finding(self, finding: Finding) -> Finding:
        observed_at = finding.last_seen or finding.timestamp
        row = self.db.execute("SELECT payload FROM findings WHERE id=?", (finding.id,)).fetchone()
        if row:
            previous = json.loads(row[0])
            finding.timestamp = previous["timestamp"]
            finding.acknowledged = previous["acknowledged"]
            finding.occurrences = previous["occurrences"] + 1
        finding.last_seen = observed_at
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO findings VALUES (?, ?, ?, ?)",
                (finding.id, finding.process_key, finding.last_seen, json.dumps(finding.to_dict())),
            )
        return finding

    def findings(self, process_key: str | None = None, limit: int | None = 1000) -> list[dict]:
        query = "SELECT payload FROM findings"
        args: tuple = ()
        if process_key:
            query += " WHERE process_key=?"
            args = (process_key,)
        query += " ORDER BY last_seen DESC"
        if limit is not None:
            query += " LIMIT ?"
            args = (*args, limit)
        return [json.loads(r[0]) for r in self.db.execute(query, args)]

    def acknowledge(self, finding_id: str) -> None:
        row = self.db.execute("SELECT payload FROM findings WHERE id=?", (finding_id,)).fetchone()
        if row:
            payload = json.loads(row[0])
            payload["acknowledged"] = True
            with self.db:
                self.db.execute(
                    "UPDATE findings SET payload=? WHERE id=?", (json.dumps(payload), finding_id)
                )

    def load_baselines(self) -> dict[str, dict]:
        return {
            r[0]: {**json.loads(r[2]), "last_seen": r[1]}
            for r in self.db.execute("SELECT identity,updated,payload FROM baselines")
        }

    def process_findings(self, keys: list[str]) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {key: [] for key in keys}
        for start in range(0, len(keys), 500):
            batch = keys[start : start + 500]
            markers = ",".join("?" for _ in batch)
            for key, payload in self.db.execute(
                f"SELECT process_key,payload FROM findings WHERE process_key IN ({markers}) "
                "ORDER BY last_seen DESC",
                batch,
            ):
                result[key].append(json.loads(payload))
        return result

    def reset_baselines(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM baselines")

    def history(self, process_key: str | None = None, limit: int = 120) -> list[dict]:
        if process_key:
            rows = self.db.execute(
                """SELECT ts,payload FROM observations WHERE process_key=?
                ORDER BY ts DESC LIMIT ?""",
                (process_key, limit),
            )
        else:
            rows = self.db.execute(
                "SELECT ts,payload FROM frames ORDER BY ts DESC LIMIT ?", (limit,)
            )
        return [{"timestamp": r[0], **json.loads(r[1])} for r in rows][::-1]

    def process_context(self, process_key: str) -> dict:
        observations = self.history(process_key)
        connections = self.db.execute(
            """SELECT payload FROM connections WHERE process_key=?
            ORDER BY last_seen DESC LIMIT 500""",
            (process_key,),
        )
        return {
            "process_key": process_key,
            "observations": observations,
            "connections": [json.loads(r[0]) for r in connections],
            "findings": self.findings(process_key),
        }

    def executions(self, limit: int = 250) -> list[dict]:
        rows = self.db.execute(
            """SELECT o.ts,o.process_key,o.payload FROM observations o
            JOIN (SELECT process_key,MAX(ts) AS latest FROM observations GROUP BY process_key) recent
            ON o.process_key=recent.process_key AND o.ts=recent.latest
            ORDER BY o.ts DESC LIMIT ?""",
            (limit,),
        )
        return [{"timestamp": r[0], "process_key": r[1], **json.loads(r[2])} for r in rows]

    def prune(self, days: int) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
        with self.db:
            for table, column, cap in (
                ("observations", "ts", 200000),
                ("frames", "ts", 10000),
                ("connections", "last_seen", 50000),
                ("findings", "last_seen", 10000),
                ("baselines", "updated", 5000),
            ):
                self.db.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
                self.db.execute(
                    f"""DELETE FROM {table} WHERE rowid IN
                    (SELECT rowid FROM {table} ORDER BY {column} DESC LIMIT -1 OFFSET ?)""",
                    (cap,),
                )
            self.db.execute(
                "DELETE FROM reputation WHERE expires < ?", (datetime.now(UTC).timestamp(),)
            )
        self.db.execute("PRAGMA incremental_vacuum")

    def close(self) -> None:
        self.db.close()
