"""Shared telemetry contracts. Missing measurements are None, never synthetic zeroes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def clean(value: object, limit: int = 8192) -> str:
    """Remove terminal/control and bidi overrides from untrusted display strings."""
    return "".join(c for c in str(value) if c.isprintable() or c in "\n\t")[:limit].translate(
        dict.fromkeys(map(ord, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
    )


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class Process:
    pid: int
    started: float | None
    name: str
    ppid: int | None = None
    exe: str | None = None
    command: str | None = None
    username: str | None = None
    cpu: float | None = None
    rss: int | None = None
    memory_percent: float | None = None
    status: str | None = None
    sha256: str | None = None
    file_identity: str | None = None
    parent_identity: str | None = None
    parent_key: str | None = None
    connections: int | None = None
    destinations: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    new_connections: int | None = None
    limitations: list[str] = field(default_factory=list)
    unknown_token: str = "unavailable"

    @property
    def key(self) -> str:
        return f"{self.pid}:{self.started if self.started is not None else self.unknown_token}"

    @property
    def identity(self) -> str | None:
        # Metadata is available before the async hash. Replacing a file starts learning again.
        if not self.exe or not self.file_identity:
            return None
        return digest(self.exe.replace("\\", "/").casefold() + "|" + self.file_identity)


@dataclass
class Connection:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str | None
    remote_port: int | None
    status: str
    pid: int | None
    process_key: str | None
    process_name: str | None
    address_class: str
    first_seen: str
    last_seen: str
    source: str = "psutil socket snapshot"
    new: bool = False

    @property
    def key(self) -> str:
        return digest(
            json.dumps(
                [
                    self.protocol,
                    self.local_ip,
                    self.local_port,
                    self.remote_ip,
                    self.remote_port,
                    self.process_key,
                    self.pid,
                ]
            )
        )


@dataclass
class Snapshot:
    timestamp: str
    processes: list[Process]
    connections: list[Connection]
    source: str
    simulated: bool = False
    system_cpu: float | None = None
    system_memory: float | None = None
    network_available: bool = True
    limitations: list[str] = field(default_factory=list)
    interval_seconds: float | None = None


@dataclass
class Finding:
    rule_id: str
    title: str
    timestamp: str
    process_key: str
    process_identity: str | None
    process_name: str
    severity: str
    weight: int
    observed: str
    expected: str | None
    evidence: dict[str, Any]
    explanation: str
    recommendation: str
    source: str
    confidence: str = "Contextual; not a malware verdict"
    limitations: str = "Sampling may miss short-lived activity."
    simulated: bool = False
    acknowledged: bool = False
    occurrences: int = 1
    last_seen: str | None = None

    @property
    def id(self) -> str:
        subject = ""
        if self.rule_id == "TI-REPUTATION":
            subject = f"|{self.evidence.get('provider')}|{self.evidence.get('indicator')}"
        return digest(f"{self.rule_id}|{self.process_key}|{self.simulated}{subject}")[:24]

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, **asdict(self)}


def severity_for(score: int) -> str:
    return (
        "High"
        if score >= 60
        else "Medium"
        if score >= 30
        else "Low"
        if score >= 10
        else "Informational"
    )
