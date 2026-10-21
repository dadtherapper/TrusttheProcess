"""Versioned JSON reports and spreadsheet-safe CSV. Conservative optional redaction."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .files import atomic_text
from .models import clean, utc_now

REPORT_SCHEMA = "trust-the-process/investigation/v1"


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {clean(k): sanitize(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [sanitize(v) for v in value]
    return clean(value) if isinstance(value, str) else value


def redact(value: Any) -> Any:
    """Redact all free text, stable IDs, hashes and addressing, including nested evidence.

    Structured timestamps, rule identifiers, counts and booleans remain usable. Free text may
    duplicate sensitive fields, so field-only redaction would give a misleading privacy claim.
    """
    safe_strings = {
        "schema",
        "timestamp",
        "last_seen",
        "first_seen",
        "generated_at",
        "looked_up",
        "rule_id",
        "severity",
        "source",
        "protocol",
        "status",
        "address_class",
        "confidence",
        "limitations",
        "metric",
    }

    def walk(item: Any, key: str = "") -> Any:
        if isinstance(item, dict):
            return {k: walk(v, k) for k, v in item.items()}
        if isinstance(item, (tuple, list)):
            return [walk(v, key) for v in item]
        if key in {"pid", "ppid", "started", "local_port", "remote_port"}:
            return "[REDACTED]" if item is not None else None
        if isinstance(item, str) and key not in safe_strings:
            return "[REDACTED]"
        # Confidence/limitations/source are supplied by the application, not telemetry.
        return item

    return walk(value)


def report(context: dict, simulated: bool, redacted: bool = False) -> dict:
    result = {
        **context,
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now(),
        "simulated": simulated,
        "redacted": redacted,
        "limitations": "Socket snapshots may miss transient activity; "
        "PID attribution is best effort; risk scores are not malware probabilities.",
    }
    result = sanitize(result)
    return redact(result) if redacted else result


def export_json(path: Path, payload: Any) -> None:
    # Atomic replacement avoids truncated reports on serialization/write failures.
    with atomic_text(path) as stream:
        json.dump(sanitize(payload), stream, indent=2, ensure_ascii=False, allow_nan=False)


def csv_cell(value: Any) -> str:
    text = clean(
        json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
    )
    if text.lstrip().startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text


def export_findings_csv(path: Path, findings: list[dict], redacted: bool = False) -> None:
    fields = [
        "id",
        "rule_id",
        "title",
        "timestamp",
        "last_seen",
        "process_key",
        "process_name",
        "severity",
        "weight",
        "observed",
        "expected",
        "evidence",
        "explanation",
        "recommendation",
        "source",
        "confidence",
        "limitations",
        "simulated",
        "acknowledged",
        "occurrences",
    ]
    data = redact(sanitize(findings)) if redacted else sanitize(findings)
    with atomic_text(path, encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in data:
            writer.writerow({field: csv_cell(row.get(field, "")) for field in fields})
