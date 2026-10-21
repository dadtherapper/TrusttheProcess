"""Explicit, indicator-only GET lookups. No uploads, automatic enrichment, or secrets on disk."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Protocol

import requests

from .models import utc_now
from .network import classify_address
from .storage import Store


@dataclass
class Reputation:
    provider: str
    indicator: str
    status: str
    flagged: bool
    summary: str
    looked_up: str
    cached: bool = False
    simulated: bool = False


class Provider(Protocol):
    name: str
    interval: float

    def lookup(self, indicator: str, kind: str) -> Reputation: ...


class ProviderFailure(Exception):
    def __init__(self, status: str, retry_after: float = 60) -> None:
        super().__init__(status)
        self.status, self.retry_after = status, retry_after


def retry_delay(value: str | None) -> float:
    try:
        seconds = float(value)
    except (ValueError, TypeError):
        try:
            stamp = parsedate_to_datetime(value)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=UTC)
            seconds = stamp.timestamp() - time.time()
        except (ValueError, TypeError, OverflowError, OSError):
            seconds = 60
    return max(60, min(seconds, 86400)) if math.isfinite(seconds) else 60


class HTTPProvider:
    name = ""
    interval = 16.0

    def __init__(self, key: str, get: Callable = requests.get) -> None:
        self.key = key
        self.get = get

    def request(self, url: str, **kwargs) -> dict | None:
        try:
            response = self.get(url, timeout=(3, 7), allow_redirects=False, **kwargs)
            if response.status_code == 404:
                return None
            if response.status_code == 429:
                raise ProviderFailure(
                    "rate_limited", retry_delay(response.headers.get("Retry-After"))
                )
            if response.status_code != 200:
                raise ProviderFailure(f"http_{response.status_code}")
            # Do not retain full reports or print request objects (they contain key headers).
            data = response.json()
            if not isinstance(data, dict):
                raise ProviderFailure("invalid_response")
            return data
        except (requests.RequestException, ValueError):
            raise ProviderFailure("unavailable") from None


class VirusTotal(HTTPProvider):
    name = "VirusTotal"

    def lookup(self, indicator: str, kind: str) -> Reputation:
        indicator = normalize_indicator(indicator, kind)
        collection = "files" if kind == "sha256" else "ip_addresses"
        data = self.request(
            f"https://www.virustotal.com/api/v3/{collection}/{indicator}",
            headers={"x-apikey": self.key, "Accept": "application/json"},
        )
        if data is None:
            return Reputation(
                self.name,
                indicator,
                "not_found",
                False,
                "No report found; this does not establish safety.",
                utc_now(),
            )
        try:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats["malicious"]
            suspicious = stats["suspicious"]
            if any(type(value) is not int or value < 0 for value in (malicious, suspicious)):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ProviderFailure("invalid_response") from None
        return Reputation(
            self.name,
            indicator,
            "reported",
            malicious >= 3,
            f"{malicious} malicious and {suspicious} suspicious engine reports; "
            "context only, not proof of compromise.",
            utc_now(),
        )


class AbuseIPDB(HTTPProvider):
    name = "AbuseIPDB"
    interval = 3.0

    def lookup(self, indicator: str, kind: str) -> Reputation:
        if kind != "ip":
            raise ProviderFailure("unsupported_indicator")
        indicator = normalize_indicator(indicator, kind)
        raw = self.request(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": indicator, "maxAgeInDays": 90},
            headers={"Key": self.key, "Accept": "application/json"},
        )
        if raw is None:
            return Reputation(
                self.name, indicator, "not_found", False, "No report found.", utc_now()
            )
        try:
            data = raw["data"]
            score, reports = data["abuseConfidenceScore"], data["totalReports"]
            if (
                type(score) is not int
                or type(reports) is not int
                or not 0 <= score <= 100
                or reports < 0
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ProviderFailure("invalid_response") from None
        return Reputation(
            self.name,
            indicator,
            "reported",
            score >= 75 and reports > 0,
            f"Abuse confidence {score}/100, {reports} reports in 90 days. "
            "Provider assessment, not a malware probability.",
            utc_now(),
        )


class MockProvider:
    name = "Local mock (SIMULATED)"
    interval = 0.0

    def lookup(self, indicator: str, kind: str) -> Reputation:
        return Reputation(
            self.name,
            indicator,
            "reported",
            indicator.endswith("9"),
            "SIMULATED adverse reputation"
            if indicator.endswith("9")
            else "SIMULATED neutral reputation",
            utc_now(),
            simulated=True,
        )


def valid_indicator(indicator: str, kind: str) -> bool:
    if kind == "sha256":
        return bool(re.fullmatch(r"[a-fA-F0-9]{64}", indicator))
    # No hostnames, scopes, URLs, private addresses, or IPv4-mapped special addresses.
    return kind == "ip" and "%" not in indicator and classify_address(indicator) == "public"


def normalize_indicator(indicator: str, kind: str) -> str:
    if not valid_indicator(indicator, kind):
        raise ValueError("Only public IP addresses or SHA-256 indicators are supported.")
    if kind == "sha256":
        return indicator.lower()
    address = ipaddress.ip_address(indicator)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def configured_provider(name: str) -> Provider:
    spec = {
        "VirusTotal": (VirusTotal, "TTP_VIRUSTOTAL_API_KEY"),
        "AbuseIPDB": (AbuseIPDB, "TTP_ABUSEIPDB_API_KEY"),
    }
    if name not in spec:
        raise ValueError("Unknown provider")
    cls, variable = spec[name]
    key = os.environ.get(variable)
    if not key:
        raise ValueError(f"Set {variable} in your environment before launching.")
    return cls(key)


class Intelligence:
    """SQLite operations run on the monitoring thread; HTTP runs on the lookup executor."""

    def __init__(self, store: Store, ttl_hours: int = 24) -> None:
        self.store, self.ttl_hours = store, ttl_hours

    def prepare(
        self, provider: Provider, indicator: str, kind: str, enabled: bool, now: float | None = None
    ) -> Reputation | None:
        if not enabled:
            raise ValueError("Enable this provider in Settings before sharing an indicator.")
        indicator = normalize_indicator(indicator, kind)
        if provider.name == "AbuseIPDB" and kind != "ip":
            raise ValueError("AbuseIPDB supports public IP addresses only.")
        now = time.time() if now is None else now
        row = self.store.db.execute(
            """SELECT expires,payload FROM reputation
            WHERE provider=? AND indicator=?""",
            (provider.name, indicator),
        ).fetchone()
        if row and row[0] > now:
            data = json.loads(row[1])
            data["cached"] = True
            return Reputation(**data)
        row = self.store.db.execute(
            "SELECT next_allowed FROM provider_limits WHERE provider=?", (provider.name,)
        ).fetchone()
        if row and row[0] > now:
            raise ValueError(f"Provider cooldown active; retry in {int(row[0] - now) + 1} seconds.")
        day = datetime.fromtimestamp(now, UTC).date().isoformat()
        if provider.name == "VirusTotal":
            daily = self.store.db.execute(
                "SELECT attempts FROM provider_daily WHERE provider=? AND day=?",
                (provider.name, day),
            ).fetchone()
            if daily and daily[0] >= 500:
                raise ValueError(
                    "VirusTotal local daily request budget reached; retry tomorrow (UTC)."
                )
        with self.store.db:
            self.store.db.execute(
                "INSERT OR REPLACE INTO provider_limits VALUES (?, ?)",
                (provider.name, now + provider.interval),
            )
            self.store.db.execute(
                """INSERT INTO provider_daily VALUES (?, ?, 1) ON CONFLICT(provider,day)
                    DO UPDATE SET attempts=attempts+1""",
                (provider.name, day),
            )
            self.store.db.execute("DELETE FROM provider_daily WHERE day < ?", (day,))
        return None

    def remember(self, result: Reputation, now: float | None = None) -> None:
        result.indicator = normalize_indicator(
            result.indicator, "sha256" if len(result.indicator) == 64 else "ip"
        )
        now = time.time() if now is None else now
        with self.store.db:
            self.store.db.execute(
                "INSERT OR REPLACE INTO reputation VALUES (?, ?, ?, ?)",
                (
                    result.provider,
                    result.indicator,
                    now + self.ttl_hours * 3600,
                    json.dumps(asdict(result)),
                ),
            )

    def failure(self, provider: str, error: ProviderFailure) -> None:
        with self.store.db:
            self.store.db.execute(
                "INSERT OR REPLACE INTO provider_limits VALUES (?, ?)",
                (provider, time.time() + error.retry_after),
            )
