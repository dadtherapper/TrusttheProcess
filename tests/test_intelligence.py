from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from trust_the_process.intelligence import (
    AbuseIPDB,
    Intelligence,
    MockProvider,
    ProviderFailure,
    VirusTotal,
    valid_indicator,
)
from trust_the_process.storage import Store


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "192.168.1.1",
        "fe80::1",
        "224.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
        "192.0.2.1",
        "::ffff:127.0.0.1",
        "8.8.8.8%zone",
        "8.8.8.8/path",
    ],
)
def test_sensitive_or_invalid_indicators_never_sent(address):
    assert not valid_indicator(address, "ip")


def response(status=200, payload=None, headers=None):
    return SimpleNamespace(status_code=status, headers=headers or {}, json=lambda: payload)


def test_virustotal_get_only_and_not_found():
    get = Mock(
        return_value=response(
            payload={
                "data": {"attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 2}}}
            }
        )
    )
    provider = VirusTotal("secret", get)
    result = provider.lookup("a" * 64, "sha256")
    assert result.flagged and result.provider == "VirusTotal"
    args, kwargs = get.call_args
    assert args[0].endswith("/files/" + "a" * 64)
    assert kwargs["headers"]["x-apikey"] == "secret" and kwargs["timeout"] == (3, 7)
    assert not kwargs["allow_redirects"]
    assert "data" not in kwargs and "files" not in kwargs
    get.return_value = response(404)
    result = provider.lookup("8.8.8.8", "ip")
    assert result.status == "not_found" and not result.flagged and "safety" in result.summary


def test_abuse_response_and_threshold():
    get = Mock(
        return_value=response(payload={"data": {"abuseConfidenceScore": 90, "totalReports": 3}})
    )
    result = AbuseIPDB("secret", get).lookup("8.8.8.8", "ip")
    assert result.flagged and "90/100" in result.summary
    assert get.call_args.kwargs["params"] == {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
    get.return_value = response(payload={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    assert not AbuseIPDB("secret", get).lookup("8.8.8.8", "ip").flagged


@pytest.mark.parametrize("code", [401, 403, 500, 302])
def test_http_failures_do_not_create_reputation(code):
    provider = VirusTotal("secret", Mock(return_value=response(code)))
    with pytest.raises(ProviderFailure, match=f"http_{code}"):
        provider.lookup("8.8.8.8", "ip")


def test_timeout_and_malformed_json():
    for get in (
        Mock(side_effect=requests.Timeout("secret")),
        Mock(return_value=response(payload=[])),
        Mock(return_value=response(payload={})),
    ):
        with pytest.raises(ProviderFailure) as error:
            VirusTotal("secret", get).lookup("8.8.8.8", "ip")
        assert "secret" not in str(error.value)


def test_429_cache_optin_and_persistent_rate_limits(tmp_path):
    store = Store(tmp_path / "reputation.db")
    intelligence = Intelligence(store)
    provider = VirusTotal(
        "secret", Mock(return_value=response(429, headers={"Retry-After": "120"}))
    )
    try:
        with pytest.raises(ValueError, match="Enable"):
            intelligence.prepare(provider, "8.8.8.8", "ip", False, now=100)
        provider.get.assert_not_called()
        assert intelligence.prepare(provider, "8.8.8.8", "ip", True, now=100) is None
        with pytest.raises(ValueError, match="cooldown"):
            intelligence.prepare(provider, "1.1.1.1", "ip", True, now=101)
        with pytest.raises(ProviderFailure) as failure:
            provider.lookup("8.8.8.8", "ip")
        assert failure.value.retry_after == 120
        intelligence.failure(provider.name, failure.value)
        result = MockProvider().lookup("8.8.8.8", "ip")
        result.provider, result.simulated = provider.name, False
        intelligence.remember(result, now=100)
        assert intelligence.prepare(provider, "8.8.8.8", "ip", True, now=101).cached
        with pytest.raises(ValueError, match="Enable"):
            intelligence.prepare(provider, "8.8.8.8", "ip", False, now=101)
        store.close()
        store = Store(tmp_path / "reputation.db")
        assert Intelligence(store).prepare(provider, "8.8.8.8", "ip", True, now=102).cached
        assert store.db.execute("SELECT next_allowed FROM provider_limits").fetchone()[0] > 120
    finally:
        store.close()


def test_mock_is_local_and_explicit():
    result = MockProvider().lookup("9.9.9.9", "ip")
    assert result.flagged and result.simulated and "SIMULATED" in result.summary


def test_cache_expiry_and_daily_budget():
    store = Store(":memory:")
    try:
        intelligence = Intelligence(store, ttl_hours=1)
        provider = VirusTotal("unused", Mock())
        result = MockProvider().lookup("8.8.8.8", "ip")
        result.provider = provider.name
        intelligence.remember(result, now=0)
        assert intelligence.prepare(provider, "8.8.8.8", "ip", True, now=3599).cached
        assert intelligence.prepare(provider, "8.8.8.8", "ip", True, now=3601) is None
        with store.db:
            store.db.execute("UPDATE provider_daily SET attempts=500")
        with pytest.raises(ValueError, match="daily"):
            intelligence.prepare(provider, "1.1.1.1", "ip", True, now=3620)
        assert intelligence.prepare(provider, "1.1.1.1", "ip", True, now=86401) is None
        provider.get.assert_not_called()
    finally:
        store.close()


def test_abuse_rejects_hashes_before_request():
    store = Store(":memory:")
    provider = AbuseIPDB("unused", Mock())
    try:
        with pytest.raises(ValueError, match="IP addresses only"):
            Intelligence(store).prepare(provider, "a" * 64, "sha256", True)
        provider.get.assert_not_called()
    finally:
        store.close()
