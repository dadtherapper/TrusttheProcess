from __future__ import annotations

import hashlib
import socket
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

import psutil
import pytest

from trust_the_process.collector import HashCache, HostCollector
from trust_the_process.models import Connection, Process
from trust_the_process.network import ConnectionTracker, PsutilNetwork, classify_address


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (None, "none"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("192.168.0.2", "private"),
        ("10.0.0.2", "private"),
        ("fc00::1", "private"),
        ("169.254.1.1", "link-local"),
        ("fe80::1%3", "link-local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),
        ("8.8.8.8", "public"),
        ("2606:4700:4700::1111", "public"),
        ("100.64.0.1", "special"),
        ("::ffff:127.0.0.1", "loopback"),
        ("not-an-ip", "invalid"),
        ("https://8.8.8.8", "invalid"),
    ],
)
def test_address_classification(address, expected):
    assert classify_address(address) == expected


def mock_process(pid=123, created=1000.0):
    raw = MagicMock()
    raw.pid = pid
    raw.oneshot.side_effect = nullcontext
    raw.create_time.return_value = created
    raw.name.return_value = "app.exe"
    raw.exe.return_value = ""
    raw.cmdline.return_value = ["app.exe", "--flag"]
    raw.memory_info.return_value = SimpleNamespace(rss=1234)
    raw.ppid.return_value = 1
    raw.username.return_value = "test-user"
    raw.cpu_percent.return_value = 5.0
    raw.memory_percent.return_value = 0.2
    raw.status.return_value = "running"
    return raw


def test_collection_permission_exit_and_pid_reuse(monkeypatch):
    raw = mock_process()
    raw.exe.side_effect = psutil.AccessDenied(123)
    raw.cmdline.side_effect = psutil.AccessDenied(123)
    dead = mock_process(124)
    dead.name.side_effect = psutil.NoSuchProcess(124)
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([raw, dead]))
    network = MagicMock(source="test")
    network.collect.return_value = []
    collector = HostCollector(network)
    try:
        first = collector.collect().processes
        assert len(first) == 1
        assert first[0].exe is None and first[0].command is None
        assert "exe" in first[0].limitations and first[0].cpu is None
        assert collector.collect().processes[0].cpu == 5.0
        raw.create_time.return_value = 2000.0
        reused = collector.collect().processes[0]
        assert reused.key != first[0].key and reused.cpu is None
        collector.resume()
        resumed = collector.collect()
        assert resumed.system_cpu is None and resumed.processes[0].cpu is None
    finally:
        collector.close()


def test_missing_creation_time_never_reuses_lifetime(monkeypatch):
    raw = mock_process()
    raw.create_time.side_effect = psutil.AccessDenied(123)
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([raw]))
    network = MagicMock(source="test")
    network.collect.return_value = []
    collector = HostCollector(network)
    try:
        a, b = collector.collect(), collector.collect()
        assert a.processes[0].key != b.processes[0].key
    finally:
        collector.close()


def test_network_permission_does_not_fabricate_zero(monkeypatch):
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([mock_process()]))
    network = MagicMock(source="test")
    network.collect.side_effect = psutil.AccessDenied()
    collector = HostCollector(network)
    try:
        snapshot = collector.collect()
        assert not snapshot.network_available
        assert snapshot.processes[0].connections is None
        assert snapshot.limitations
    finally:
        collector.close()


def socket_row(pid=123, udp=False, ipv6=False):
    return SimpleNamespace(
        pid=pid,
        type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,
        family=socket.AF_INET6 if ipv6 else socket.AF_INET,
        laddr=("::" if ipv6 else "0.0.0.0", 50),
        raddr=() if udp else ("8.8.8.8", 443),
        status="NONE" if udp else "ESTABLISHED",
    )


def test_network_normalization_and_reused_pid(monkeypatch, process):
    monkeypatch.setattr(
        psutil, "net_connections", lambda kind: [socket_row(), socket_row(999, True, True)]
    )
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1000.0))
    rows = PsutilNetwork().collect({123: process}, "t")
    assert rows[0].process_key == process.key and rows[0].remote_port == 443
    assert rows[0].protocol == "TCP4" and rows[0].address_class == "public"
    assert rows[1].protocol == "UDP6" and rows[1].remote_ip is None
    assert rows[1].process_key is None
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 2000.0))
    assert PsutilNetwork().collect({123: process}, "t")[0].process_key is None


def test_socket_episode_and_new_counts(process):
    def connection(stamp, port=3000):
        return Connection(
            "TCP4",
            "10.0.0.2",
            port,
            "8.8.8.8",
            443,
            "ESTABLISHED",
            123,
            process.key,
            process.name,
            "public",
            stamp,
            stamp,
        )

    tracker = ConnectionTracker()
    first = connection("a")
    tracker.update([first], [process])
    assert process.new_connections == 0  # existing sockets are not new at application start
    second, new = connection("b"), connection("b", 4000)
    tracker.update([second, new], [process])
    assert second.first_seen == "a" and second.last_seen == "b"
    assert new.new and process.new_connections == 1
    assert process.connections == 2 and process.destinations == ["8.8.8.8"]
    tracker.update([], [process])
    third = connection("c")
    tracker.update([third], [process])
    assert third.new and third.first_seen == "c"


def test_hash_cache_and_changed_file(tmp_path):
    path = tmp_path / "binary.exe"
    path.write_bytes(b"first")
    cache = HashCache()
    try:
        identity = cache.fingerprint(str(path))
        assert cache.get(str(path), identity) is None
        key = str(path) + "|" + identity
        cache.pending[key].result(timeout=5)
        assert cache.get(str(path), identity) == hashlib.sha256(b"first").hexdigest()
        assert key not in cache.pending
        path.write_bytes(b"different contents")
        changed = cache.fingerprint(str(path))
        assert changed != identity
        assert cache.get(str(path), changed) is None
        cache.pending[str(path) + "|" + changed].result(timeout=5)
        assert cache.get(str(path), changed) == hashlib.sha256(b"different contents").hexdigest()
        assert cache.fingerprint(str(tmp_path / "missing")) is None
    finally:
        cache.close()


def test_file_and_process_identity_are_distinct(process):
    other = Process(**{**process.__dict__, "pid": 999, "started": 2000})
    assert process.identity == other.identity and process.key != other.key
    other.file_identity = "updated-file"
    assert process.identity != other.identity


def test_missing_creation_times_are_unique_across_collector_sessions(monkeypatch):
    raw = mock_process()
    raw.create_time.side_effect = psutil.AccessDenied(123)
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([raw]))
    network = MagicMock(source="test")
    network.collect.return_value = []
    a, b = HostCollector(network), HostCollector(network)
    try:
        assert a.collect().processes[0].key != b.collect().processes[0].key
    finally:
        a.close()
        b.close()


def test_analysis_keeps_the_real_executable_path(monkeypatch):
    from trust_the_process.baseline import Baselines
    from trust_the_process.config import Config
    from trust_the_process.detection import Detector

    raw = mock_process()
    path = "C:\\Windows\\Sys\u202etem32\\lsass.exe"
    raw.exe.return_value = path
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([raw]))
    network = MagicMock(source="test")
    network.collect.return_value = []
    collector = HostCollector(network)
    monkeypatch.setattr(collector.hashes, "fingerprint", lambda _: "file-identity")
    monkeypatch.setattr(collector.hashes, "get", lambda *_: None)
    try:
        snapshot = collector.collect()
        snapshot.simulated = True
        assert snapshot.processes[0].exe == path
        assert "EXEC-SYSTEM" in {
            f.rule_id for f in Detector(Config(), Baselines(Config())).evaluate(snapshot)
        }
    finally:
        collector.close()


def test_failed_socket_ownership_stays_unavailable(monkeypatch, process):
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [socket_row()])

    def inaccessible(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(psutil, "Process", inaccessible)
    rows = PsutilNetwork().collect({process.pid: process}, "now")
    ConnectionTracker().update(rows, [process])
    assert rows[0].process_key is None and process.connections is None
