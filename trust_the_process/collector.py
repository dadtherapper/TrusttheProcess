"""Read-only host collection and bounded asynchronous executable hashing."""

from __future__ import annotations

import hashlib
import os
import stat
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor

import psutil

from .models import Process, Snapshot, clean, utc_now
from .network import ConnectionTracker, NetworkAdapter, PsutilNetwork


class HashCache:
    def __init__(self) -> None:
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ttp-hash")
        self.pending: dict[str, Future] = {}
        self.cache: OrderedDict[str, tuple[float, str | None]] = OrderedDict()
        self.stop = threading.Event()

    @staticmethod
    def fingerprint(path: str) -> str | None:
        if path.startswith(("\\\\", "//")):
            return None
        try:
            metadata = os.stat(path)
            if not stat.S_ISREG(metadata.st_mode):
                return None
            return f"{metadata.st_size}:{metadata.st_mtime_ns}:{metadata.st_ino}"
        except OSError:
            return None

    def _hash(self, path: str, fingerprint: str) -> str | None:
        try:
            # Do not hash devices, network paths, or arbitrarily large binaries.
            if path.startswith(("\\\\", "//")) or os.path.getsize(path) > 512 * 1024 * 1024:
                return None
            value = hashlib.sha256()
            with open(path, "rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    if self.stop.is_set():
                        return None
                    value.update(chunk)
            return value.hexdigest() if self.fingerprint(path) == fingerprint else None
        except OSError:
            return None

    def get(self, path: str, fingerprint: str | None) -> str | None:
        # Reap completed jobs even if their processes have since exited.
        for completed in [k for k, future in self.pending.items() if future.done()]:
            self.cache[completed] = (time.monotonic(), self.pending.pop(completed).result())
        while len(self.cache) > 2048:
            self.cache.popitem(last=False)
        if not fingerprint:
            return None
        key = path + "|" + fingerprint
        if key in self.pending and self.pending[key].done():
            future = self.pending.pop(key)
            self.cache[key] = (time.monotonic(), future.result())
        cached = self.cache.get(key)
        if cached and (cached[1] or time.monotonic() - cached[0] < 300):
            self.cache.move_to_end(key)
            return cached[1]
        if key not in self.pending and len(self.pending) < 64 and not self.stop.is_set():
            self.pending[key] = self.pool.submit(self._hash, path, fingerprint)
        while len(self.cache) > 2048:
            self.cache.popitem(last=False)
        return None

    def close(self) -> None:
        self.stop.set()
        self.pool.shutdown(wait=True, cancel_futures=True)


class HostCollector:
    source = "psutil socket snapshot"

    def __init__(self, network: NetworkAdapter | None = None) -> None:
        self.network = network or PsutilNetwork()
        self.hashes = HashCache()
        self.tracker = ConnectionTracker()
        self.cpu_seen: set[str] = set()
        self.iteration = 0
        self.system_primed = False
        self.last_observed: float | None = None
        self.session = uuid.uuid4().hex

    def resume(self) -> None:
        self.tracker = ConnectionTracker()
        self.cpu_seen.clear()
        self.system_primed = False
        self.last_observed = None

    def collect(self) -> Snapshot:
        observed = time.monotonic()
        interval = observed - self.last_observed if self.last_observed is not None else None
        self.iteration += 1
        timestamp = utc_now()
        processes = []
        fingerprints: dict[str, str | None] = {}
        for raw in psutil.process_iter():
            missing = []

            def read(name: str, raw=raw, missing=missing):
                try:
                    return getattr(raw, name)()
                except psutil.NoSuchProcess:
                    raise
                except (psutil.AccessDenied, OSError, ValueError, NotImplementedError):
                    missing.append(name)
                    return None

            try:
                with raw.oneshot():
                    started = read("create_time")
                    name = read("name")
                    exe = read("exe") or None
                    if exe and clean(exe) != exe:
                        missing.append("executable path display was sanitized")
                    cmd = read("cmdline")
                    memory = read("memory_info")
                    p = Process(
                        pid=raw.pid,
                        started=started,
                        name=clean(name or "Unavailable"),
                        ppid=read("ppid"),
                        exe=exe,
                        command=clean(" ".join(cmd)) if cmd else None,
                        username=clean(read("username") or "") or None,
                        cpu=read("cpu_percent"),
                        rss=memory.rss if memory else None,
                        memory_percent=read("memory_percent"),
                        status=read("status"),
                        limitations=missing,
                        unknown_token=f"unknown-{self.session}-{self.iteration}",
                    )
                if p.key not in self.cpu_seen:
                    p.cpu = None  # psutil's first non-blocking sample has no interval.
                if exe:
                    if exe not in fingerprints:
                        fingerprints[exe] = self.hashes.fingerprint(exe)
                    p.file_identity = fingerprints[exe]
                    p.sha256 = self.hashes.get(exe, p.file_identity)
                processes.append(p)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        self.cpu_seen = {p.key for p in processes}
        by_pid = {p.pid: p for p in processes}
        for p in processes:
            parent = by_pid.get(p.ppid)
            if parent and p.started is not None and parent.started is not None:
                if parent.started <= p.started:
                    p.parent_identity, p.parent_key = parent.identity, parent.key
        limitations = []
        try:
            connections = self.network.collect(by_pid, timestamp)
            self.tracker.update(connections, processes)
            network_available = True
        except (psutil.Error, OSError) as error:
            connections = []
            network_available = False
            self.tracker = ConnectionTracker()
            limitations.append(f"Network snapshot unavailable ({type(error).__name__}).")
        system_cpu = psutil.cpu_percent()
        previous_system_sample = self.system_primed
        self.system_primed = True
        self.last_observed = observed
        return Snapshot(
            timestamp,
            processes,
            connections,
            self.network.source,
            system_cpu=system_cpu if previous_system_sample else None,
            system_memory=psutil.virtual_memory().percent,
            network_available=network_available,
            limitations=limitations,
            interval_seconds=interval,
        )

    def close(self) -> None:
        self.hashes.close()
