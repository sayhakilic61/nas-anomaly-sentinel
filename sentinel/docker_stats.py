"""Per-container CPU / disk-write / network-out rates via the Docker API.

Talks to a read-only docker-socket-proxy (see docker-compose.yml), never to the
raw socket with write access.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("sentinel.docker")


def cpu_percent(s: dict) -> float:
    cpu, pre = s.get("cpu_stats", {}), s.get("precpu_stats", {})
    cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
    sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    online = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or []) or 1
    return (cpu_delta / sys_delta) * online * 100.0 if sys_delta > 0 and cpu_delta > 0 else 0.0


def blk_write_bytes(s: dict) -> int:
    entries = (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
    return sum(e.get("value", 0) for e in entries if str(e.get("op", "")).lower() == "write")


def net_tx_bytes(s: dict) -> int:
    return sum(n.get("tx_bytes", 0) for n in (s.get("networks") or {}).values())


class DockerStats:
    def __init__(self):
        import docker  # imported lazily so the scanner works without the SDK

        self.client = docker.from_env(timeout=15)
        self._prev: dict[str, tuple[float, int, int]] = {}

    def collect(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        try:
            containers = self.client.containers.list()
        except Exception as exc:
            log.error("Docker API unavailable: %s", exc)
            return out
        for c in containers:
            try:
                s = c.stats(stream=False)
            except Exception:
                continue
            now = time.time()
            w, tx = blk_write_bytes(s), net_tx_bytes(s)
            prev = self._prev.get(c.name)
            self._prev[c.name] = (now, w, tx)
            if prev is None:
                continue
            dt = max(now - prev[0], 1.0)
            out[f"ctr:{c.name}"] = {
                "cpu_pct": cpu_percent(s),
                "mem_mb": (s.get("memory_stats") or {}).get("usage", 0) / 1e6,
                "blk_write_mb_per_h": max(w - prev[1], 0) / 1e6 * 3600 / dt,
                "net_tx_mb_per_h": max(tx - prev[2], 0) / 1e6 * 3600 / dt,
            }
        return out
