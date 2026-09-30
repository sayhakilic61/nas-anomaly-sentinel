"""SQLite time-series store: one row per (timestamp, source, metric)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics ON metrics(source, metric, ts);
CREATE TABLE IF NOT EXISTS alerts (
    ts REAL NOT NULL,
    severity INTEGER NOT NULL,
    score REAL NOT NULL,
    summary TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts ON alerts(ts);
"""


class Storage:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ---- writes -----------------------------------------------------------
    def write_metrics(self, ts: float, source: str, metrics: dict[str, float]) -> None:
        rows = [(ts, source, k, float(v)) for k, v in metrics.items()]
        self.write_rows(rows)

    def write_rows(self, rows: list[tuple[float, str, str, float]]) -> None:
        with self._lock:
            self._conn.executemany(
                "INSERT INTO metrics(ts, source, metric, value) VALUES (?,?,?,?)", rows
            )
            self._conn.commit()

    def write_alert(self, ts: float, severity: int, score: float, summary: str, details: list) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts(ts, severity, score, summary, details) VALUES (?,?,?,?,?)",
                (ts, severity, score, summary, json.dumps(details, ensure_ascii=False)),
            )
            self._conn.commit()

    def prune(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            self._conn.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
            self._conn.commit()

    # ---- reads ------------------------------------------------------------
    def series(self, source: str, metric: str, since: float, until: float | None = None):
        until = until if until is not None else time.time() + 1
        with self._lock:
            cur = self._conn.execute(
                "SELECT ts, value FROM metrics WHERE source=? AND metric=? AND ts>=? AND ts<? ORDER BY ts",
                (source, metric, since, until),
            )
            return cur.fetchall()

    def value_near(self, source: str, metric: str, ts: float, tolerance: float) -> float | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM metrics WHERE source=? AND metric=? AND ts BETWEEN ? AND ? "
                "ORDER BY ABS(ts - ?) LIMIT 1",
                (source, metric, ts - tolerance, ts + tolerance, ts),
            )
            row = cur.fetchone()
        return row[0] if row else None

    def sources(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._conn.execute("SELECT DISTINCT source FROM metrics ORDER BY source")]

    def metrics_for(self, source: str) -> list[str]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT DISTINCT metric FROM metrics WHERE source=? ORDER BY metric", (source,)
            )
            return [r[0] for r in cur]

    def worst_alert_since(self, since: float) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT ts, severity, score, summary FROM alerts WHERE ts>=? ORDER BY severity DESC, ts DESC LIMIT 1",
                (since,),
            ).fetchone()
        return {"ts": row[0], "severity": row[1], "score": row[2], "summary": row[3]} if row else None

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT ts, severity, score, summary, details FROM alerts ORDER BY ts DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {"ts": r[0], "severity": r[1], "score": r[2], "summary": r[3], "details": json.loads(r[4])}
            for r in rows
        ]
