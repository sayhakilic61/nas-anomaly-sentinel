"""Anomaly detection.

Two layers, deliberately simple and explainable:

1. **Rules** (active from minute one, no history needed)
   ransom notes, known ransomware extensions, bulk extension changes,
   magic-byte mismatches, high-entropy text files.

2. **Statistical baseline** (active after MIN_BASELINE_DAYS of history)
   For each metric, take the last 30 days of values recorded at the *same hour
   of day* (+/- HOUR_WINDOW), compute median and MAD, and score the current value
   with a robust z-score:  z = 0.6745 * (x - median) / MAD.
   Using the same hour means the nightly backup at 02:00 is "normal", while the
   same write volume at 14:00 on a Sunday is not.

   Volume anomalies alone are WARNINGs; they become CRITICAL when writes and
   deletions/overwrites spike together (encrypt-and-replace pattern).

   A separate daily check compares today's total growth with the last 30 daily
   growths ("is this the usual growth?").
"""
from __future__ import annotations

import statistics
import time
from dataclasses import asdict, dataclass, field

from .storage import Storage

OK, WARNING, CRITICAL = 0, 1, 2

# metric -> minimum absolute excess over the median before we care.
# Stops alerts like "3 files instead of the usual 0".
STAT_METRICS: dict[str, float] = {
    "created_per_h": 60.0,
    "modified_per_h": 120.0,
    "deleted_per_h": 60.0,
    "written_mb_per_h": 250.0,
    "growth_mb_per_h": 500.0,
    # container metrics
    "cpu_pct": 40.0,
    "blk_write_mb_per_h": 500.0,
    "net_tx_mb_per_h": 500.0,
}
DAILY_GROWTH_MIN_GB = 2.0


@dataclass
class Finding:
    source: str
    kind: str            # rule | stat | daily | correlated
    metric: str
    severity: int
    value: float
    median: float | None = None
    z: float | None = None
    examples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def robust_z(value: float, history: list[float], min_delta: float) -> tuple[float, float]:
    """Return (median, z). MAD is floored so flat histories don't explode."""
    med = statistics.median(history)
    mad = statistics.median([abs(h - med) for h in history])
    mad = max(mad, 0.05 * abs(med), min_delta / 10.0, 1e-9)
    return med, 0.6745 * (value - med) / mad


def _hour_distance(a: int, b: int) -> int:
    d = abs(a - b) % 24
    return min(d, 24 - d)


class Detector:
    def __init__(self, store: Storage, cfg):
        self.store = store
        self.cfg = cfg

    # ------------------------------------------------------------------
    def rules(self, source: str, metrics: dict[str, float], samples: dict[str, list[str]]) -> list[Finding]:
        c = self.cfg
        out: list[Finding] = []

        def add(metric: str, threshold: float):
            v = metrics.get(metric, 0.0)
            if v >= threshold:
                out.append(Finding(source, "rule", metric, CRITICAL, v, examples=samples.get(metric, [])))

        add("ransom_notes", 1)
        add("ransom_ext", c.rule_ransom_ext)
        add("ext_changed", c.rule_ext_changed)
        add("magic_mismatch", c.rule_magic_mismatch)
        if metrics.get("high_entropy", 0) >= c.rule_high_entropy and metrics.get("high_entropy_ratio", 0) >= 0.5:
            out.append(Finding(source, "rule", "high_entropy", CRITICAL, metrics["high_entropy"],
                               examples=samples.get("high_entropy", [])))
        return out

    # ------------------------------------------------------------------
    def _baseline(self, source: str, metric: str, now: float) -> list[float] | None:
        since = now - self.cfg.baseline_days * 86400
        rows = self.store.series(source, metric, since, until=now - 1)
        if not rows:
            return None
        days = {int(ts // 86400) for ts, _ in rows}
        if len(days) < self.cfg.min_baseline_days:
            return None
        hour = time.localtime(now).tm_hour
        same_hour = [v for ts, v in rows if _hour_distance(time.localtime(ts).tm_hour, hour) <= self.cfg.hour_window]
        return same_hour if len(same_hour) >= 10 else None

    def statistical(self, source: str, metrics: dict[str, float], now: float) -> list[Finding]:
        out: list[Finding] = []
        for metric, min_delta in STAT_METRICS.items():
            if metric not in metrics:
                continue
            history = self._baseline(source, metric, now)
            if history is None:
                continue
            value = metrics[metric]
            med, z = robust_z(value, history, min_delta)
            if value - med < min_delta:
                continue
            if z < self.cfg.z_warning:
                continue
            # Volume alone is only "unusual" (a big legit copy looks the same).
            # Mass deletion far outside the norm is destructive on its own.
            sev = CRITICAL if (metric == "deleted_per_h" and z >= self.cfg.z_critical) else WARNING
            out.append(Finding(source, "stat", metric, sev, value, med, z))
        # Destructive pattern: lots written AND lots deleted/overwritten at the same time
        # (encrypt-and-replace). A bulk copy only writes/creates, so it stays a WARNING.
        deviating = {f.metric for f in out}
        writes = deviating & {"written_mb_per_h", "created_per_h", "blk_write_mb_per_h"}
        destroys = deviating & {"deleted_per_h", "modified_per_h"}
        if writes and destroys and all(f.severity < CRITICAL for f in out):
            out.append(Finding(source, "correlated", "correlated", CRITICAL, float(len(out))))
        return out

    def daily_growth(self, source: str, metrics: dict[str, float], now: float) -> list[Finding]:
        if "total_gb" not in metrics:
            return []
        tol = 3600.0
        day = 86400.0
        yesterday = self.store.value_near(source, "total_gb", now - day, tol)
        if yesterday is None:
            return []
        today_growth = metrics["total_gb"] - yesterday
        past = []
        for k in range(1, self.cfg.baseline_days):
            a = self.store.value_near(source, "total_gb", now - k * day, tol)
            b = self.store.value_near(source, "total_gb", now - (k + 1) * day, tol)
            if a is not None and b is not None:
                past.append(a - b)
        if len(past) < self.cfg.min_baseline_days:
            return []
        med, z = robust_z(today_growth, past, DAILY_GROWTH_MIN_GB)
        if today_growth - med < DAILY_GROWTH_MIN_GB or z < self.cfg.z_warning:
            return []
        return [Finding(source, "daily", "daily_growth_gb", WARNING, today_growth, med, z)]

    # ------------------------------------------------------------------
    def evaluate(self, source: str, metrics: dict[str, float], samples: dict[str, list[str]] | None = None,
                 now: float | None = None) -> list[Finding]:
        now = now if now is not None else time.time()
        return (
            self.rules(source, metrics, samples or {})
            + self.statistical(source, metrics, now)
            + self.daily_growth(source, metrics, now)
        )


def score(findings: list[Finding]) -> tuple[int, float]:
    """Overall (status, score). Score bands match the status so they never disagree:
    OK = 0, WARNING = 30-69, CRITICAL = 70-100."""
    if not findings:
        return OK, 0.0
    status = max(f.severity for f in findings)
    top = [f for f in findings if f.severity == status]
    extra = sum(min(f.z or 5.0, 20.0) for f in top) + 5.0 * (len(top) - 1)
    if status == CRITICAL:
        return status, min(100.0, 70.0 + extra)
    return status, min(69.0, 30.0 + extra)
