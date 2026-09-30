"""Seed N days of realistic history so the statistical baseline works immediately.

Only seed the demo sandbox! Seeding a real share would teach the detector
fake "normal" behaviour; real shares learn from real data (7-30 days).

Pattern: busy weekday office hours, quiet nights and weekends, and a nightly
backup burst at 02:00. The detector learns that the 02:00 burst is normal.

    python -m sentinel.seed --days 30
"""
from __future__ import annotations

import argparse
import math
import os
import random
import time

from . import config
from .storage import Storage


def activity(ts: float) -> float:
    lt = time.localtime(ts)
    weekday = lt.tm_wday < 5
    h = lt.tm_hour
    if weekday and 9 <= h < 18:
        return 1.0
    if 7 <= h < 23:
        return 0.3 if weekday else 0.15
    return 0.04


def dir_size_gb(path: str) -> float:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total / 1e9


def generate(source: str, days: int, step: int, scale: float, end_gb: float, rng: random.Random,
             now: float | None = None):
    now = now if now is not None else time.time()
    start = now - days * 86400
    ts_list = [start + i * step for i in range(int(days * 86400 / step))]
    per_h = 3600.0 / step

    raw_growth = []
    rows = []
    for ts in ts_list:
        a = activity(ts)
        noise = lambda: rng.lognormvariate(0, 0.35)  # noqa: E731
        created = max(0.0, a * 25 * scale * noise())
        modified = max(0.0, a * 50 * scale * noise())
        deleted = max(0.0, a * 6 * scale * noise())
        written = a * 30 * scale * noise()
        if time.localtime(ts).tm_hour == 2:  # nightly backup job
            written += 400 * scale * noise()
            created += 60 * scale * noise()
        raw_growth.append(max(0.0, a * noise()))
        rows.append([ts, created, modified, deleted, written])

    # Scale growth so the share grew ~25% over the period and ends at end_gb.
    total_growth_gb = end_gb * 0.25 if end_gb > 0 else 0.01
    g_sum = sum(raw_growth) or 1.0
    growth_gb = [g / g_sum * total_growth_gb for g in raw_growth]
    total = end_gb - total_growth_gb

    out = []
    for (ts, created, modified, deleted, written), g in zip(rows, growth_gb):
        total += g
        metrics = {
            "total_gb": total,
            "growth_mb_per_h": g * 1000 * per_h,  # GB in this step -> MB per hour
            "created_per_h": created,
            "modified_per_h": modified,
            "deleted_per_h": deleted,
            "written_mb_per_h": written,
            "ext_changed": float(rng.random() < 0.01),
            "ransom_ext": 0.0,
            "ransom_notes": 0.0,
            "magic_mismatch": 0.0,
            "high_entropy": 0.0,
            "high_entropy_ratio": 0.0,
        }
        out.extend((ts, source, k, v) for k, v in metrics.items())
    return out


def generate_container(source: str, days: int, step: int, rng: random.Random, now: float | None = None):
    now = now if now is not None else time.time()
    start = now - days * 86400
    out = []
    for i in range(int(days * 86400 / step)):
        ts = start + i * step
        a = activity(ts)
        m = {
            "cpu_pct": 2 + 10 * a * rng.lognormvariate(0, 0.4),
            "mem_mb": 180 + 20 * math.sin(i / 50) + rng.random() * 5,
            "blk_write_mb_per_h": 20 * a * rng.lognormvariate(0, 0.5),
            "net_tx_mb_per_h": 40 * a * rng.lognormvariate(0, 0.5),
        }
        out.extend((ts, source, k, v) for k, v in m.items())
    return out


def main() -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--step", type=int, default=300, help="seconds between synthetic samples")
    ap.add_argument("--scale", type=float, default=1.0, help="activity multiplier (1.0 = small office share)")
    ap.add_argument("--container", default="", help="also seed a fake container source, e.g. ctr:nextcloud")
    ap.add_argument("--only", default="", help="comma-separated share names to seed (default: all)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    store = Storage(cfg.db_path)
    rng = random.Random(args.seed)
    only = {n.strip() for n in args.only.split(",") if n.strip()}
    for name, path in cfg.watch_paths.items():
        if only and name not in only:
            continue
        end_gb = dir_size_gb(path) if os.path.isdir(path) else 0.05
        rows = generate(name, args.days, args.step, args.scale, end_gb, rng)
        store.write_rows(rows)
        print(f"[{name}] seeded {len(rows):,} rows over {args.days} days (current size {end_gb:.3f} GB)")
    if args.container:
        rows = generate_container(args.container, args.days, args.step, rng)
        store.write_rows(rows)
        print(f"[{args.container}] seeded {len(rows):,} rows")


if __name__ == "__main__":
    main()
