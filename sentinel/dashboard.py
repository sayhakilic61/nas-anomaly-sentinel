"""Tiny read-only dashboard: status, 30-day series with the "usual" band, alert log."""
from __future__ import annotations

import json
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .storage import Storage

STATE: dict = {"status": 0, "score": 0.0, "summary": "", "last_scan": None, "findings": []}
STATIC = Path(__file__).parent / "static"
INDEX_HTML = (STATIC / "index.html").read_text(encoding="utf-8")
CHART_JS = (STATIC / "chart.umd.js").read_bytes()  # vendored Chart.js 4.4.1 (MIT) - works offline


def hourly_profile(rows: list[tuple[float, float]]) -> dict[str, list[float | None]]:
    buckets: dict[int, list[float]] = {h: [] for h in range(24)}
    for ts, v in rows:
        buckets[time.localtime(ts).tm_hour].append(v)
    p10, med, p90 = [], [], []
    for h in range(24):
        vals = sorted(buckets[h])
        if len(vals) < 5:
            p10.append(None), med.append(None), p90.append(None)
            continue
        q = statistics.quantiles(vals, n=10)
        p10.append(q[0]), med.append(statistics.median(vals)), p90.append(q[-1])
    return {"p10": p10, "median": med, "p90": p90}


def make_handler(store: Storage, baseline_days: int):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep container logs clean
            pass

        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj):
            self._send(200, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self):
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path in ("/", "/index.html"):
                return self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            if url.path == "/static/chart.umd.js":
                return self._send(200, CHART_JS, "application/javascript")
            if url.path == "/api/status":
                return self._json(STATE)
            if url.path == "/api/sources":
                return self._json({s: store.metrics_for(s) for s in store.sources()})
            if url.path == "/api/series":
                source, metric = q.get("source", ""), q.get("metric", "")
                days = min(int(q.get("days", "7")), baseline_days)
                now = time.time()
                rows = store.series(source, metric, now - days * 86400)
                base = store.series(source, metric, now - baseline_days * 86400)
                step = max(1, len(rows) // 2000)  # keep the chart light
                pts = rows[::step]
                prof = hourly_profile(base)
                # Band is resolved per point with the SERVER clock, i.e. exactly the
                # hour buckets the detector uses - no browser/container timezone drift.
                band = [[prof["p10"][time.localtime(ts).tm_hour], prof["p90"][time.localtime(ts).tm_hour]]
                        for ts, _ in pts]
                return self._json({"points": pts, "band": band})
            if url.path == "/api/alerts":
                return self._json(store.recent_alerts(int(q.get("limit", "30"))))
            self._send(404, b"not found", "text/plain")

    return Handler


def start(store: Storage, port: int, baseline_days: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(store, baseline_days))
    threading.Thread(target=server.serve_forever, daemon=True, name="dashboard").start()
    return server
