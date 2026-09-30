"""NAS Anomaly Sentinel - main loop."""
from __future__ import annotations

import logging
import os
import signal
import time

from . import alerts, config, dashboard
from .detector import Detector, score
from .scanner import Scanner
from .storage import Storage

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("sentinel")
_running = True


def _stop(*_):
    global _running
    _running = False


def run_once(cfg, store, detector, alerter, scanners, docker_stats=None) -> list:
    now = time.time()
    findings = []
    for sc in scanners:
        t0 = time.time()
        res = sc.scan(now)
        if res is None:
            log.info("[%s] baseline snapshot taken (%.1fs)", sc.name, time.time() - t0)
            continue
        findings += detector.evaluate(sc.name, res.metrics, res.samples, now)
        store.write_metrics(now, sc.name, res.metrics)
        log.info("[%s] scan %.1fs files=%d created/h=%.0f written=%.1fMB/h",
                 sc.name, time.time() - t0, res.metrics["file_count"],
                 res.metrics["created_per_h"], res.metrics["written_mb_per_h"])
    if docker_stats:
        for source, metrics in docker_stats.collect().items():
            findings += detector.evaluate(source, metrics, None, now)
            store.write_metrics(now, source, metrics)

    status, sc_value = score(findings)
    lang = cfg.alert_lang
    summary = alerts.summarize(findings, lang)
    if alerter.dispatch(status, sc_value, findings, now):
        store.write_alert(now, status, sc_value, summary, [alerts.describe(f, lang) for f in findings])
        log.warning("ALERT %s: %s", status, summary)

    # The dashboard keeps showing the worst alert of the last hour, so a burst that
    # is over by the next scan does not silently turn the page green again.
    shown = {"status": status, "score": sc_value, "summary": summary}
    worst = store.worst_alert_since(now - 3600)
    if worst and worst["severity"] > status:
        shown = {"status": worst["severity"], "score": worst["score"], "summary": worst["summary"]}
    dashboard.STATE.update(**shown, last_scan=now, findings=[f.to_dict() for f in findings])
    return findings


def main() -> None:
    cfg = config.load()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    store = Storage(cfg.db_path)
    detector = Detector(store, cfg)
    alerter = alerts.Alerter(cfg)
    scanners = [Scanner(n, p, cfg.exclude_dirs, cfg.entropy_sample) for n, p in cfg.watch_paths.items()]
    docker_stats = None
    if cfg.docker_stats:
        try:
            from .docker_stats import DockerStats
            docker_stats = DockerStats()
        except Exception as exc:
            log.error("Docker stats disabled: %s", exc)

    dashboard.STATE["lang"] = cfg.alert_lang
    dashboard.start(store, cfg.dashboard_port, cfg.baseline_days)
    log.info("Watching %s | interval %ss | dashboard :%s | email=%s zabbix=%s docker=%s",
             cfg.watch_paths, cfg.scan_interval, cfg.dashboard_port,
             cfg.smtp_enabled, cfg.zabbix_enabled, bool(docker_stats))

    last_prune = 0.0
    while _running:
        started = time.time()
        try:
            run_once(cfg, store, detector, alerter, scanners, docker_stats)
        except Exception:
            log.exception("Scan cycle failed")
        if started - last_prune > 3600:
            store.prune(cfg.retention_days)
            last_prune = started
        while _running and time.time() - started < cfg.scan_interval:
            time.sleep(1)
    log.info("Stopped.")


if __name__ == "__main__":
    main()
