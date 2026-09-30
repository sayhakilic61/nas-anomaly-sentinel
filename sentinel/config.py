"""Environment-driven configuration. Every option has a safe default."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw not in (None, "") else default


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return float(raw) if raw not in (None, "") else default


def parse_watch_paths(raw: str) -> dict[str, str]:
    """"docs=/watch/docs,photos=/watch/photos" -> {"docs": "/watch/docs", ...}"""
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, path = part.split("=", 1)
        else:
            path = part
            name = os.path.basename(path.rstrip("/")) or "root"
        out[name.strip()] = path.strip()
    return out


@dataclass
class Config:
    watch_paths: dict[str, str] = field(default_factory=dict)
    exclude_dirs: set[str] = field(default_factory=set)
    db_path: str = "/data/sentinel.db"
    scan_interval: int = 300
    retention_days: int = 35
    baseline_days: int = 30
    min_baseline_days: int = 7
    hour_window: int = 1
    z_warning: float = 4.0
    z_critical: float = 8.0
    entropy_sample: int = 200
    rule_ransom_ext: int = 3
    rule_ext_changed: int = 20
    rule_magic_mismatch: int = 5
    rule_high_entropy: int = 10
    alert_cooldown: int = 1800
    alert_lang: str = "tr"
    docker_stats: bool = False
    dashboard_port: int = 8080
    # email
    smtp_enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_tls: str = "starttls"  # starttls | ssl | none
    mail_from: str = "nas-sentinel@localhost"
    mail_to: list[str] = field(default_factory=list)
    # zabbix
    zabbix_enabled: bool = False
    zabbix_server: str = "zabbix-server"
    zabbix_port: int = 10051
    zabbix_host: str = "nas-sentinel"


def load() -> Config:
    return Config(
        watch_paths=parse_watch_paths(os.getenv("WATCH_PATHS", "demo=/watch/demo")),
        exclude_dirs={
            d.strip()
            for d in os.getenv(
                "EXCLUDE_DIRS", "@eaDir,@recycle,#recycle,.Trash-1000,.snapshot,@tmp,lost+found"
            ).split(",")
            if d.strip()
        },
        db_path=os.getenv("DB_PATH", "/data/sentinel.db"),
        scan_interval=_int("SCAN_INTERVAL", 300),
        retention_days=_int("RETENTION_DAYS", 35),
        baseline_days=_int("BASELINE_DAYS", 30),
        min_baseline_days=_int("MIN_BASELINE_DAYS", 7),
        hour_window=_int("HOUR_WINDOW", 1),
        z_warning=_float("Z_WARNING", 4.0),
        z_critical=_float("Z_CRITICAL", 8.0),
        entropy_sample=_int("ENTROPY_SAMPLE", 200),
        rule_ransom_ext=_int("RULE_RANSOM_EXT", 3),
        rule_ext_changed=_int("RULE_EXT_CHANGED", 20),
        rule_magic_mismatch=_int("RULE_MAGIC_MISMATCH", 5),
        rule_high_entropy=_int("RULE_HIGH_ENTROPY", 10),
        alert_cooldown=_int("ALERT_COOLDOWN", 1800),
        alert_lang=os.getenv("ALERT_LANG", "tr").lower(),
        docker_stats=_bool("ENABLE_DOCKER_STATS", False),
        dashboard_port=_int("DASHBOARD_PORT", 8080),
        smtp_enabled=_bool("SMTP_ENABLED", False),
        smtp_host=os.getenv("SMTP_HOST", "localhost"),
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=os.getenv("SMTP_USER", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_tls=os.getenv("SMTP_TLS", "starttls").lower(),
        mail_from=os.getenv("MAIL_FROM", "nas-sentinel@localhost"),
        mail_to=[m.strip() for m in os.getenv("MAIL_TO", "").split(",") if m.strip()],
        zabbix_enabled=_bool("ZABBIX_ENABLED", False),
        zabbix_server=os.getenv("ZABBIX_SERVER", "zabbix-server"),
        zabbix_port=_int("ZABBIX_PORT", 10051),
        zabbix_host=os.getenv("ZABBIX_HOST", "nas-sentinel"),
    )
