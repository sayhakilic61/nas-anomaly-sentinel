"""Alert formatting and delivery (e-mail + Zabbix) with cooldown."""
from __future__ import annotations

import logging
import smtplib
import ssl
import time
from email.message import EmailMessage

from . import zabbix_sender
from .detector import CRITICAL, OK, WARNING, Finding

log = logging.getLogger("sentinel.alerts")

TEXT = {
    "tr": {
        "sev": {OK: "NORMAL", WARNING: "UYARI", CRITICAL: "KRİTİK"},
        "subject": "[NAS Sentinel] {sev}: {summary}",
        "ok": "Olağan dışı bir hareket yok.",
        "intro": "NAS Anomaly Sentinel aşağıdaki sapmaları tespit etti.",
        "examples": "Örnek dosyalar",
        "advice_crit": (
            "Öneri: Etkilenen paylaşımı hemen salt-okunur yapın veya SMB/NFS erişimini kesin, "
            "şüpheli istemciyi ağdan ayırın ve snapshot'larınızı kontrol edin."
        ),
        "advice_warn": "Öneri: Değişikliğin beklenen bir iş (yedek, toplu kopyalama) olup olmadığını kontrol edin.",
        "rule": {
            "ransom_notes": "Fidye notu benzeri dosya: {v:.0f} adet",
            "ransom_ext": "Bilinen fidye yazılımı uzantısı: {v:.0f} dosya",
            "ext_changed": "Toplu uzantı değişimi: {v:.0f} dosya",
            "magic_mismatch": "İçerik/uzantı uyuşmazlığı (magic bytes): {v:.0f} dosya",
            "high_entropy": "Şifrelenmiş görünümlü (yüksek entropi) metin dosyası: {v:.0f}",
        },
        "stat": "{label}: {v:,.1f} — 30 günlük aynı-saat medyanı {m:,.1f} (z={z:.1f})",
        "daily": "Günlük büyüme {v:,.2f} GB — son 30 günün medyanı {m:,.2f} GB (z={z:.1f})",
        "correlated": "Yazma ile silme/üzerine yazma aynı anda sıçradı (şifrele-ve-değiştir deseni)",
        "labels": {
            "created_per_h": "Yeni dosya/saat",
            "modified_per_h": "Değişen dosya/saat",
            "deleted_per_h": "Silinen dosya/saat",
            "written_mb_per_h": "Yazılan MB/saat",
            "growth_mb_per_h": "Büyüme MB/saat",
            "cpu_pct": "CPU %",
            "blk_write_mb_per_h": "Disk yazma MB/saat",
            "net_tx_mb_per_h": "Ağ çıkışı MB/saat",
        },
    },
    "en": {
        "sev": {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL"},
        "subject": "[NAS Sentinel] {sev}: {summary}",
        "ok": "No unusual activity.",
        "intro": "NAS Anomaly Sentinel detected the following deviations.",
        "examples": "Example files",
        "advice_crit": (
            "Advice: make the affected share read-only or cut SMB/NFS access now, isolate the "
            "suspicious client and check your snapshots."
        ),
        "advice_warn": "Advice: check whether this is expected work (backup, bulk copy).",
        "rule": {
            "ransom_notes": "Ransom-note-like files: {v:.0f}",
            "ransom_ext": "Known ransomware extensions: {v:.0f} files",
            "ext_changed": "Bulk extension changes: {v:.0f} files",
            "magic_mismatch": "Content/extension mismatch (magic bytes): {v:.0f} files",
            "high_entropy": "Encrypted-looking (high entropy) text files: {v:.0f}",
        },
        "stat": "{label}: {v:,.1f} — 30-day same-hour median {m:,.1f} (z={z:.1f})",
        "daily": "Daily growth {v:,.2f} GB — 30-day median {m:,.2f} GB (z={z:.1f})",
        "correlated": "Writes and deletions/overwrites spiked together (encrypt-and-replace pattern)",
        "labels": {
            "created_per_h": "New files/h",
            "modified_per_h": "Modified files/h",
            "deleted_per_h": "Deleted files/h",
            "written_mb_per_h": "Written MB/h",
            "growth_mb_per_h": "Growth MB/h",
            "cpu_pct": "CPU %",
            "blk_write_mb_per_h": "Disk write MB/h",
            "net_tx_mb_per_h": "Network out MB/h",
        },
    },
}


def t(lang: str) -> dict:
    return TEXT.get(lang, TEXT["en"])


def describe(f: Finding, lang: str) -> str:
    tx = t(lang)
    if f.kind == "rule":
        text = tx["rule"][f.metric].format(v=f.value)
    elif f.kind == "stat":
        label = tx["labels"].get(f.metric, f.metric)
        text = tx["stat"].format(label=label, v=f.value, m=f.median or 0, z=f.z or 0)
    elif f.kind == "daily":
        text = tx["daily"].format(v=f.value, m=f.median or 0, z=f.z or 0)
    else:
        text = tx["correlated"].format(v=f.value)
    return f"[{f.source}] {text}"


def summarize(findings: list[Finding], lang: str) -> str:
    if not findings:
        return t(lang)["ok"]
    top = sorted(findings, key=lambda f: -f.severity)[0]
    extra = len(findings) - 1
    return describe(top, lang) + (f" (+{extra})" if extra else "")


class Alerter:
    def __init__(self, cfg):
        self.cfg = cfg
        self._last_sent: dict[str, dict] = {}
        self._last_status = OK

    # ------------------------------------------------------------------
    def should_send(self, status: int, findings: list[Finding], now: float) -> bool:
        """One e-mail per incident: within the cooldown, a share that was already
        reported is only reported again if it got worse or shows a NEW rule hit
        (e.g. ransom notes appear after the volume alert)."""
        if status == OK:
            return False
        cooldown = self.cfg.alert_cooldown
        new_info = False
        by_source: dict[str, list[Finding]] = {}
        for f in findings:
            by_source.setdefault(f.source, []).append(f)
        for source, fs in by_source.items():
            sev = max(f.severity for f in fs)
            rules = {f.metric for f in fs if f.kind == "rule"}
            last = self._last_sent.get(source)
            if (last is None or now - last["ts"] >= cooldown or sev > last["severity"]
                    or not rules <= last["rules"]):
                new_info = True
        if not new_info:
            return False
        for source, fs in by_source.items():
            last = self._last_sent.get(source)
            fresh = last is None or now - last["ts"] >= cooldown
            self._last_sent[source] = {
                "ts": now,
                "severity": max([f.severity for f in fs] + ([] if fresh else [last["severity"]])),
                "rules": {f.metric for f in fs if f.kind == "rule"} | (set() if fresh else last["rules"]),
            }
        return True

    def build_email(self, status: int, findings: list[Finding]) -> EmailMessage:
        lang = self.cfg.alert_lang
        tx = t(lang)
        msg = EmailMessage()
        msg["Subject"] = tx["subject"].format(sev=tx["sev"][status], summary=summarize(findings, lang))[:200]
        msg["From"] = self.cfg.mail_from
        msg["To"] = ", ".join(self.cfg.mail_to)
        lines = [tx["intro"], "", time.strftime("%Y-%m-%d %H:%M:%S"), ""]
        for f in sorted(findings, key=lambda f: -f.severity):
            lines.append(f"• {tx['sev'][f.severity]} — {describe(f, lang)}")
            if f.examples:
                lines.append(f"    {tx['examples']}:")
                lines.extend(f"      - {p}" for p in f.examples)
        lines += ["", tx["advice_crit"] if status == CRITICAL else tx["advice_warn"]]
        msg.set_content("\n".join(lines))
        return msg

    def send_email(self, msg: EmailMessage) -> None:
        c = self.cfg
        if not c.smtp_enabled or not c.mail_to:
            return
        try:
            if c.smtp_tls == "ssl":
                server = smtplib.SMTP_SSL(c.smtp_host, c.smtp_port, context=ssl.create_default_context(), timeout=15)
            else:
                server = smtplib.SMTP(c.smtp_host, c.smtp_port, timeout=15)
                if c.smtp_tls == "starttls":
                    server.starttls(context=ssl.create_default_context())
            with server:
                if c.smtp_user:
                    server.login(c.smtp_user, c.smtp_password)
                server.send_message(msg)
            log.info("Alert e-mail sent to %s", msg["To"])
        except Exception as exc:  # never let alerting crash the monitor
            log.error("E-mail delivery failed: %s", exc)

    def send_zabbix(self, status: int, score_value: float, findings: list[Finding]) -> None:
        c = self.cfg
        if not c.zabbix_enabled:
            return
        items = {
            "sentinel.heartbeat": 1,
            "sentinel.status": status,
            "sentinel.score": round(score_value, 1),
            "sentinel.message": summarize(findings, c.alert_lang),
        }
        try:
            resp = zabbix_sender.send(c.zabbix_server, c.zabbix_port, c.zabbix_host, items)
            log.debug("Zabbix response: %s", resp.get("info"))
        except Exception as exc:
            log.error("Zabbix delivery failed: %s", exc)

    # ------------------------------------------------------------------
    def dispatch(self, status: int, score_value: float, findings: list[Finding], now: float | None = None) -> bool:
        """Always update Zabbix; send e-mail only when needed. Returns True if an alert was raised."""
        now = now if now is not None else time.time()
        self.send_zabbix(status, score_value, findings)
        raised = self.should_send(status, findings, now)
        if raised:
            self.send_email(self.build_email(status, findings))
        self._last_status = status
        return raised
