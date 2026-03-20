"""SENTINEL Threat-Tiered Alerting Module.

Three-tier threat model — no alert fatigue.

  GREEN  — log only. New devices, brief passes, known devices.
  YELLOW — internal flag, no Telegram. Repeat unknowns, dwell,
           person+unknown RF correlation.
  RED    — Telegram + Frigate snapshot. Flagged returns, persistent
           unknowns, pattern anomalies, night gate activity.

SENTINEL stays silent until something is actually worth attention.
"""

import json
import logging
import sys
import time
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import requests

sys.path.insert(0, "/opt/sentinel")

import config
from database import AlertLog, Device, Tag, get_session

logger = logging.getLogger("sentinel.alerter")


# ---------------------------------------------------------------------------
# Threat levels
# ---------------------------------------------------------------------------

class ThreatLevel(str, Enum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


# ---------------------------------------------------------------------------
# Attribute helper (Device ORM or dict)
# ---------------------------------------------------------------------------

def _dev(obj, attr, default=None):
    """Get attribute from an ORM object or a plain dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


# ---------------------------------------------------------------------------
# Rate limiter (RED alerts only)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Token-bucket rate limiter for Telegram messages."""

    def __init__(self, max_per_minute: int = 10):
        self.max_per_minute = max_per_minute
        self.timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        now = time.time()
        with self._lock:
            self.timestamps = [t for t in self.timestamps if now - t < 60]
            if len(self.timestamps) >= self.max_per_minute:
                return False
            self.timestamps.append(now)
            return True

    def wait(self, timeout: float = 30) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.acquire():
                return True
            time.sleep(1)
        return False


# ---------------------------------------------------------------------------
# Cooldown tracker (RED alerts only)
# ---------------------------------------------------------------------------

class CooldownTracker:
    """Per-device cooldown to prevent RED alert storms."""

    def __init__(self, cooldown_seconds: int = 600):
        self.cooldown = cooldown_seconds
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def can_alert(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._last.get(key, 0)
            if now - last < self.cooldown:
                return False
            self._last[key] = now
            return True

    def reset(self, key: str):
        with self._lock:
            self._last.pop(key, None)


# ---------------------------------------------------------------------------
# Alert formatter
# ---------------------------------------------------------------------------

_LEVEL_HEADER = {
    ThreatLevel.GREEN: "\U0001f7e2",   # green circle
    ThreatLevel.YELLOW: "\U0001f7e1",  # yellow circle
    ThreatLevel.RED: "\U0001f534",     # red circle
}

_TYPE_ICON = {
    "new_device": "\U0001f4e1",           # satellite
    "brief_pass": "\U0001f4a8",           # dash
    "known_device": "\u2705",             # check
    "repeat_unknown": "\u26a0\ufe0f",     # warning
    "long_dwell": "\u23f1\ufe0f",         # stopwatch
    "frigate_person_unknown": "\U0001f6b6",  # person walking
    "flagged_return": "\U0001f6a8",       # rotating light
    "persistent_unknown": "\U0001f6a9",   # flag
    "pattern_anomaly": "\U0001f50d",      # magnifying glass
    "night_gate": "\U0001f319",           # crescent moon
    "frigate_person": "\U0001f6b6",       # person walking
    "frigate_car": "\U0001f697",          # car
    "frigate_object": "\U0001f4f7",       # camera
}


def format_alert(level: ThreatLevel, alert_type: str, device=None,
                 tag=None, camera: str | None = None,
                 details: dict | None = None) -> str:
    """Build an HTML-formatted alert message."""
    details = details or {}
    level_dot = _LEVEL_HEADER[level]
    icon = _TYPE_ICON.get(alert_type, "\U0001f514")

    lines = [
        f"{level_dot} {icon} <b>SENTINEL {level.value.upper()}: "
        f"{alert_type.replace('_', ' ').upper()}</b>",
        "",
    ]

    if device:
        name = (_dev(device, "alias") or _dev(device, "hostname")
                or _dev(device, "vendor") or _dev(device, "mac"))
        lines.append(f"\U0001f4f1 <b>Device:</b> {name}")
        lines.append(
            f"\U0001f4cd <b>MAC:</b> <code>{_dev(device, 'mac', '?')}</code>"
        )
        if _dev(device, "device_type"):
            lines.append(f"\U0001f4e1 <b>Type:</b> {_dev(device, 'device_type')}")
        if _dev(device, "vendor"):
            lines.append(f"\U0001f3ed <b>Vendor:</b> {_dev(device, 'vendor')}")

    if tag:
        tag_cat = _dev(tag, "category", "unknown")
        tag_label = _dev(tag, "label")
        flagged = _dev(tag, "flagged", False)
        tag_str = f"\U0001f3f7\ufe0f <b>Tag:</b> {tag_cat}"
        if tag_label:
            tag_str += f" ({tag_label})"
        if flagged:
            tag_str += " \u26a0\ufe0f <b>FLAGGED</b>"
        lines.append(tag_str)

    if camera:
        lines.append(f"\U0001f3a5 <b>Camera:</b> {camera}")

    # Detail fields
    for key, label, fmt in [
        ("confidence", "Confidence", lambda v: f"{v:.0%}"),
        ("rssi", "RSSI", lambda v: f"{v} dBm"),
        ("duration_min", "Duration", lambda v: f"{v}m"),
        ("visit_count", "Visits", str),
        ("distinct_days", "Distinct days", str),
        ("visits_today", "Visits today", str),
        ("zones", "Zones", lambda v: ", ".join(v) if isinstance(v, list) else str(v)),
    ]:
        val = details.get(key)
        if val is not None:
            lines.append(f"\u2022 <b>{label}:</b> {fmt(val)}")

    if details.get("reason"):
        lines.append(f"\n\U0001f4ac {details['reason']}")

    from zoneinfo import ZoneInfo
    tz_name = config.get().get("general", {}).get("timezone", "UTC")
    try:
        now = datetime.now(ZoneInfo(tz_name))
    except Exception:
        now = datetime.now()
#     lines.append(f"\n\U0001f552 {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core alerter
# ---------------------------------------------------------------------------

class ThreatAlerter:
    """Routes alerts by threat level: GREEN->log, YELLOW->flag, RED->Telegram."""

    API_BASE = "https://api.telegram.org/bot{token}"

    def __init__(self):
        self.cfg = config.get()
        tg_cfg = self.cfg.get("telegram", {})
        self.tg_enabled = tg_cfg.get("enabled", False)
        self.token = tg_cfg.get("bot_token", "")
        self.chat_id = tg_cfg.get("chat_id", "")
        self.send_snapshots = tg_cfg.get("send_snapshots", True)
        self.parse_mode = tg_cfg.get("parse_mode", "HTML")

        self.rate_limiter = RateLimiter(tg_cfg.get("rate_limit", 10))
        self.cooldown = CooldownTracker(
            self.cfg.get("alerts", {}).get("cooldown", 600)
        )

        if self.tg_enabled:
            if not self.token or "YOUR_" in self.token:
                logger.warning("Telegram enabled but bot_token not configured")
                self.tg_enabled = False
            elif not self.chat_id or "YOUR_" in str(self.chat_id):
                logger.warning("Telegram enabled but chat_id not configured")
                self.tg_enabled = False

        logger.info("ThreatAlerter initialized (telegram=%s)", self.tg_enabled)

    def send_alert(self, level: ThreatLevel, alert_type: str,
                   device=None, tag=None,
                   camera: str | None = None,
                   snapshot_path: str | None = None,
                   details: dict | None = None) -> str:
        """Route alert by threat level.

        Accepts Device ORM objects or plain dicts for device/tag.

        Returns action taken: "logged", "flagged", "sent", or "suppressed".
        """
        details = details or {}
        mac = _dev(device, "mac", "unknown")
        message = format_alert(level, alert_type, device, tag, camera, details)

        # ── GREEN: log only ──
        if level == ThreatLevel.GREEN:
            logger.debug("GREEN %s: %s", alert_type, mac)
            self._log_alert(level, alert_type, device, message,
                            channel="log", delivered=True)
            return "logged"

        # ── YELLOW: internal flag, no Telegram ──
        if level == ThreatLevel.YELLOW:
            logger.info("YELLOW %s: %s | %s",
                        alert_type, mac, details.get("reason", ""))
            self._log_alert(level, alert_type, device, message,
                            channel="internal", delivered=True)
            return "flagged"

        # ── RED: Telegram + snapshot ──
        logger.warning("RED %s: %s | %s",
                       alert_type, mac, details.get("reason", ""))

        # Cooldown: 10 min per device+type
        cooldown_key = f"{alert_type}:{mac}"
        if not self.cooldown.can_alert(cooldown_key):
            logger.info("RED suppressed (cooldown): %s %s", alert_type, mac)
            self._log_alert(level, alert_type, device, message,
                            channel="telegram", delivered=False,
                            error="cooldown")
            return "suppressed"

        if not self.tg_enabled:
            logger.info("RED [telegram disabled]: %s %s", alert_type, mac)
            self._log_alert(level, alert_type, device, message,
                            channel="telegram", delivered=False,
                            error="telegram_disabled")
            return "flagged"

        # Rate limit
        if not self.rate_limiter.wait(timeout=15):
            logger.warning("RED rate-limited: %s", alert_type)
            self._log_alert(level, alert_type, device, message,
                            channel="telegram", delivered=False,
                            error="rate_limited")
            return "suppressed"

        # Send via Telegram
        sent = False
        error = None
        try:
            if (snapshot_path and self.send_snapshots
                    and Path(snapshot_path).exists()):
                sent = self._send_photo(message, snapshot_path)
            else:
                sent = self._send_message(message)
        except Exception as e:
            error = str(e)
            logger.error("Telegram send failed: %s", e)

        self._log_alert(level, alert_type, device, message,
                        channel="telegram", delivered=sent, error=error)

        if sent:
            logger.info("RED sent via Telegram: %s for %s", alert_type, mac)
        return "sent" if sent else "suppressed"

    # ── Telegram transport ──

    def _send_message(self, text: str) -> bool:
        url = f"{self.API_BASE.format(token=self.token)}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": self.parse_mode,
            "disable_web_page_preview": True,
        }
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200 and resp.json().get("ok"):
            return True
        logger.error("Telegram API error: %s %s",
                     resp.status_code, resp.text[:200])
        return False

    def _send_photo(self, caption: str, photo_path: str) -> bool:
        url = f"{self.API_BASE.format(token=self.token)}/sendPhoto"
        if len(caption) > 1024:
            caption = caption[:1020] + "..."
        data = {
            "chat_id": self.chat_id,
            "caption": caption,
            "parse_mode": self.parse_mode,
        }
        with open(photo_path, "rb") as f:
            resp = requests.post(url, data=data, files={"photo": f}, timeout=30)
        if resp.status_code == 200 and resp.json().get("ok"):
            return True
        logger.error("Telegram photo error: %s %s",
                     resp.status_code, resp.text[:200])
        return False

    # ── DB logging ──

    def _log_alert(self, level: ThreatLevel, alert_type: str, device,
                   message: str, channel: str = "log",
                   delivered: bool = False, error: str | None = None):
        session = get_session()
        try:
            log = AlertLog(
                alert_type=f"{level.value}:{alert_type}",
                device_id=_dev(device, "id"),
                message=message,
                channel=channel,
                delivered=delivered,
                error=error,
            )
            session.add(log)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("Failed to log alert: %s", e)
        finally:
            session.close()

    def test_connection(self) -> bool:
        """Send a test message to verify Telegram configuration."""
        if not self.tg_enabled:
            logger.warning("Telegram not enabled, cannot test")
            return False
        try:
            return self._send_message(
                "\U0001f534 <b>SENTINEL</b> \u2014 Telegram link verified.\n"
                "Threat-tiered alerting active. You will only hear from me "
                "when it matters."
            )
        except Exception as e:
            logger.error("Telegram test failed: %s", e)
            return False


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_alerter: ThreatAlerter | None = None


def get_alerter() -> ThreatAlerter:
    """Get or create the singleton alerter instance."""
    global _alerter
    if _alerter is None:
        _alerter = ThreatAlerter()
    return _alerter


def send_alert(level: ThreatLevel = ThreatLevel.GREEN, **kwargs) -> str:
    """Convenience wrapper. Returns action taken."""
    return get_alerter().send_alert(level=level, **kwargs)
