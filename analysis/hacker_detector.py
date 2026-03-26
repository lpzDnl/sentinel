"""SENTINEL Hacker Hardware Detector.

Identifies pentest/hacker hardware by OUI vendor name matching and
probe SSID fingerprinting, then scores the combination.

Scoring model
─────────────
  ESP32/Realtek alone               →  40  (log only, too common)
  Vendor match alone                →  60  (YELLOW — could be legit dev board)
  Probe SSID match alone            →  80  (RED — very suspicious)
  Vendor match + probe SSID match   → 100  (RED — confirmed pentest kit)
  Hak5 hardware (always)            → 100  (RED)
  ESP32 + pentest probe             →  90  (RED)

Public API
──────────
  check_device_for_hacker_hardware(device_id) -> dict | None
  scan_recent_devices(hours=1)               -> list[dict]
"""

import logging
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/opt/sentinel")

from database import Device, ProbeRequest, get_session

logger = logging.getLogger("sentinel.hacker_detector")


# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------

# (substring_to_match, base_score, is_esp_like)
# is_esp_like = True means device is common enough that vendor alone is not
# sufficient for a RED — needs a probe SSID hit to escalate.
_VENDOR_WATCHLIST: list[tuple[str, int, bool]] = [
    ("raspberry pi trading", 60, False),
    ("raspberry pi",         60, False),
    ("hak5",                100, False),
    ("great scott gadgets",  80, False),
    ("flipper devices",      80, False),
    ("alfa network",         60, False),
    ("alfa",                 60, False),
    ("nanopi",               60, False),
    ("hardkernel",           60, False),   # ODROID
    ("pine64",               60, False),
    ("banana pi",            60, False),
    ("orange pi",            60, False),
    ("radxa",                60, False),
    ("espressif",            40, True),    # ESP32/ESP8266 — very common
    ("realtek",              40, True),    # common NIC vendor
]

# Plain substring patterns (case-insensitive) for probe SSIDs
_PROBE_SUBSTRINGS: list[str] = [
    "pwnagotchi",
    "pwnagatchi",
    "hackrf",
    "flipper",
    "wifi_pineapple",
    "pineapple",
    "lan turtle",
    "packet squirrel",
    "bash bunny",
    "shark jack",
    "screen crab",
    "nano",
    "tetra",
    "kali",
    "parrot",
    "pentest",
    "pwn",
    "deauth",
    "sdrtouch",
]

# Regex patterns for probe SSIDs
_PROBE_PATTERNS: list[re.Pattern] = [
    re.compile(r"^pwnagotchi",    re.I),
    re.compile(r"^hackrf",        re.I),
    re.compile(r"sdr.{0,3}touch", re.I),
]


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _match_probe_ssid(ssid: str) -> str | None:
    """Return the matching term/pattern if SSID is suspicious, else None."""
    s = ssid.lower().strip()
    for sub in _PROBE_SUBSTRINGS:
        if sub in s:
            return sub
    for pat in _PROBE_PATTERNS:
        if pat.search(ssid):
            return pat.pattern
    return None


def _match_vendor(vendor: str) -> tuple[str, int, bool] | None:
    """Return (matched_term, base_score, is_esp_like) or None."""
    v = vendor.lower()
    for term, score, is_esp in _VENDOR_WATCHLIST:
        if term in v:
            return term, score, is_esp
    return None


# ---------------------------------------------------------------------------
# Core scoring (pure Python — no DB)
# ---------------------------------------------------------------------------

def _score_device(
    device_id: int,
    mac: str,
    vendor: str,
    ssids: list[str],
) -> dict | None:
    """Score a device given its vendor and probe SSIDs.

    Returns None if no suspicious indicators found, otherwise a full hit dict.
    """
    vendor = vendor or ""
    reasons: list[str] = []
    matched_vendor: str | None = None
    matched_ssids:  list[str]  = []
    vendor_score   = 0
    is_esp_like    = False

    # 1. Vendor check
    vm = _match_vendor(vendor)
    if vm:
        matched_term, vendor_score, is_esp_like = vm
        matched_vendor = matched_term
        reasons.append(f"Vendor '{vendor}' matches '{matched_term}'")

    # 2. Probe SSID check
    for ssid in ssids:
        m = _match_probe_ssid(ssid)
        if m and ssid not in matched_ssids:
            matched_ssids.append(ssid)
            reasons.append(f"Probe SSID {ssid!r} matches '{m}'")

    if not reasons:
        return None

    has_vendor = bool(matched_vendor)
    has_probe  = bool(matched_ssids)

    # Compute score
    if is_esp_like and not has_probe:
        score = 40                          # ESP/Realtek alone — log only
    elif is_esp_like and has_probe:
        score = 90                          # ESP + pentest probe
    elif has_vendor and has_probe:
        score = 100                         # confirmed pentest kit
    elif has_vendor and not has_probe:
        score = vendor_score                # vendor alone (60–80)
    else:
        score = 80                          # probe SSID alone

    # Hak5 is always critical
    if matched_vendor and "hak5" in matched_vendor:
        score = 100

    alert_level = (
        "red"    if score >= 80 else
        "yellow" if score >= 60 else
        "log"
    )

    return {
        "device_id":      device_id,
        "mac":            mac,
        "vendor":         vendor,
        "score":          score,
        "alert_level":    alert_level,
        "reasons":        reasons,
        "matched_vendor": matched_vendor,
        "matched_ssids":  matched_ssids,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_device_for_hacker_hardware(device_id: int) -> dict | None:
    """Check a single device for pentest/hacker hardware indicators.

    Returns None if clean, or a dict with:
      device_id, mac, vendor, score, alert_level, reasons,
      matched_vendor, matched_ssids
    """
    session = get_session()
    try:
        device = session.get(Device, device_id)
        if not device:
            return None

        if device.tag_category in ("resident", "neighbor", "delivery", "ignore"):
            return None

        ssid_rows = (
            session.query(ProbeRequest.ssid)
            .filter(
                ProbeRequest.device_id == device_id,
                ProbeRequest.ssid.isnot(None),
                ProbeRequest.ssid != "",
            )
            .distinct()
            .all()
        )
        ssids = [row[0] for row in ssid_rows]

        return _score_device(device_id, device.mac, device.vendor or "", ssids)

    except Exception as e:
        logger.error("Hacker check failed for device %d: %s", device_id, e)
        return None
    finally:
        session.close()


def scan_recent_devices(hours: int = 1) -> list[dict]:
    """Scan all devices first seen within the last `hours` hours.

    Uses a single batch query for vendors + probe SSIDs to avoid N+1.
    Returns list of hit dicts sorted by score descending.
    Score 40 (log-only ESP/Realtek hits) are included so nothing is hidden.
    """
    session = get_session()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        recent = (
            session.query(Device.id, Device.mac, Device.vendor)
            .filter(Device.first_seen >= cutoff)
            .all()
        )
        if not recent:
            logger.info("scan_recent_devices: no devices first seen in last %dh", hours)
            return []

        device_ids = [row[0] for row in recent]
        logger.info(
            "scan_recent_devices: checking %d devices (first_seen >= %s)",
            len(device_ids),
            cutoff.strftime("%Y-%m-%d %H:%M UTC"),
        )

        # Batch probe SSID fetch — one query instead of N
        probe_rows = (
            session.query(ProbeRequest.device_id, ProbeRequest.ssid)
            .filter(
                ProbeRequest.device_id.in_(device_ids),
                ProbeRequest.ssid.isnot(None),
                ProbeRequest.ssid != "",
            )
            .distinct()
            .all()
        )
        probe_map: dict[int, list[str]] = defaultdict(list)
        for did, ssid in probe_rows:
            probe_map[did].append(ssid)

    finally:
        session.close()

    hits: list[dict] = []
    for device_id, mac, vendor in recent:
        result = _score_device(device_id, mac, vendor or "", probe_map.get(device_id, []))
        if result is not None:
            hits.append(result)
            logger.info(
                "Hit: %s  vendor=%r  score=%d  level=%s  reasons=%s",
                mac, vendor, result["score"], result["alert_level"],
                "; ".join(result["reasons"]),
            )

    hits.sort(key=lambda x: x["score"], reverse=True)
    logger.info("scan_recent_devices: %d hits out of %d devices", len(hits), len(recent))
    return hits
