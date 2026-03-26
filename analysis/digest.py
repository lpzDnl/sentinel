"""SENTINEL Daily Intelligence Digest.

Compiles the last 24 hours of sensor data into a structured Telegram
summary.  Runs once per day at 07:00 MDT via digest_loop().

Sections
────────
  1. ACTIVITY OVERVIEW  — WiFi MACs, vehicles, camera detections vs baseline
  2. THREAT SUMMARY     — RED/YELLOW/GREEN counts, RED details, persistent unknowns
  3. VEHICLE INTEL      — evening window, flagged vehicles, top 3 by frequency
  4. OVERNIGHT REPORT   — 00:00–06:00 persons, unknown WiFi, RED alerts
  5. NEW DEVICES        — first-time devices, non-randomized highlights
  6. HACKER HARDWARE    — hits from hacker_detector logged in last 24h

Entry points
────────────
  run_digest()   — build + send immediately; returns message text
  digest_loop()  — async loop that calls run_digest() daily at 07:00 MDT
"""

import asyncio
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/opt/sentinel")

import config
from database import (
    AlertLog,
    Device,
    Event,
    FrigateEvent,
    PresenceBundle,
    ProbeRequest,
    SdrSignal,
    Tag,
    VehicleIdentityCluster,
    VehicleProfile,
    Visit,
    get_session,
)
from analysis.alerter import get_alerter

logger = logging.getLogger("sentinel.digest")

ENV_BASELINE_PATH = Path("/opt/sentinel/data/env_baselines.json")
_TZ_NAME = "America/Denver"


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _tz():
    from zoneinfo import ZoneInfo
    return ZoneInfo(_TZ_NAME)


def _to_local(dt: datetime) -> datetime:
    if dt is None:
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_tz())


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Baseline loader
# ---------------------------------------------------------------------------

def _load_baselines() -> dict:
    try:
        return json.loads(ENV_BASELINE_PATH.read_text())
    except Exception as e:
        logger.warning("Could not load env_baselines.json: %s", e)
        return {}


# ---------------------------------------------------------------------------
# Delta flag helper
# ---------------------------------------------------------------------------

def _delta_flag(actual: float, baseline_avg: float) -> str:
    """Return a warning string if actual deviates >50% from baseline average."""
    if baseline_avg <= 0:
        return ""
    ratio = actual / baseline_avg
    if ratio > 1.5:
        pct = int((ratio - 1) * 100)
        return f" ⚠️ +{pct}% vs avg"
    if ratio < 0.5:
        pct = int((1 - ratio) * 100)
        return f" ⬇️ -{pct}% vs avg"
    return ""


# ---------------------------------------------------------------------------
# Section 1 — Activity overview
# ---------------------------------------------------------------------------

def _gather_activity(session, cutoff: datetime) -> dict:
    from sqlalchemy import func, distinct as sql_distinct

    # Unique WiFi MACs seen (device last_seen within window is fastest)
    wifi_macs = (
        session.query(func.count(Device.id))
        .filter(
            Device.device_type == "wifi",
            Device.last_seen >= cutoff,
        )
        .scalar() or 0
    )

    # Probe event count for baseline comparison
    probe_events = (
        session.query(func.count(ProbeRequest.id))
        .filter(ProbeRequest.timestamp >= cutoff)
        .scalar() or 0
    )

    # Unique TPMS sensors seen
    tpms_vehicles = (
        session.query(func.count(sql_distinct(SdrSignal.device_uid)))
        .filter(
            SdrSignal.signal_class == "tpms",
            SdrSignal.timestamp >= cutoff,
        )
        .scalar() or 0
    )

    # TPMS event count for baseline comparison
    tpms_events = (
        session.query(func.count(SdrSignal.id))
        .filter(
            SdrSignal.signal_class == "tpms",
            SdrSignal.timestamp >= cutoff,
        )
        .scalar() or 0
    )

    # Frigate person detections
    persons = (
        session.query(func.count(FrigateEvent.id))
        .filter(
            FrigateEvent.label == "person",
            FrigateEvent.timestamp >= cutoff,
        )
        .scalar() or 0
    )

    # Frigate car detections
    cars = (
        session.query(func.count(FrigateEvent.id))
        .filter(
            FrigateEvent.label == "car",
            FrigateEvent.timestamp >= cutoff,
        )
        .scalar() or 0
    )

    return {
        "wifi_macs":     wifi_macs,
        "probe_events":  probe_events,
        "tpms_vehicles": tpms_vehicles,
        "tpms_events":   tpms_events,
        "persons":       persons,
        "cars":          cars,
    }


# ---------------------------------------------------------------------------
# Section 2 — Threat summary
# ---------------------------------------------------------------------------

def _gather_threats(session, cutoff: datetime) -> dict:
    from sqlalchemy import func

    red_count = (
        session.query(func.count(AlertLog.id))
        .filter(AlertLog.timestamp >= cutoff, AlertLog.alert_type.like("red:%"))
        .scalar() or 0
    )
    yellow_count = (
        session.query(func.count(AlertLog.id))
        .filter(AlertLog.timestamp >= cutoff, AlertLog.alert_type.like("yellow:%"))
        .scalar() or 0
    )
    green_count = (
        session.query(func.count(AlertLog.id))
        .filter(AlertLog.timestamp >= cutoff, AlertLog.alert_type.like("green:%"))
        .scalar() or 0
    )

    red_rows = (
        session.query(AlertLog)
        .filter(AlertLog.timestamp >= cutoff, AlertLog.alert_type.like("red:%"))
        .order_by(AlertLog.timestamp.desc())
        .limit(5)
        .all()
    )

    # Unknown devices with 3+ visits in last 24h — persistent unknowns building up
    persist_rows = (
        session.query(
            Device.mac,
            Device.vendor,
            func.count(Visit.id).label("vcount"),
        )
        .join(Visit, Visit.device_id == Device.id)
        .join(Tag, Tag.device_id == Device.id)
        .filter(
            Visit.arrived_at >= cutoff,
            Tag.category == "unknown",
        )
        .group_by(Device.id)
        .having(func.count(Visit.id) >= 3)
        .order_by(func.count(Visit.id).desc())
        .limit(5)
        .all()
    )

    return {
        "red_count":           red_count,
        "yellow_count":        yellow_count,
        "green_count":         green_count,
        "red_rows":            red_rows,
        "persistent_unknowns": list(persist_rows),
    }


# ---------------------------------------------------------------------------
# Section 3 — Vehicle intelligence
# ---------------------------------------------------------------------------

def _gather_vehicles(session, cutoff: datetime) -> dict:
    from sqlalchemy import func, distinct as sql_distinct

    tz = _tz()
    now_local = datetime.now(tz)
    today_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)

    # Most recent 16:00–20:00 window — at 07:00 this is yesterday's evening
    if now_local.hour < 16:
        eve_date = today_local - timedelta(days=1)
    else:
        eve_date = today_local
    eve_start = eve_date.replace(hour=16).astimezone(timezone.utc)
    eve_end   = eve_date.replace(hour=20).astimezone(timezone.utc)

    evening_count = (
        session.query(func.count(sql_distinct(SdrSignal.device_uid)))
        .filter(
            SdrSignal.signal_class == "tpms",
            SdrSignal.timestamp >= eve_start,
            SdrSignal.timestamp < eve_end,
        )
        .scalar() or 0
    )

    flagged = (
        session.query(VehicleProfile)
        .filter(
            VehicleProfile.flagged == True,
            VehicleProfile.last_seen >= cutoff,
        )
        .order_by(VehicleProfile.last_seen.desc())
        .all()
    )

    top3 = (
        session.query(VehicleProfile)
        .order_by(VehicleProfile.sighting_count.desc())
        .limit(3)
        .all()
    )

    return {
        "evening_vehicles": evening_count,
        "flagged":          flagged,
        "top3":             top3,
        "eve_start_local":  _to_local(eve_start).strftime("%H:%M"),
        "eve_end_local":    _to_local(eve_end).strftime("%H:%M"),
    }


# ---------------------------------------------------------------------------
# Section 4 — Overnight report
# ---------------------------------------------------------------------------

def _gather_overnight(session, cutoff: datetime) -> dict:
    from sqlalchemy import func

    tz = _tz()
    now_local   = datetime.now(tz)
    today_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)

    # 00:00–06:00 local today (within the 24h window when running at 07:00)
    night_start_l = today_local
    night_end_l   = today_local.replace(hour=6)
    night_start   = night_start_l.astimezone(timezone.utc)
    night_end     = night_end_l.astimezone(timezone.utc)

    # Person detections on camera overnight
    persons = (
        session.query(func.count(FrigateEvent.id))
        .filter(
            FrigateEvent.label == "person",
            FrigateEvent.timestamp >= night_start,
            FrigateEvent.timestamp < night_end,
        )
        .scalar() or 0
    )

    # Unknown WiFi devices active overnight — via events table to catch activity
    # not just last_seen snapshots
    unknown_device_ids_q = (
        session.query(Tag.device_id)
        .join(Device, Device.id == Tag.device_id)
        .filter(
            Tag.category == "unknown",
            Device.device_type == "wifi",
        )
        .scalar_subquery()
    )
    unknowns = (
        session.query(func.count(func.distinct(Event.device_id)))
        .filter(
            Event.device_id.in_(
                session.query(Tag.device_id)
                .join(Device, Device.id == Tag.device_id)
                .filter(Tag.category == "unknown", Device.device_type == "wifi")
            ),
            Event.timestamp >= night_start,
            Event.timestamp < night_end,
        )
        .scalar() or 0
    )

    # RED alerts overnight
    red_alerts = (
        session.query(func.count(AlertLog.id))
        .filter(
            AlertLog.timestamp >= night_start,
            AlertLog.timestamp < night_end,
            AlertLog.alert_type.like("red:%"),
        )
        .scalar() or 0
    )

    return {
        "persons":    persons,
        "unknowns":   unknowns,
        "red_alerts": red_alerts,
        "window":     f"{night_start_l.strftime('%H:%M')}–{night_end_l.strftime('%H:%M')}",
    }


# ---------------------------------------------------------------------------
# Section 5 — New devices
# ---------------------------------------------------------------------------

def _gather_new_devices(session, cutoff: datetime) -> dict:
    from sqlalchemy import func

    total_new = (
        session.query(func.count(Device.id))
        .filter(Device.first_seen >= cutoff)
        .scalar() or 0
    )

    # Non-randomized first-time devices are more operationally interesting
    # (stable hardware MAC = trackable entity)
    non_random = (
        session.query(Device)
        .filter(
            Device.first_seen >= cutoff,
            Device.is_randomized == False,
            Device.device_type == "wifi",
        )
        .order_by(Device.first_seen.desc())
        .limit(5)
        .all()
    )

    return {
        "total_new":  total_new,
        "non_random": non_random,
    }


# ---------------------------------------------------------------------------
# Section 6.5 — Vehicle presence (presence_engine enrichment)
# ---------------------------------------------------------------------------

def _gather_vehicle_presence(session) -> dict:
    """Pull top 3 most-profiled vehicles with enriched identity data."""
    import json as _json

    top3 = (
        session.query(VehicleProfile)
        .order_by(VehicleProfile.sighting_count.desc())
        .limit(3)
        .all()
    )

    enriched: list[dict] = []
    for vp in top3:
        cl = (
            session.query(VehicleIdentityCluster)
            .filter(VehicleIdentityCluster.tpms_sensor_id == vp.sensor_id)
            .first()
        )
        ssids   = _json.loads(cl.representative_ssids  or "[]") if cl else []
        bt_v    = _json.loads(cl.associated_bt_vendors or "[]") if cl else []
        bundles = cl.bundle_count if cl else 0
        enriched.append({
            "sensor_id":      vp.sensor_id,
            "model":          vp.model,
            "sighting_count": vp.sighting_count,
            "ssids":          ssids,
            "bt_vendors":     bt_v,
            "bundle_count":   bundles,
            "camera_appearances": cl.camera_appearances if cl else 0,
            "dominant_camera":   cl.dominant_camera    if cl else None,
        })

    # Vehicles whose SSID fingerprint is inconsistent (multiple distinct
    # fingerprints in recent bundles — possible different driver / loaner car)
    changed: list[str] = []
    recent_bundles = (
        session.query(PresenceBundle)
        .filter(
            PresenceBundle.probe_ssid_fingerprint.isnot(None),
            PresenceBundle.probe_ssid_fingerprint != "",
        )
        .order_by(PresenceBundle.timestamp.desc())
        .limit(500)
        .all()
    )
    by_sensor: dict[str, set] = {}
    for b in recent_bundles:
        by_sensor.setdefault(b.tpms_sensor_id, set()).add(b.probe_ssid_fingerprint)
    for sensor_id, fps in by_sensor.items():
        if len(fps) > 1:
            changed.append(sensor_id)

    # Cross-vehicle same-person matches
    try:
        from analysis.presence_engine import find_same_person_different_vehicle
        same_person_hits = find_same_person_different_vehicle(min_ssid_overlap=2)
    except Exception:
        same_person_hits = []

    return {
        "top3":             enriched,
        "ssid_changed":     changed[:5],
        "same_person_hits": same_person_hits[:3],
    }


# ---------------------------------------------------------------------------
# Section 6 — Hacker hardware
# ---------------------------------------------------------------------------

def _gather_hacker_hits(session, cutoff: datetime) -> list[dict]:
    rows = (
        session.query(AlertLog)
        .filter(
            AlertLog.timestamp >= cutoff,
            AlertLog.alert_type == "red:hacker_hardware",
        )
        .order_by(AlertLog.timestamp.desc())
        .all()
    )
    return [{"timestamp": r.timestamp, "message": r.message} for r in rows]


# ---------------------------------------------------------------------------
# Message builder
# ---------------------------------------------------------------------------

def _build_message(
    activity:          dict,
    threats:           dict,
    vehicles:          dict,
    overnight:         dict,
    new_devices:       dict,
    hacker_hits:       list,
    baselines:         dict,
    now_local:         datetime,
    vehicle_presence:  dict | None = None,
) -> str:
    wdays = baselines.get("window_days", 6)
    sc    = baselines.get("sample_counts", {})

    # Daily averages from baselines (event counts)
    b_probe  = sc.get("wifi_probes",    0) / max(wdays, 1)
    b_tpms   = sc.get("sdr_tpms",       0) / max(wdays, 1)
    b_person = sc.get("frigate_person", 0) / max(wdays, 1)
    b_car    = sc.get("frigate_car",    0) / max(wdays, 1)

    lines: list[str] = []

    # ── Header ──
    lines += [
        "👁 <b>SENTINEL DAILY DIGEST</b>",
        f"📅 {now_local.strftime('%Y-%m-%d')} · {now_local.strftime('%H:%M %Z')}",
        "",
    ]

    # ── 1. Activity overview ──
    lines.append("📊 <b>ACTIVITY — LAST 24h</b>")
    lines.append(
        f"• WiFi devices:    {activity['wifi_macs']} unique MACs"
        f"  ({activity['probe_events']:,} probe events"
        f"{_delta_flag(activity['probe_events'], b_probe)})"
    )
    lines.append(
        f"• TPMS sensors:    {activity['tpms_vehicles']} unique"
        f"  ({activity['tpms_events']:,} signals"
        f"{_delta_flag(activity['tpms_events'], b_tpms)})"
    )
    lines.append(
        f"• Camera persons:  {activity['persons']}"
        f"{_delta_flag(activity['persons'], b_person)}"
    )
    lines.append(
        f"• Camera cars:     {activity['cars']}"
        f"{_delta_flag(activity['cars'], b_car)}"
    )
    lines.append("")

    # ── 2. Threat summary ──
    r = threats["red_count"]
    y = threats["yellow_count"]
    g = threats["green_count"]
    lines.append("🚨 <b>THREAT SUMMARY</b>")
    lines.append(f"🔴 {r}  🟡 {y}  🟢 {g}")

    if threats["red_rows"]:
        lines.append("")
        lines.append("<b>RED alerts:</b>")
        for row in threats["red_rows"]:
            ts    = _to_local(row.timestamp).strftime("%H:%M")
            atype = row.alert_type.split(":", 1)[-1]
            lines.append(f"  🔴 {ts}  {atype.replace('_', ' ')}")

    if threats["persistent_unknowns"]:
        lines.append("")
        n = len(threats["persistent_unknowns"])
        lines.append(f"<b>Persistent unknowns (3+ visits/24h):</b> {n}")
        for mac, vendor, vcount in threats["persistent_unknowns"][:3]:
            label = (vendor or mac)[:32]
            lines.append(f"  ⚠️ {label}  ×{vcount}")
    lines.append("")

    # ── 3. Vehicle intelligence ──
    lines.append("🚗 <b>VEHICLE INTELLIGENCE</b>")
    lines.append(
        f"• Evening ({vehicles['eve_start_local']}–"
        f"{vehicles['eve_end_local']}):  "
        f"{vehicles['evening_vehicles']} vehicles"
    )

    if vehicles["flagged"]:
        lines.append(f"• ⚠️ Flagged vehicles seen:  {len(vehicles['flagged'])}")
        for vp in vehicles["flagged"][:3]:
            reason = vp.flag_reason or "flagged"
            lines.append(f"  🚨 {vp.sensor_id}  — {reason}")
    else:
        lines.append("• Flagged vehicles:  none ✓")

    if vehicles["top3"]:
        lines.append("• Most frequent:")
        for vp in vehicles["top3"]:
            label = vp.model or vp.sensor_id
            lines.append(f"  🚗 {label}  ×{vp.sighting_count}")
    lines.append("")

    # ── 4. Overnight ──
    on = overnight
    lines.append(f"🌙 <b>OVERNIGHT ({on['window']} MDT)</b>")
    if on["persons"] > 0:
        lines.append(f"  ⚠️ Camera persons:     {on['persons']}")
    else:
        lines.append(f"  Camera persons:     0 ✓")
    if on["unknowns"] > 0:
        lines.append(f"  ⚠️ Unknown WiFi devices:  {on['unknowns']}")
    else:
        lines.append(f"  Unknown WiFi:       0 ✓")
    if on["red_alerts"] > 0:
        lines.append(f"  🔴 RED alerts:          {on['red_alerts']}")
    else:
        lines.append(f"  RED alerts:         0 ✓")
    lines.append("")

    # ── 5. New devices ──
    nd = new_devices
    lines.append("📡 <b>NEW DEVICES</b>")
    lines.append(f"• Total first-time:    {nd['total_new']}")
    if nd["non_random"]:
        lines.append(f"• Non-randomized MACs: {len(nd['non_random'])}")
        for dev in nd["non_random"][:3]:
            vendor = (dev.vendor or "unknown")[:28]
            lines.append(f"  📍 <code>{dev.mac}</code>  {vendor}")
    else:
        lines.append("• Non-randomized MACs: 0")
    lines.append("")

    # ── 6. Vehicle presence ──
    if vehicle_presence:
        vp = vehicle_presence
        lines.append("🔍 <b>VEHICLE PRESENCE</b>")
        if vp["top3"]:
            for v in vp["top3"]:
                label = v["model"] or v["sensor_id"]
                parts = [f"×{v['sighting_count']} / {v['bundle_count']} bundles"]
                if v["bt_vendors"]:
                    parts.append(f"{v['bt_vendors'][0]} BT")
                if v["ssids"]:
                    parts.append(f"probes [{', '.join(v['ssids'][:2])}]")
                if v["camera_appearances"]:
                    parts.append(f"{v['dominant_camera'] or 'cam'} ×{v['camera_appearances']}")
                lines.append(f"  🚗 {label}  {' | '.join(parts)}")
        else:
            lines.append("  No vehicle presence data")

        if vp["ssid_changed"]:
            lines.append(f"• ⚠️ SSID signature changed: {', '.join(vp['ssid_changed'][:3])}")

        if vp["same_person_hits"]:
            lines.append(f"• 🔗 Same-person matches: {len(vp['same_person_hits'])}")
            for hit in vp["same_person_hits"][:2]:
                shared = ", ".join(hit["overlap_ssids"][:3])
                lines.append(
                    f"  {hit['vehicle_a'][:20]} ↔ {hit['vehicle_b'][:20]}"
                    f"  shared=[{shared}]"
                )
        else:
            lines.append("• Same-person cross-matches:  none")
        lines.append("")

    # ── 7. Hacker hardware ──
    lines.append("🔬 <b>HACKER HARDWARE</b>")
    if hacker_hits:
        for hit in hacker_hits[:3]:
            ts    = _to_local(hit["timestamp"]).strftime("%H:%M")
            # Pull first content line from the stored alert message
            msg   = hit["message"] or ""
            brief = next(
                (ln.strip() for ln in msg.splitlines() if ln.strip()
                 and not ln.strip().startswith("<")),
                "detected",
            )
            lines.append(f"  🚨 {ts}  {brief[:60]}")
    else:
        lines.append("  None detected ✓")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_digest() -> str:
    """Compile and send the daily digest. Returns the message text."""
    cfg     = config.get()
    tz_name = cfg.get("general", {}).get("timezone", _TZ_NAME)

    try:
        from zoneinfo import ZoneInfo
        now_local = datetime.now(ZoneInfo(tz_name))
    except Exception:
        now_local = datetime.now()

    now_utc = datetime.now(timezone.utc)
    cutoff  = now_utc - timedelta(hours=24)

    logger.info(
        "Running daily digest  window=%s → %s  tz=%s",
        cutoff.strftime("%Y-%m-%d %H:%M UTC"),
        now_utc.strftime("%Y-%m-%d %H:%M UTC"),
        tz_name,
    )

    baselines = _load_baselines()

    session = get_session()
    try:
        activity         = _gather_activity(session, cutoff)
        threats          = _gather_threats(session, cutoff)
        vehicles         = _gather_vehicles(session, cutoff)
        overnight        = _gather_overnight(session, cutoff)
        new_devs         = _gather_new_devices(session, cutoff)
        hacker_hits      = _gather_hacker_hits(session, cutoff)
        vehicle_presence = _gather_vehicle_presence(session)
    finally:
        session.close()

    message = _build_message(
        activity, threats, vehicles, overnight,
        new_devs, hacker_hits, baselines, now_local,
        vehicle_presence=vehicle_presence,
    )

    # Telegram max is 4096; leave margin for safety
    if len(message) > 4000:
        message = message[:3995] + "\n..."

    logger.info("Digest ready (%d chars)", len(message))
    logger.info("\n%s", message)

    alerter = get_alerter()
    alerter.send_raw_message(message, alert_type="daily_digest")

    return message


# ---------------------------------------------------------------------------
# Daily async loop
# ---------------------------------------------------------------------------

async def digest_loop() -> None:
    """Run run_digest() every day at 07:00 America/Denver.

    Calculates exact wall-clock seconds until the next 07:00 before each
    sleep, so DST transitions don't accumulate drift.
    """
    from zoneinfo import ZoneInfo

    tz = ZoneInfo(_TZ_NAME)
    logger.info("Digest loop started — fires daily at 07:00 %s", _TZ_NAME)

    while True:
        now    = datetime.now(tz)
        target = now.replace(hour=7, minute=0, second=0, microsecond=0)
        if now >= target:
            target += timedelta(days=1)

        wait = (target - now).total_seconds()
        logger.info(
            "Next digest at %s  (%.0f min away)",
            target.strftime("%Y-%m-%d %H:%M %Z"),
            wait / 60,
        )
        await asyncio.sleep(wait)

        try:
            run_digest()
        except Exception as exc:
            logger.error("Digest run failed: %s", exc, exc_info=True)
