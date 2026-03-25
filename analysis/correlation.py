"""SENTINEL Correlation & Threat Classification Engine.

Correlates RF device detections with Frigate visual events,
classifies threats into GREEN/YELLOW/RED tiers, computes
behavioral baselines, and auto-tags repeat devices.

Threat model:
  GREEN  — new device, brief pass, known device (log only)
  YELLOW — repeat unknown 2+/day, dwell >10m, person+unknown RF
  RED    — flagged return, persistent unknown (3+ visits / 2+ days),
           pattern anomaly, night gate (22-06) with unknown device
"""

import json
import logging
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

sys.path.insert(0, "/opt/sentinel")

import config
from database import (
    Baseline,
    Device,
    Event,
    FrigateEvent,
    ProbeRequest,
    SdrFrigateCorrelation,
    SdrSignal,
    Tag,
    Visit,
    get_session,
)
from analysis.alerter import ThreatLevel, send_alert, _dev

logger = logging.getLogger("sentinel.correlation")


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _local_hour() -> int:
    """Return current hour in configured local timezone."""
    tz_name = config.get().get("general", {}).get("timezone", "UTC")
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(tz_name)).hour
    except Exception:
        return datetime.now().hour


def _is_night(hour: int | None = None) -> bool:
    """True if hour falls within the night gate window (default 22:00-06:00)."""
    if hour is None:
        hour = _local_hour()
    cfg = config.get().get("alerts", {}).get("thresholds", {})
    start = cfg.get("night_start", 22)
    end = cfg.get("night_end", 6)
    if start > end:  # overnight wrap (e.g. 22-06)
        return hour >= start or hour < end
    return start <= hour < end


def _utc_aware(dt):
    """Ensure a datetime is timezone-aware (UTC)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Frigate <-> RF Correlation (unchanged logic)
# ---------------------------------------------------------------------------

def correlate_frigate_event(frigate_event_id: int) -> dict | None:
    """Correlate a Frigate event with nearby RF device detections.

    Scoring: time proximity (40%), arrival during window (30%),
    event density (20%), signal strength (10%).

    Returns dict with correlation results, or None.
    """
    cfg = config.get()
    window = cfg.get("correlation", {}).get("time_window", 120)
    min_conf = cfg.get("correlation", {}).get("min_confidence", 0.5)

    session = get_session()
    try:
        fe = session.get(FrigateEvent, frigate_event_id)
        if not fe:
            return None

        t_start = fe.timestamp - timedelta(seconds=window)
        t_end = fe.timestamp + timedelta(seconds=window)

        rf_events = (
            session.query(Event)
            .filter(
                Event.timestamp.between(t_start, t_end),
                Event.event_type.in_(
                    ["wifi_probe", "bt_ble", "bt_classic", "arrival"]
                ),
                Event.device_id.isnot(None),
            )
            .all()
        )

        if not rf_events:
            return None

        candidates = {}
        for evt in rf_events:
            did = evt.device_id
            if did not in candidates:
                candidates[did] = {
                    "device_id": did,
                    "events": [],
                    "has_arrival": False,
                    "min_time_delta": float("inf"),
                    "best_rssi": None,
                }
            c = candidates[did]
            c["events"].append(evt)

            delta = abs((evt.timestamp - fe.timestamp).total_seconds())
            c["min_time_delta"] = min(c["min_time_delta"], delta)

            if evt.event_type == "arrival":
                c["has_arrival"] = True

            if evt.rssi is not None:
                if c["best_rssi"] is None or evt.rssi > c["best_rssi"]:
                    c["best_rssi"] = evt.rssi

        scored = []
        for did, c in candidates.items():
            score = 0.0
            time_factor = max(0, 1 - (c["min_time_delta"] / window))
            score += time_factor * 0.4
            if c["has_arrival"]:
                score += 0.3
            event_factor = min(len(c["events"]) / 10, 1.0)
            score += event_factor * 0.2
            if c["best_rssi"] is not None and c["best_rssi"] > -60:
                score += 0.1
            c["score"] = round(score, 3)
            if score >= min_conf:
                scored.append(c)

        if not scored:
            return None

        scored.sort(key=lambda x: x["score"], reverse=True)
        best = scored[0]

        fe.correlated_device_id = best["device_id"]
        fe.correlation_confidence = best["score"]

        device = session.get(Device, best["device_id"])
        if device:
            open_visit = (
                session.query(Visit)
                .filter(
                    Visit.device_id == device.id,
                    Visit.departed_at.is_(None),
                )
                .order_by(Visit.arrived_at.desc())
                .first()
            )
            if open_visit:
                existing = json.loads(
                    open_visit.correlated_frigate_events or "[]"
                )
                existing.append(fe.frigate_event_id)
                open_visit.correlated_frigate_events = json.dumps(existing)

        session.commit()

        result = {
            "frigate_event_id": fe.frigate_event_id,
            "frigate_label": fe.label,
            "camera": fe.camera,
            "best_device_id": best["device_id"],
            "best_device_mac": device.mac if device else None,
            "confidence": best["score"],
            "candidates": len(scored),
            "arrival_correlated": best["has_arrival"],
        }

        logger.info(
            "Correlated Frigate %s (%s on %s) -> device %s (%.0f%%)",
            fe.frigate_event_id, fe.label, fe.camera,
            device.mac if device else "?", best["score"] * 100,
        )
        return result

    except Exception as e:
        session.rollback()
        logger.error("Correlation failed for frigate event %s: %s",
                     frigate_event_id, e)
        return None
    finally:
        session.close()


# ---------------------------------------------------------------------------
# SDR <-> Frigate correlation (TPMS + car)
# ---------------------------------------------------------------------------

def correlate_sdr_frigate(sdr_signal_id: int) -> list[dict]:
    """Correlate a TPMS signal with Frigate car events within the time window.

    Looks back and forward `sdr_frigate_window` seconds (default 60) from
    the TPMS signal timestamp for any Frigate 'car' detections, scores by
    time proximity, and writes unique matches to SdrFrigateCorrelation.

    Skips pairs already in the table to prevent duplicates.

    Returns list of newly-created correlation dicts.
    """
    cfg = config.get()
    window = cfg.get("correlation", {}).get("sdr_frigate_window", 60)

    session = get_session()
    results = []
    try:
        sig = session.get(SdrSignal, sdr_signal_id)
        if not sig or sig.signal_class != "tpms":
            return results

        sig_ts = _utc_aware(sig.timestamp)
        t_lo = sig_ts - timedelta(seconds=window)
        t_hi = sig_ts + timedelta(seconds=window)

        frigate_cars = (
            session.query(FrigateEvent)
            .filter(
                FrigateEvent.label == "car",
                FrigateEvent.timestamp.between(t_lo, t_hi),
            )
            .all()
        )

        if not frigate_cars:
            return results

        for fe in frigate_cars:
            fe_ts = _utc_aware(fe.timestamp)
            delta = abs((sig_ts - fe_ts).total_seconds())
            if delta > window:
                continue

            confidence = round(max(0.0, 1.0 - (delta / window)), 3)

            # Dedup: skip if this (signal, frigate_event) pair already exists
            already = (
                session.query(SdrFrigateCorrelation)
                .filter(
                    SdrFrigateCorrelation.sdr_signal_id == sig.id,
                    SdrFrigateCorrelation.frigate_event_id == fe.id,
                )
                .first()
            )
            if already:
                continue

            corr = SdrFrigateCorrelation(
                sdr_signal_id=sig.id,
                frigate_event_id=fe.id,
                correlation_window_seconds=window,
                confidence=confidence,
                notes=(
                    f"TPMS {sig.device_uid} <-> {fe.camera} car "
                    f"({delta:.1f}s delta)"
                ),
            )
            session.add(corr)

            results.append({
                "sdr_signal_id": sig.id,
                "device_uid": sig.device_uid,
                "model": sig.model,
                "frigate_event_db_id": fe.id,
                "frigate_event_id": fe.frigate_event_id,
                "camera": fe.camera,
                "frigate_confidence": fe.confidence,
                "time_delta_seconds": round(delta, 1),
                "confidence": confidence,
            })

            logger.info(
                "SDR<->Frigate: TPMS %s <-> car on %s  delta=%.1fs  conf=%.0f%%",
                sig.device_uid, fe.camera, delta, confidence * 100,
            )

        if results:
            session.commit()

        return results

    except Exception as e:
        session.rollback()
        logger.error("SDR/Frigate correlation failed for signal %d: %s",
                     sdr_signal_id, e)
        return []
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Threat classification — Devices
# ---------------------------------------------------------------------------

def classify_device_threat(device_id: int) -> tuple[ThreatLevel, str, dict]:
    """Classify threat level for a device based on current state.

    Evaluates RED conditions first (highest priority), then YELLOW,
    then GREEN. Returns the single highest applicable tier.

    Returns:
        (level, alert_type, details) tuple.
    """
    cfg = config.get()
    thresholds = cfg.get("alerts", {}).get("thresholds", {})

    session = get_session()
    try:
        device = session.get(Device, device_id)
        if not device:
            return ThreatLevel.GREEN, "brief_pass", {}

        tag = session.query(Tag).filter(Tag.device_id == device_id).first()
        baseline = (
            session.query(Baseline)
            .filter(Baseline.device_id == device_id)
            .first()
        )

        category = tag.category if tag else "unknown"
        is_flagged = bool(tag and tag.flagged)
        is_unknown = category == "unknown"
        is_known = category in ("resident", "neighbor", "delivery", "ignore")
        mac = device.mac

        # Count visits (all time)
        total_visits = (
            session.query(func.count(Visit.id))
            .filter(Visit.device_id == device_id)
            .scalar() or 0
        )

        # Count distinct visit dates
        distinct_days = 0
        if total_visits >= 2:
            distinct_days = (
                session.query(
                    func.count(func.distinct(func.date(Visit.arrived_at)))
                )
                .filter(Visit.device_id == device_id)
                .scalar() or 0
            )

        # Count visits today
        now_utc = datetime.now(timezone.utc)
        today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        visits_today = (
            session.query(func.count(Visit.id))
            .filter(
                Visit.device_id == device_id,
                Visit.arrived_at >= today_start,
            )
            .scalar() or 0
        )

        # Check open visit for dwell time
        dwell_minutes = 0
        open_visit = (
            session.query(Visit)
            .filter(
                Visit.device_id == device_id,
                Visit.departed_at.is_(None),
            )
            .order_by(Visit.arrived_at.desc())
            .first()
        )
        if open_visit:
            arrived = _utc_aware(open_visit.arrived_at)
            dwell_minutes = int(
                (now_utc - arrived).total_seconds() / 60
            )

        current_hour = _local_hour()

        # Build base context that goes with every classification
        base = {
            "visit_count": total_visits,
            "distinct_days": distinct_days,
            "visits_today": visits_today,
            "duration_min": dwell_minutes if dwell_minutes > 0 else None,
        }

        # ── RED checks (highest priority) ──

        # 1. Flagged device returns
        if is_flagged:
            return (
                ThreatLevel.RED, "flagged_return",
                {**base, "reason":
                 f"Flagged device {_dev(tag, 'label') or mac} detected"},
            )

        # 2. Persistent unknown: 3+ visits across 2+ distinct days
        persist_visits = thresholds.get("persistent_unknown_visits", 3)
        persist_days = thresholds.get("persistent_unknown_days", 2)
        if (is_unknown
                and total_visits >= persist_visits
                and distinct_days >= persist_days):
            return (
                ThreatLevel.RED, "persistent_unknown",
                {**base, "reason":
                 f"Unknown device {mac} seen {total_visits} times "
                 f"across {distinct_days} days"},
            )

        # 3. Pattern anomaly: unknown device outside baseline hours
        if is_unknown and baseline:
            start_h = baseline.typical_start_hour
            end_h = baseline.typical_end_hour
            if start_h is not None and end_h is not None:
                if start_h <= end_h:
                    outside = current_hour < start_h or current_hour >= end_h
                else:
                    outside = current_hour >= end_h and current_hour < start_h
                if outside:
                    return (
                        ThreatLevel.RED, "pattern_anomaly",
                        {**base, "reason":
                         f"Unknown {mac} at {current_hour}:00 "
                         f"(baseline {start_h}:00-{end_h}:00)"},
                    )

        # 4. Night activity with unknown device (22:00-06:00)
        if is_unknown and _is_night(current_hour) and visits_today >= 1:
            return (
                ThreatLevel.RED, "night_gate",
                {**base, "reason":
                 f"Unknown device {mac} active at {current_hour}:00 "
                 f"(night window)"},
            )

        # ── YELLOW checks ──

        # 5. Same unknown device 2+ times today
        repeat_threshold = thresholds.get("repeat_unknown_daily", 2)
        if is_unknown and visits_today >= repeat_threshold:
            return (
                ThreatLevel.YELLOW, "repeat_unknown",
                {**base, "reason":
                 f"Unknown {mac} visit #{visits_today} today"},
            )

        # 6. Unknown device dwelling >10 min
        dwell_threshold = thresholds.get("dwell_minutes", 10)
        if is_unknown and dwell_minutes >= dwell_threshold:
            return (
                ThreatLevel.YELLOW, "long_dwell",
                {**base, "reason":
                 f"Unknown {mac} dwelling {dwell_minutes}m "
                 f"(threshold {dwell_threshold}m)"},
            )

        # ── GREEN (everything else) ──

        # 7. First-time device
        if device.total_sightings == 1:
            # Enrich with proximity, timing, vendor, and probe context
            latest_event = (
                session.query(Event)
                .filter(Event.device_id == device_id, Event.rssi.isnot(None))
                .order_by(Event.timestamp.desc())
                .first()
            )
            rssi = latest_event.rssi if latest_event else None

            probe_rows = (
                session.query(ProbeRequest.ssid)
                .filter(
                    ProbeRequest.device_id == device_id,
                    ProbeRequest.ssid.isnot(None),
                    ProbeRequest.ssid != "",
                )
                .distinct()
                .limit(10)
                .all()
            )
            probe_ssids = [row[0] for row in probe_rows]
            border_ssids = [
                s for s in probe_ssids
                if s.lower().startswith(_BORDER_PREFIXES)
            ]

            first_seen = device.first_seen
            new_device_details = {
                **base,
                "reason": f"First-time device {mac}",
                "rssi": rssi,
                "is_night": _is_night(current_hour),
                "probe_ssids": probe_ssids[:3],
                "border_ssids": border_ssids[:3],
                "first_seen": first_seen.strftime("%Y-%m-%d %H:%M UTC") if first_seen else None,
            }
            return (ThreatLevel.GREEN, "new_device", new_device_details)

        # 8. Known device
        if is_known:
            return (
                ThreatLevel.GREEN, "known_device",
                {**base, "reason": f"Known {category}: {mac}"},
            )

        # 9. Default: brief pass
        return (
            ThreatLevel.GREEN, "brief_pass",
            {**base, "reason": f"Routine sighting: {mac}"},
        )

    except Exception as e:
        logger.error("Threat classification failed for device %d: %s",
                     device_id, e)
        return ThreatLevel.GREEN, "brief_pass", {}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Threat classification — Frigate events
# ---------------------------------------------------------------------------

def classify_frigate_threat(
    fe: FrigateEvent,
    correlation: dict | None,
    session,
) -> tuple[ThreatLevel, str, dict]:
    """Classify threat level for a Frigate visual event.

    Args:
        fe: FrigateEvent ORM object (attached to session).
        correlation: Result from correlate_frigate_event(), or None.
        session: Active DB session.

    Returns:
        (level, alert_type, details) tuple.
    """
    label = fe.label or "object"
    camera = fe.camera
    current_hour = _local_hour()
    night = _is_night(current_hour)

    # Determine correlated device identity
    corr_device = None
    corr_tag = None
    corr_category = None
    corr_flagged = False

    if correlation and correlation.get("best_device_id"):
        corr_device = session.get(Device, correlation["best_device_id"])
        if corr_device:
            corr_tag = (
                session.query(Tag)
                .filter(Tag.device_id == corr_device.id)
                .first()
            )
            corr_category = corr_tag.category if corr_tag else "unknown"
            corr_flagged = bool(corr_tag and corr_tag.flagged)

    is_unknown = (
        corr_category == "unknown"
        or corr_category is None  # no correlation at all
    )
    is_known = corr_category in ("resident", "neighbor", "delivery", "ignore")

    base = {
        "confidence": fe.confidence,
        "zones": json.loads(fe.zones) if fe.zones else [],
    }
    if correlation:
        base["reason"] = (
            f"Correlated with {correlation['best_device_mac']} "
            f"({correlation['confidence']:.0%} confidence)"
        )
    else:
        base["reason"] = "No RF device correlated"

    # Only person detections escalate threat
    if label != "person":
        return (
            ThreatLevel.GREEN, f"frigate_{label}",
            {**base, "reason": f"{label.title()} on {camera}"},
        )

    # ── Person detections ──

    # RED: flagged device correlated with person on camera
    if corr_flagged:
        return (
            ThreatLevel.RED, "flagged_return",
            {**base, "reason":
             f"Flagged device {_dev(corr_tag, 'label') or corr_device.mac} "
             f"correlated with person on {camera}"},
        )

    # RED: person on camera at night with unknown/no RF
    if night and is_unknown:
        return (
            ThreatLevel.RED, "night_gate",
            {**base, "reason":
             f"Person on {camera} at {current_hour}:00 "
             f"(night window, {'unidentified' if not corr_device else 'unknown device ' + corr_device.mac})"},
        )

    # YELLOW: person on camera with unknown RF device (daytime)
    if is_unknown:
        return (
            ThreatLevel.YELLOW, "frigate_person_unknown",
            {**base, "reason":
             f"Person on {camera} — "
             f"{'no RF correlation' if not corr_device else 'unknown device ' + corr_device.mac}"},
        )

    # GREEN: person on camera with known device
    return (
        ThreatLevel.GREEN, "frigate_person",
        {**base, "reason":
         f"Person on {camera}, identified as "
         f"{corr_category}: {_dev(corr_device, 'alias') or _dev(corr_device, 'mac')}"},
    )


# ---------------------------------------------------------------------------
# Pipeline entry points (called by capture modules / frigate receiver)
# ---------------------------------------------------------------------------

def evaluate_device(device_id: int) -> dict:
    """Full evaluation pipeline for a device event.

    Called whenever a new RF event is recorded. Classifies threat,
    routes alert, auto-tags, and recomputes baseline.
    """
    results = {
        "device_id": device_id,
        "threat_level": None,
        "alert_type": None,
        "action": None,
        "auto_tagged": False,
        "baseline_updated": False,
    }

    # Classify and alert
    level, alert_type, details = classify_device_threat(device_id)
    results["threat_level"] = level.value
    results["alert_type"] = alert_type

    # Fetch device+tag for the alert (need attached objects)
    session = get_session()
    try:
        device = session.get(Device, device_id)
        tag = session.query(Tag).filter(Tag.device_id == device_id).first()
    finally:
        session.close()

    action = send_alert(
        level=level,
        alert_type=alert_type,
        device=device,
        tag=tag,
        details=details,
    )
    results["action"] = action

    # Auto-tag: probe-pattern rules first, visit-threshold fallback
    probe_tagged = auto_tag_by_probes(device_id)
    results["auto_tagged"] = probe_tagged or (not probe_tagged and auto_tag_device(device_id))

    # Recompute baseline periodically
    session = get_session()
    try:
        baseline = (
            session.query(Baseline)
            .filter(Baseline.device_id == device_id)
            .first()
        )
        stale = True
        if baseline and baseline.last_computed:
            age = (
                datetime.now(timezone.utc) - baseline.last_computed
            ).total_seconds()
            stale = age > 3600
    finally:
        session.close()

    if stale:
        b = compute_baseline(device_id)
        results["baseline_updated"] = b is not None

    return results


def evaluate_frigate_event(frigate_db_id: int) -> dict:
    """Full evaluation pipeline for a Frigate event.

    Called when a Frigate webhook/poll event is received.
    Correlates with RF, classifies threat, routes alert.
    """
    results = {
        "frigate_db_id": frigate_db_id,
        "correlation": None,
        "threat_level": None,
        "alert_type": None,
        "action": None,
    }

    # Correlate with RF devices
    corr = correlate_frigate_event(frigate_db_id)
    results["correlation"] = corr

    session = get_session()
    try:
        fe = session.get(FrigateEvent, frigate_db_id)
        if not fe:
            return results

        # Classify threat
        level, alert_type, details = classify_frigate_threat(
            fe, corr, session,
        )
        results["threat_level"] = level.value
        results["alert_type"] = alert_type

        # Resolve device+tag for the alert
        device = None
        tag = None
        if corr and corr.get("best_device_id"):
            device = session.get(Device, corr["best_device_id"])
            if device:
                tag = (
                    session.query(Tag)
                    .filter(Tag.device_id == device.id)
                    .first()
                )

        action = send_alert(
            level=level,
            alert_type=alert_type,
            device=device,
            tag=tag,
            camera=fe.camera,
            snapshot_path=fe.snapshot_path,
            details=details,
        )
        results["action"] = action

    except Exception as e:
        logger.error("Frigate evaluation pipeline error: %s", e)
    finally:
        session.close()

    return results


# ---------------------------------------------------------------------------
# Backward-compatible aliases
# ---------------------------------------------------------------------------

def run_correlation_for_device(device_id: int) -> dict:
    """Alias for evaluate_device (backward compat)."""
    return evaluate_device(device_id)


def run_correlation_for_frigate(frigate_db_id: int) -> dict:
    """Alias for evaluate_frigate_event (backward compat)."""
    return evaluate_frigate_event(frigate_db_id)


# ---------------------------------------------------------------------------
# Baseline computation
# ---------------------------------------------------------------------------

def compute_baseline(device_id: int) -> Baseline | None:
    """Compute or update behavioral baseline for a device.

    Analyzes visit history to determine typical hours, days,
    duration, and frequency.
    """
    cfg = config.get()
    baseline_days = cfg.get(
        "correlation", {}
    ).get("patterns", {}).get("baseline_days", 14)

    session = get_session()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=baseline_days)
        visits = (
            session.query(Visit)
            .filter(
                Visit.device_id == device_id,
                Visit.arrived_at >= cutoff,
                Visit.departed_at.isnot(None),
            )
            .all()
        )

        if len(visits) < 2:
            return None

        # Convert UTC timestamps to local timezone before extracting
        # hours/weekdays so baselines match _local_hour() comparisons.
        tz_name = cfg.get("general", {}).get("timezone", "UTC")
        try:
            from zoneinfo import ZoneInfo
            local_tz = ZoneInfo(tz_name)
        except Exception:
            local_tz = timezone.utc

        def _to_local(dt):
            if dt is None:
                return dt
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(local_tz)

        arrival_hours = [_to_local(v.arrived_at).hour for v in visits]
        departure_hours = [_to_local(v.departed_at).hour for v in visits if v.departed_at]

        typical_start = (
            Counter(arrival_hours).most_common(1)[0][0]
            if arrival_hours else None
        )
        typical_end = (
            Counter(departure_hours).most_common(1)[0][0]
            if departure_hours else None
        )

        visit_days = [_to_local(v.arrived_at).weekday() for v in visits]
        day_counts = Counter(visit_days)
        typical_days = ",".join(str(d) for d, _ in day_counts.most_common())

        durations = [v.duration_seconds for v in visits if v.duration_seconds]
        avg_duration = (
            int(sum(durations) / len(durations)) if durations else None
        )

        date_set = set(v.arrived_at.date() for v in visits)
        days_active = len(date_set) or 1
        avg_per_day = round(len(visits) / days_active, 2)

        baseline = (
            session.query(Baseline)
            .filter(Baseline.device_id == device_id)
            .first()
        )
        if not baseline:
            baseline = Baseline(device_id=device_id)
            session.add(baseline)

        baseline.typical_start_hour = typical_start
        baseline.typical_end_hour = typical_end
        baseline.typical_days = typical_days
        baseline.avg_visit_duration = avg_duration
        baseline.avg_visits_per_day = avg_per_day
        baseline.total_visits = len(visits)
        baseline.last_computed = datetime.now(timezone.utc)

        session.commit()
        session.refresh(baseline)
        session.expunge(baseline)

        logger.info(
            "Baseline computed for device %d: hours=%s-%s avg_dur=%ss "
            "visits/day=%.1f",
            device_id, typical_start, typical_end, avg_duration, avg_per_day,
        )
        return baseline

    except Exception as e:
        session.rollback()
        logger.error("Baseline computation failed for device %d: %s",
                     device_id, e)
        return None
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Auto-tagging
# ---------------------------------------------------------------------------

# Probe-pattern classification constants
_RESIDENT_NETWORKS = frozenset({"valenciavalencia", "valenciavalencia.menudencia"})
_NEIGHBOR_NETWORKS = frozenset({
    "verizon_6z6jcd", "geturown", "trojanmade", "ortizfamily",
    "velasquez", "spectrumsetup", "att", "netgear_orbi", "familyb", "catalpa",
})
_BORDER_PREFIXES = ("infinitum", "totalplay", "izzi", "telmex")


def auto_tag_by_probes(device_id: int) -> bool:
    """Tag a device based on its probe request SSID patterns.

    Rules (applied in priority order):
      1. Resident  — probes for any known resident network SSID.
      2. Border commuter — probes for Mexican carrier SSIDs
         (INFINITUM*, Totalplay*, izzi*, Telmex*).
      3. Neighbor  — ALL probed SSIDs belong to the neighbor network set.

    Skips devices already tagged with category != 'unknown' and
    devices with randomized MACs.

    Returns True if a new tag was applied.
    """
    session = get_session()
    try:
        device = session.get(Device, device_id)
        if not device:
            return False

        if device.is_randomized:
            return False

        tag = session.query(Tag).filter(Tag.device_id == device_id).first()
        if tag and tag.category != "unknown":
            return False

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
        if not ssid_rows:
            return False

        ssids = [row[0] for row in ssid_rows]
        ssids_lower = [s.lower() for s in ssids]
        ssids_lower_set = set(ssids_lower)

        new_category = None
        new_notes = None

        # Rule 1: Resident network
        if any(s in _RESIDENT_NETWORKS for s in ssids_lower):
            new_category = "resident"
            matched = [s for s in ssids if s.lower() in _RESIDENT_NETWORKS]
            new_notes = f"Probed resident network(s): {', '.join(matched)}"

        # Rule 2: Border commuter (Mexican carrier)
        elif any(s.startswith(_BORDER_PREFIXES) for s in ssids_lower):
            new_category = "border_commuter"
            matched = [
                s for s in ssids
                if s.lower().startswith(_BORDER_PREFIXES)
            ]
            new_notes = f"Mexican carrier connection — probed: {', '.join(matched)}"

        # Rule 3: Neighbor only (every probed SSID is a neighbor network)
        elif ssids_lower_set.issubset(_NEIGHBOR_NETWORKS):
            new_category = "neighbor"
            new_notes = f"Probes only neighbor networks: {', '.join(ssids)}"

        if not new_category:
            return False

        if not tag:
            tag = Tag(device_id=device_id)
            session.add(tag)

        tag.category = new_category
        tag.tagged_by = "auto_probe"
        tag.tagged_at = datetime.now(timezone.utc)
        tag.notes = new_notes
        session.commit()

        logger.info(
            "Probe-tagged device %s as '%s': %s",
            device.mac, new_category, new_notes,
        )
        return True

    except Exception as e:
        session.rollback()
        logger.error("Probe auto-tag failed for device %d: %s", device_id, e)
        return False
    finally:
        session.close()


def auto_tag_device(device_id: int) -> bool:
    """Promote 'unknown' to 'visitor' after visit threshold."""
    cfg = config.get()
    tagging = cfg.get("tagging", {})
    if not tagging.get("auto_tag_known", True):
        return False

    threshold = tagging.get("known_threshold", 5)

    session = get_session()
    try:
        device = session.get(Device, device_id)
        if not device:
            return False

        tag = session.query(Tag).filter(Tag.device_id == device_id).first()
        if not tag or tag.category != "unknown":
            return False

        visit_count = (
            session.query(Visit)
            .filter(Visit.device_id == device_id)
            .count()
        )
        if visit_count < threshold:
            return False

        tag.category = "visitor"
        tag.tagged_by = "auto"
        tag.tagged_at = datetime.now(timezone.utc)
        tag.notes = f"Auto-tagged after {visit_count} visits"
        session.commit()

        logger.info("Auto-tagged device %s as 'visitor' after %d visits",
                     device.mac, visit_count)
        return True

    except Exception as e:
        session.rollback()
        logger.error("Auto-tag failed for device %d: %s", device_id, e)
        return False
    finally:
        session.close()
