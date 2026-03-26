#!/usr/bin/env python3
"""SENTINEL Baseline Seeder.

Two-phase backfill:
  Phase 1 — Per-device baselines: runs compute_baseline() for every device
             with 2+ completed visits in the last 14 days.
  Phase 2 — Environment baselines: computes hourly/daily activity norms
             across all sensors (WiFi probes, BT events, Frigate detections,
             SDR signals). Stored in the existing baselines table using a
             sentinel device_id=0 convention, and written to a JSON sidecar
             at /opt/sentinel/data/env_baselines.json for fast dashboard reads.

Usage:
    cd /opt/sentinel
    python3 seed_baselines.py [--dry-run] [--days N] [--verbose]
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/opt/sentinel")

import config
from database import (
    Baseline,
    Device,
    Event,
    FrigateEvent,
    ProbeRequest,
    SdrSignal,
    Visit,
    get_session,
    init_db,
)
from analysis.correlation import compute_baseline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.seed_baselines")

ENV_BASELINE_PATH = Path("/opt/sentinel/data/env_baselines.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _local_hour(dt, tz_name="America/Chicago"):
    """Convert a UTC datetime to local hour."""
    try:
        from zoneinfo import ZoneInfo
        return _utc(dt).astimezone(ZoneInfo(tz_name)).hour
    except Exception:
        return _utc(dt).hour


# ---------------------------------------------------------------------------
# Phase 1: Per-device baselines
# ---------------------------------------------------------------------------

def seed_device_baselines(days: int, dry_run: bool) -> dict:
    cfg = config.get()
    tz_name = cfg.get("general", {}).get("timezone", "UTC")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    session = get_session()
    stats = {"eligible": 0, "computed": 0, "skipped_dry": 0, "failed": 0, "already_fresh": 0}

    try:
        # Find all device_ids with 2+ completed visits in the window
        from sqlalchemy import func
        eligible_ids = (
            session.query(Visit.device_id)
            .filter(
                Visit.arrived_at >= cutoff,
                Visit.departed_at.isnot(None),
            )
            .group_by(Visit.device_id)
            .having(func.count(Visit.id) >= 2)
            .all()
        )
        device_ids = [row[0] for row in eligible_ids]
        stats["eligible"] = len(device_ids)
        logger.info("Phase 1: %d devices eligible for baseline computation", len(device_ids))

    finally:
        session.close()

    for i, device_id in enumerate(device_ids, 1):
        # Check freshness — skip if computed within last hour
        session = get_session()
        try:
            existing = (
                session.query(Baseline)
                .filter(Baseline.device_id == device_id)
                .first()
            )
            if existing and existing.last_computed:
                age_hours = (
                    datetime.now(timezone.utc) - _utc(existing.last_computed)
                ).total_seconds() / 3600
                if age_hours < 1:
                    stats["already_fresh"] += 1
                    continue
        finally:
            session.close()

        if dry_run:
            stats["skipped_dry"] += 1
            if i <= 5 or i % 500 == 0:
                logger.info("  [dry-run] Would compute baseline for device_id=%d", device_id)
            continue

        result = compute_baseline(device_id)
        if result:
            stats["computed"] += 1
            if i <= 10 or i % 500 == 0:
                logger.info(
                    "  [%d/%d] device_id=%-6d  hours=%s-%s  visits/day=%.1f  avg_dur=%ss",
                    i, len(device_ids), device_id,
                    result.typical_start_hour, result.typical_end_hour,
                    result.avg_visits_per_day or 0,
                    result.avg_visit_duration or 0,
                )
        else:
            stats["failed"] += 1

    return stats


# ---------------------------------------------------------------------------
# Phase 2: Environment baselines
# ---------------------------------------------------------------------------

def compute_environment_baselines(days: int, dry_run: bool) -> dict:
    """Compute hourly + daily activity norms across the whole environment.

    Produces a JSON structure:
    {
      "generated_at": "...",
      "window_days": N,
      "timezone": "...",
      "hourly": {
        "wifi_probes":    [avg_count_per_hour_0..23],
        "bt_events":      [...],
        "frigate_person": [...],
        "frigate_car":    [...],
        "sdr_tpms":       [...],
        "sdr_weather":    [...]
      },
      "daily": {
        "wifi_probes":    [avg_Mon..Sun],
        ...
      },
      "peaks": {
        "wifi_probes":    {"hour": H, "count": N},
        ...
      },
      "quiet_hours": [0, 1, 2, ...],   # hours below 10% of peak
      "busy_hours":  [8, 9, 10, ...],  # hours above 75% of peak
    }
    """
    cfg = config.get()
    tz_name = cfg.get("general", {}).get("timezone", "UTC")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    now = datetime.now(timezone.utc)

    logger.info("Phase 2: Computing environment baselines over last %d days (tz=%s)", days, tz_name)

    session = get_session()
    try:
        # --- WiFi probes per hour ---
        probes = (
            session.query(ProbeRequest.timestamp)
            .filter(ProbeRequest.timestamp >= cutoff)
            .all()
        )
        probe_hours = defaultdict(int)
        probe_days = defaultdict(int)
        for (ts,) in probes:
            h = _local_hour(ts, tz_name)
            probe_hours[h] += 1
            probe_days[_utc(ts).weekday()] += 1

        # --- BT events per hour ---
        bt_events = (
            session.query(Event.timestamp)
            .filter(
                Event.timestamp >= cutoff,
                Event.event_type.in_(["bt_ble", "bt_classic"]),
            )
            .all()
        )
        bt_hours = defaultdict(int)
        bt_days = defaultdict(int)
        for (ts,) in bt_events:
            bt_hours[_local_hour(ts, tz_name)] += 1
            bt_days[_utc(ts).weekday()] += 1

        # --- Frigate events per hour (person + car separate) ---
        frigate_events = (
            session.query(FrigateEvent.timestamp, FrigateEvent.label)
            .filter(FrigateEvent.timestamp >= cutoff)
            .all()
        )
        person_hours = defaultdict(int)
        car_hours = defaultdict(int)
        person_days = defaultdict(int)
        car_days = defaultdict(int)
        for ts, label in frigate_events:
            h = _local_hour(ts, tz_name)
            d = _utc(ts).weekday()
            if label == "person":
                person_hours[h] += 1
                person_days[d] += 1
            elif label == "car":
                car_hours[h] += 1
                car_days[d] += 1

        # --- SDR signals per hour ---
        sdr_signals = (
            session.query(SdrSignal.timestamp, SdrSignal.signal_class)
            .filter(SdrSignal.timestamp >= cutoff)
            .all()
        )
        tpms_hours = defaultdict(int)
        weather_hours = defaultdict(int)
        tpms_days = defaultdict(int)
        weather_days = defaultdict(int)
        for ts, sig_class in sdr_signals:
            h = _local_hour(ts, tz_name)
            d = _utc(ts).weekday()
            if sig_class == "tpms":
                tpms_hours[h] += 1
                tpms_days[d] += 1
            elif sig_class == "weather":
                weather_hours[h] += 1
                weather_days[d] += 1

    finally:
        session.close()

    # Normalize to averages per day-of-data
    # Count how many of each weekday appeared in our window
    day_counts = defaultdict(int)
    d = cutoff.date()
    while d <= now.date():
        day_counts[d.weekday()] += 1
        d += timedelta(days=1)

    total_days = max(days, 1)

    def _hourly_avg(counter):
        """Return list of 24 avg-per-day values, rounded to 2dp."""
        return [round(counter.get(h, 0) / total_days, 2) for h in range(24)]

    def _daily_avg(counter):
        """Return list of 7 avg-per-weekday values (Mon=0..Sun=6)."""
        return [
            round(counter.get(d, 0) / max(day_counts[d], 1), 2)
            for d in range(7)
        ]

    def _peaks(hourly_list):
        peak_val = max(hourly_list) if hourly_list else 0
        peak_hour = hourly_list.index(peak_val) if peak_val > 0 else None
        return {"hour": peak_hour, "avg_per_day": peak_val}

    def _quiet_hours(hourly_list, threshold=0.10):
        peak = max(hourly_list) if hourly_list else 0
        if peak == 0:
            return list(range(24))
        return [h for h, v in enumerate(hourly_list) if v < peak * threshold]

    def _busy_hours(hourly_list, threshold=0.75):
        peak = max(hourly_list) if hourly_list else 0
        if peak == 0:
            return []
        return [h for h, v in enumerate(hourly_list) if v >= peak * threshold]

    wifi_hourly = _hourly_avg(probe_hours)
    bt_hourly   = _hourly_avg(bt_hours)
    per_hourly  = _hourly_avg(person_hours)
    car_hourly  = _hourly_avg(car_hours)
    tpms_hourly = _hourly_avg(tpms_hours)
    wx_hourly   = _hourly_avg(weather_hours)

    # Composite activity signal: frigate_car + sdr_tpms per hour.
    # WiFi probes are flat 24/7 due to randomised MACs and constant passive
    # probing, so they are useless for determining quiet vs. busy periods.
    # Frigate car detections and TPMS signals both track real vehicle movement
    # and therefore reflect genuine human activity rhythms.
    composite_hourly = [
        round(car_hourly[h] + tpms_hourly[h], 2) for h in range(24)
    ]

    env = {
        "generated_at": now.isoformat(),
        "window_days": days,
        "timezone": tz_name,
        "sample_counts": {
            "wifi_probes":    len(probes),
            "bt_events":      len(bt_events),
            "frigate_person": sum(person_hours.values()),
            "frigate_car":    sum(car_hours.values()),
            "sdr_tpms":       sum(tpms_hours.values()),
            "sdr_weather":    sum(weather_hours.values()),
        },
        "hourly": {
            "wifi_probes":       wifi_hourly,
            "bt_events":         bt_hourly,
            "frigate_person":    per_hourly,
            "frigate_car":       car_hourly,
            "sdr_tpms":          tpms_hourly,
            "sdr_weather":       wx_hourly,
            "composite_activity": composite_hourly,
        },
        "daily": {
            "wifi_probes":    _daily_avg(probe_days),
            "bt_events":      _daily_avg(bt_days),
            "frigate_person": _daily_avg(person_days),
            "frigate_car":    _daily_avg(car_days),
            "sdr_tpms":       _daily_avg(tpms_days),
            "sdr_weather":    _daily_avg(weather_days),
        },
        "peaks": {
            "wifi_probes":    _peaks(wifi_hourly),
            "bt_events":      _peaks(bt_hourly),
            "frigate_person": _peaks(per_hourly),
            "frigate_car":    _peaks(car_hourly),
            "sdr_tpms":       _peaks(tpms_hourly),
            "sdr_weather":    _peaks(wx_hourly),
            "composite_activity": _peaks(composite_hourly),
        },
        # Quiet/busy hours derived from composite (frigate_car + sdr_tpms),
        # which reflects real vehicle/human activity rhythms.
        "quiet_hours": _quiet_hours(composite_hourly),
        "busy_hours":  _busy_hours(composite_hourly),
    }

    if not dry_run:
        ENV_BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        ENV_BASELINE_PATH.write_text(json.dumps(env, indent=2))
        logger.info("Environment baselines written to %s", ENV_BASELINE_PATH)
    else:
        logger.info("[dry-run] Would write environment baselines to %s", ENV_BASELINE_PATH)

    # Print a human-readable summary
    logger.info("--- Environment Baseline Summary ---")
    logger.info("Sample window: %d days  |  Timezone: %s", days, tz_name)
    for sensor, counts in env["sample_counts"].items():
        peak = env["peaks"][sensor]
        logger.info(
            "  %-18s  %6d events  |  peak hour %02d:00 (~%.1f/day)",
            sensor, counts,
            peak["hour"] if peak["hour"] is not None else -1,
            peak["avg_per_day"],
        )
    logger.info(
        "Quiet hours (<10%% of composite peak): %s",
        str(env["quiet_hours"]),
    )
    logger.info(
        "Busy  hours (>75%% of composite peak): %s",
        str(env["busy_hours"]),
    )

    return env


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SENTINEL baseline seeder")
    parser.add_argument("--days", type=int, default=14,
                        help="Lookback window in days (default: 14)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Analyse only, write nothing")
    parser.add_argument("--verbose", action="store_true",
                        help="Debug-level logging")
    parser.add_argument("--env-only", action="store_true",
                        help="Skip per-device baselines, run env baseline only")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.dry_run:
        logger.info("=== DRY RUN — no changes will be written ===")

    init_db()

    # Phase 1
    if not args.env_only:
        logger.info("=== Phase 1: Per-device baselines ===")
        d_stats = seed_device_baselines(args.days, args.dry_run)
        logger.info(
            "Phase 1 complete: eligible=%d  computed=%d  fresh=%d  failed=%d  dry=%d",
            d_stats["eligible"], d_stats["computed"],
            d_stats["already_fresh"], d_stats["failed"], d_stats["skipped_dry"],
        )
    else:
        logger.info("Skipping Phase 1 (--env-only)")

    # Phase 2
    logger.info("=== Phase 2: Environment baselines ===")
    compute_environment_baselines(args.days, args.dry_run)

    logger.info("=== Seeding complete ===")


if __name__ == "__main__":
    main()
