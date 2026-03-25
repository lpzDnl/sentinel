#!/usr/bin/env python3
"""SENTINEL Web Dashboard.

Flask-SocketIO application providing a real-time cyberpunk-themed
command center for monitoring RF captures, Frigate events,
device intelligence, and alert history.

Run standalone:  python3 -m web.app
Run as service:  systemctl start sentinel-web
"""

import json
import logging
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from flask_socketio import SocketIO

sys.path.insert(0, "/opt/sentinel")

import config
from database import (
    AlertLog,
    Baseline,
    Device,
    Event,
    FrigateEvent,
    ProbeRequest,
    SdrDeviceTag,
    SdrFrigateCorrelation,
    SdrSignal,
    Tag,
    VehicleProfile,
    Visit,
    get_session,
    init_db,
)

logger = logging.getLogger("sentinel.web")

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> tuple[Flask, SocketIO]:
    cfg = config.get()
    web_cfg = cfg.get("web", {})

    app = Flask(
        __name__,
        template_folder="/opt/sentinel/web/templates",
        static_folder="/opt/sentinel/web/static",
    )
    app.config["SECRET_KEY"] = web_cfg.get("secret_key", "sentinel-dev-key")

    sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    @app.context_processor
    def inject_globals():
        return {"now_utc": datetime.now(timezone.utc), "config": cfg}

    snapshot_dir = cfg.get("frigate", {}).get("snapshot_dir", "/opt/sentinel/data/snapshots")
    tz_name = cfg.get("general", {}).get("timezone", "UTC")

    try:
        from zoneinfo import ZoneInfo
        _local_tz = ZoneInfo(tz_name)
    except Exception:
        _local_tz = timezone.utc

    def _local_today_start_utc():
        """Return UTC datetime for midnight today in the configured local timezone."""
        local_now = datetime.now(_local_tz)
        local_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        return local_midnight.astimezone(timezone.utc)

    # -- Jinja2 filters --

    @app.template_filter("localtime")
    def localtime_filter(dt):
        if dt is None:
            return "—"
        try:
            from zoneinfo import ZoneInfo
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            local = dt.astimezone(ZoneInfo(tz_name))
            return local.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return dt.strftime("%Y-%m-%d %H:%M:%S")

    @app.template_filter("timeago")
    def timeago_filter(dt):
        if dt is None:
            return "never"
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = now - dt
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}s ago"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"

    @app.template_filter("duration")
    def duration_filter(seconds):
        if seconds is None:
            return "—"
        seconds = int(seconds)
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

    @app.template_filter("is_active")
    def is_active_filter(dt, minutes=10):
        if dt is None:
            return False
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now - dt).total_seconds() < minutes * 60

    @app.template_filter("tojson_safe")
    def tojson_safe_filter(obj):
        from markupsafe import Markup
        return Markup(json.dumps(obj))

    # -- Helper functions --

    def get_stats(session):
        now = datetime.now(timezone.utc)
        today_start = _local_today_start_utc()
        active_window = now - timedelta(minutes=10)

        total_devices = session.query(Device).count()
        active_devices = (
            session.query(Device)
            .filter(Device.last_seen >= active_window)
            .count()
        )
        events_today = (
            session.query(Event)
            .filter(Event.timestamp >= today_start)
            .count()
        )
        alerts_today = (
            session.query(AlertLog)
            .filter(AlertLog.timestamp >= today_start)
            .count()
        )
        new_devices_today = (
            session.query(Device)
            .filter(Device.first_seen >= today_start)
            .count()
        )
        frigate_today = (
            session.query(FrigateEvent)
            .filter(FrigateEvent.timestamp >= today_start)
            .count()
        )
        open_visits = (
            session.query(Visit)
            .filter(Visit.departed_at.is_(None))
            .count()
        )

        return {
            "total_devices": total_devices,
            "active_devices": active_devices,
            "events_today": events_today,
            "alerts_today": alerts_today,
            "new_devices_today": new_devices_today,
            "frigate_today": frigate_today,
            "open_visits": open_visits,
            "timestamp": now.isoformat(),
        }

    def serialize_device(dev, tag=None):
        return {
            "id": dev.id,
            "mac": dev.mac,
            "device_type": dev.device_type,
            "vendor": dev.vendor,
            "hostname": dev.hostname,
            "alias": dev.alias,
            "is_randomized": dev.is_randomized,
            "first_seen": dev.first_seen.isoformat() if dev.first_seen else None,
            "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
            "total_sightings": dev.total_sightings,
            "tag_category": tag.category if tag else "unknown",
            "tag_label": tag.label if tag else None,
            "tag_flagged": tag.flagged if tag else False,
            "notes": dev.notes,
        }

    def serialize_event(evt, device=None, tag=None):
        return {
            "id": evt.id,
            "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
            "event_type": evt.event_type,
            "source": evt.source,
            "device_id": device.id if device else None,
            "device_mac": device.mac if device else None,
            "device_vendor": device.vendor if device else None,
            "device_alias": device.alias if device else None,
            "tag_category": tag.category if tag else None,
            "tag_label": tag.label if tag else None,
            "tag_flagged": tag.flagged if tag else False,
            "ssid": evt.ssid,
            "rssi": evt.rssi,
            "channel": evt.channel,
            "camera": evt.camera,
            "frigate_event_id": evt.frigate_event_id,
            "snapshot_path": evt.snapshot_path,
            "confidence": evt.confidence,
        }

    # -- Page routes --

    @app.route("/")
    def dashboard():
        session = get_session()
        try:
            stats = get_stats(session)
            now = datetime.now(timezone.utc)
            active_window = now - timedelta(minutes=10)

            active = (
                session.query(Device, Tag)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(Device.last_seen >= active_window)
                .order_by(Device.last_seen.desc())
                .limit(50)
                .all()
            )

            recent_events = (
                session.query(Event, Device, Tag)
                .outerjoin(Device, Event.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .order_by(Event.timestamp.desc())
                .limit(30)
                .all()
            )

            # 24h hourly event counts
            hourly = []
            for h in range(24):
                hour_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23 - h)
                hour_end = hour_start + timedelta(hours=1)
                count = (
                    session.query(Event)
                    .filter(Event.timestamp.between(hour_start, hour_end))
                    .count()
                )
                hourly.append({"hour": hour_start.strftime("%H:%M"), "count": count})

            # Device type breakdown
            type_counts = {}
            for dtype in ["wifi", "bluetooth_le", "bluetooth_classic", "unknown"]:
                type_counts[dtype] = (
                    session.query(Device)
                    .filter(Device.device_type == dtype)
                    .count()
                )

            return render_template(
                "dashboard.html",
                stats=stats,
                active_devices=active,
                recent_events=recent_events,
                hourly_data=hourly,
                type_counts=type_counts,
            )
        finally:
            session.close()

    @app.route("/devices")
    def devices():
        session = get_session()
        try:
            search = request.args.get("q", "").strip()
            tag_filter = request.args.get("tag", "").strip()
            type_filter = request.args.get("type", "").strip()
            page = max(1, request.args.get("page", 1, type=int))
            per_page = 50

            q = (
                session.query(Device, Tag)
                .outerjoin(Tag, Device.id == Tag.device_id)
            )
            if search:
                like = f"%{search}%"
                q = q.filter(
                    (Device.mac.ilike(like))
                    | (Device.vendor.ilike(like))
                    | (Device.hostname.ilike(like))
                    | (Device.alias.ilike(like))
                    | (Tag.label.ilike(like))
                )
            if tag_filter:
                q = q.filter(Tag.category == tag_filter)
            if type_filter:
                q = q.filter(Device.device_type == type_filter)

            total = q.count()
            devices_list = (
                q.order_by(Device.last_seen.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            return render_template(
                "devices.html",
                devices=devices_list,
                search=search,
                tag_filter=tag_filter,
                type_filter=type_filter,
                page=page,
                per_page=per_page,
                total=total,
            )
        finally:
            session.close()

    @app.route("/devices/<int:device_id>")
    def device_detail(device_id):
        session = get_session()
        try:
            device = session.get(Device, device_id)
            if not device:
                return render_template("404.html"), 404

            tag = session.query(Tag).filter(Tag.device_id == device_id).first()
            baseline = session.query(Baseline).filter(Baseline.device_id == device_id).first()

            visits = (
                session.query(Visit)
                .filter(Visit.device_id == device_id)
                .order_by(Visit.arrived_at.desc())
                .limit(50)
                .all()
            )

            events = (
                session.query(Event)
                .filter(Event.device_id == device_id)
                .order_by(Event.timestamp.desc())
                .limit(100)
                .all()
            )

            probes = (
                session.query(ProbeRequest)
                .filter(ProbeRequest.device_id == device_id)
                .order_by(ProbeRequest.timestamp.desc())
                .limit(50)
                .all()
            )

            frigate_correlated = (
                session.query(FrigateEvent)
                .filter(FrigateEvent.correlated_device_id == device_id)
                .order_by(FrigateEvent.timestamp.desc())
                .limit(20)
                .all()
            )

            # Unique SSIDs probed
            ssids = (
                session.query(ProbeRequest.ssid)
                .filter(ProbeRequest.device_id == device_id, ProbeRequest.ssid.isnot(None))
                .distinct()
                .all()
            )
            ssid_list = [s[0] for s in ssids if s[0]]

            categories = config.get().get("tagging", {}).get(
                "categories", ["resident", "neighbor", "delivery", "visitor", "unknown", "flagged", "ignore"]
            )

            return render_template(
                "device_detail.html",
                device=device,
                tag=tag,
                baseline=baseline,
                visits=visits,
                events=events,
                probes=probes,
                frigate_events=frigate_correlated,
                ssid_list=ssid_list,
                categories=categories,
            )
        finally:
            session.close()

    @app.route("/timeline")
    def timeline():
        session = get_session()
        try:
            type_filter = request.args.get("type", "").strip()
            camera_filter = request.args.get("camera", "").strip()
            page = max(1, request.args.get("page", 1, type=int))
            per_page = 50

            q = (
                session.query(Event, Device, Tag)
                .outerjoin(Device, Event.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
            )
            if type_filter:
                q = q.filter(Event.event_type == type_filter)
            if camera_filter:
                q = q.filter(Event.camera == camera_filter)

            total = q.count()
            events = (
                q.order_by(Event.timestamp.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            event_types = [r[0] for r in session.query(Event.event_type).distinct().all()]
            cameras = [r[0] for r in session.query(Event.camera).filter(Event.camera.isnot(None)).distinct().all()]

            return render_template(
                "timeline.html",
                events=events,
                type_filter=type_filter,
                camera_filter=camera_filter,
                event_types=event_types,
                cameras=cameras,
                page=page,
                per_page=per_page,
                total=total,
            )
        finally:
            session.close()

    @app.route("/alerts")
    def alerts():
        session = get_session()
        try:
            type_filter = request.args.get("type", "").strip()
            level_filter = request.args.get("level", "").strip()
            page = max(1, request.args.get("page", 1, type=int))
            per_page = 50

            q = session.query(AlertLog)
            if type_filter:
                q = q.filter(AlertLog.alert_type.contains(type_filter))
            if level_filter:
                q = q.filter(AlertLog.alert_type.startswith(level_filter + ":"))

            total = q.count()
            alert_list = (
                q.order_by(AlertLog.timestamp.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            # Extract unique type portions (after "level:" prefix)
            raw_types = [r[0] for r in session.query(AlertLog.alert_type).distinct().all()]
            alert_types = sorted(set(
                t.split(":", 1)[1] if ":" in t else t for t in raw_types
            ))

            return render_template(
                "alerts.html",
                alerts=alert_list,
                type_filter=type_filter,
                level_filter=level_filter,
                alert_types=alert_types,
                page=page,
                per_page=per_page,
                total=total,
            )
        finally:
            session.close()

    @app.route("/baselines")
    def baselines():
        session = get_session()
        try:
            baselines_list = (
                session.query(Baseline, Device, Tag)
                .join(Device, Baseline.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .order_by(Baseline.avg_visits_per_day.desc())
                .limit(50)
                .all()
            )

            # Build heatmap data: hour (0-23) x day (0-6)
            heatmap = [[0] * 7 for _ in range(24)]
            visits = (
                session.query(Visit)
                .filter(Visit.arrived_at.isnot(None))
                .all()
            )
            for v in visits:
                try:
                    local_dt = v.arrived_at
                    if local_dt.tzinfo is None:
                        local_dt = local_dt.replace(tzinfo=timezone.utc)
                    local_dt = local_dt.astimezone(_local_tz)
                    heatmap[local_dt.hour][local_dt.weekday()] += 1
                except (IndexError, AttributeError):
                    pass

            # Top visitors
            from sqlalchemy import func
            top_visitors = (
                session.query(Device, Tag, func.count(Visit.id).label("visit_count"))
                .join(Visit, Device.id == Visit.device_id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .group_by(Device.id)
                .order_by(func.count(Visit.id).desc())
                .limit(15)
                .all()
            )

            return render_template(
                "baselines.html",
                baselines=baselines_list,
                heatmap=heatmap,
                top_visitors=top_visitors,
            )
        finally:
            session.close()

    @app.route("/intelligence")
    def intelligence():
        session = get_session()
        try:
            from sqlalchemy import func
            now = datetime.now(timezone.utc)
            cutoff_24h = now - timedelta(hours=24)
            cutoff_7d  = now - timedelta(days=7)

            # 1. High-threat devices: RED/YELLOW alerts in last 24h
            threat_rows = (
                session.query(AlertLog, Device, Tag)
                .outerjoin(Device, AlertLog.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(
                    AlertLog.timestamp >= cutoff_24h,
                    (AlertLog.alert_type.startswith("red:"))
                    | (AlertLog.alert_type.startswith("yellow:")),
                )
                .order_by(AlertLog.timestamp.desc())
                .limit(50)
                .all()
            )
            # Deduplicate by device_id, keep highest-level alert per device
            seen_device_ids = set()
            high_threat = []
            for alert, dev, tag in threat_rows:
                key = dev.id if dev else None
                if key in seen_device_ids:
                    continue
                seen_device_ids.add(key)
                parts = alert.alert_type.split(":", 1)
                lvl   = parts[0] if len(parts) > 1 else ""
                atype = parts[1] if len(parts) > 1 else alert.alert_type
                high_threat.append({
                    "alert":  alert,
                    "device": dev,
                    "tag":    tag,
                    "level":  lvl,
                    "atype":  atype,
                })

            # 2. New unknown devices: first seen in last 24h, no vendor, no non-unknown tag
            new_unknown = (
                session.query(Device, Tag)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(
                    Device.first_seen >= cutoff_24h,
                    (Device.vendor.is_(None) | (Device.vendor == "")),
                    (Tag.id.is_(None) | (Tag.category == "unknown")),
                )
                .order_by(Device.first_seen.desc())
                .limit(50)
                .all()
            )

            # 3. Recurring TPMS vehicles: seen 3+ times in last 7 days, grouped by device_uid
            tpms_counts = (
                session.query(
                    SdrSignal.device_uid,
                    SdrSignal.model,
                    func.count(SdrSignal.id).label("sightings"),
                    func.min(SdrSignal.timestamp).label("first_seen"),
                    func.max(SdrSignal.timestamp).label("last_seen"),
                    func.avg(SdrSignal.rssi).label("avg_rssi"),
                )
                .filter(
                    SdrSignal.signal_class == "tpms",
                    SdrSignal.timestamp >= cutoff_7d,
                )
                .group_by(SdrSignal.device_uid, SdrSignal.model)
                .having(func.count(SdrSignal.id) >= 3)
                .order_by(func.count(SdrSignal.id).desc())
                .limit(30)
                .all()
            )

            # Fetch SDR tags for those device_uids
            tpms_uids = [r.device_uid for r in tpms_counts if r.device_uid]
            tpms_tags = {}
            if tpms_uids:
                rows = session.query(SdrDeviceTag).filter(SdrDeviceTag.device_uid.in_(tpms_uids)).all()
                tpms_tags = {t.device_uid: t for t in rows}

            # 4. Night activity: events between 00:00–05:00 local time in last 24h
            # Build per-hour UTC windows for local hours 0-4 across last 24h
            local_now = datetime.now(_local_tz)
            night_events = []
            for h in range(5):  # hours 0-4
                local_night = local_now.replace(hour=h, minute=0, second=0, microsecond=0)
                # Could be today or yesterday depending on current local hour
                if local_night > local_now:
                    local_night -= timedelta(days=1)
                window_start = local_night.astimezone(timezone.utc)
                window_end   = window_start + timedelta(hours=1)
                if window_start >= cutoff_24h:
                    evts = (
                        session.query(Event, Device, Tag)
                        .outerjoin(Device, Event.device_id == Device.id)
                        .outerjoin(Tag, Device.id == Tag.device_id)
                        .filter(Event.timestamp.between(window_start, window_end))
                        .order_by(Event.timestamp.desc())
                        .limit(20)
                        .all()
                    )
                    night_events.extend(evts)

            night_events.sort(key=lambda x: x[0].timestamp, reverse=True)

            # 5. Activity heatmap: visits by hour of day (UTC-6) and category, last 7 days
            _MTN = timedelta(hours=-6)
            _heatmap_cats = ["resident", "neighbor", "unknown"]
            heatmap_data = {cat: [0] * 24 for cat in _heatmap_cats}

            visit_rows = (
                session.query(Visit.arrived_at, Tag.category)
                .outerjoin(Device, Visit.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(Visit.arrived_at >= cutoff_7d)
                .all()
            )
            for arrived_at, category in visit_rows:
                if arrived_at is None:
                    continue
                local_dt = arrived_at.replace(tzinfo=timezone.utc) + _MTN
                hour = local_dt.hour
                cat = category if category in _heatmap_cats else "unknown"
                heatmap_data[cat][hour] += 1

            heatmap_max = max(
                (c for row in heatmap_data.values() for c in row), default=1
            ) or 1

            return render_template(
                "intelligence.html",
                high_threat=high_threat,
                new_unknown=new_unknown,
                tpms_counts=tpms_counts,
                tpms_tags=tpms_tags,
                night_events=night_events,
                heatmap_data=heatmap_data,
                heatmap_max=heatmap_max,
                generated_at=now,
            )
        finally:
            session.close()

    @app.route("/sdr")
    def sdr():
        session = get_session()
        try:
            class_filter = request.args.get("class", "").strip()
            page = max(1, request.args.get("page", 1, type=int))
            per_page = 100

            q = session.query(SdrSignal)
            if class_filter:
                q = q.filter(SdrSignal.signal_class == class_filter)

            total = q.count()
            signals = (
                q.order_by(SdrSignal.timestamp.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            from sqlalchemy import func
            class_counts = dict(
                session.query(SdrSignal.signal_class, func.count(SdrSignal.id))
                .group_by(SdrSignal.signal_class)
                .all()
            )

            # Build tag lookup keyed by device_uid for signals on this page
            uids = list({s.device_uid for s in signals if s.device_uid})
            sdr_tags = {}
            if uids:
                rows = (
                    session.query(SdrDeviceTag)
                    .filter(SdrDeviceTag.device_uid.in_(uids))
                    .all()
                )
                sdr_tags = {t.device_uid: t for t in rows}

            return render_template(
                "sdr.html",
                signals=signals,
                class_filter=class_filter,
                page=page,
                per_page=per_page,
                total=total,
                class_counts=class_counts,
                sdr_tags=sdr_tags,
            )
        finally:
            session.close()

    @app.route("/vehicles")
    def vehicles():
        session = get_session()
        try:
            profiles = (
                session.query(VehicleProfile)
                .order_by(VehicleProfile.sighting_count.desc())
                .all()
            )
            return render_template("vehicles.html", profiles=profiles)
        finally:
            session.close()

    @app.route("/border")
    def border():
        session = get_session()
        try:
            from sqlalchemy import func, or_

            # Mexican carrier SSID patterns
            MX_PATTERNS = [
                "%INFINITUM%",
                "%Totalplay%",
                "%totalplay%",
                "%izzi%",
                "%Telmex%",
                "%telmex%",
            ]

            mx_filter = or_(*[ProbeRequest.ssid.ilike(p) for p in MX_PATTERNS])

            # Device IDs that have at least one Mexican carrier probe
            mx_device_ids_q = (
                session.query(ProbeRequest.device_id)
                .filter(mx_filter, ProbeRequest.ssid.isnot(None))
                .distinct()
                .subquery()
            )

            # All devices matching that set
            border_devices_q = (
                session.query(Device, Tag)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(Device.id.in_(mx_device_ids_q))
                .order_by(Device.last_seen.desc())
                .all()
            )

            # For each device collect MX and US SSIDs
            device_ids = [d.id for d, _ in border_devices_q]

            # All probes for these devices
            all_probes = (
                session.query(ProbeRequest.device_id, ProbeRequest.ssid)
                .filter(
                    ProbeRequest.device_id.in_(device_ids),
                    ProbeRequest.ssid.isnot(None),
                )
                .distinct()
                .all()
            )

            # Build per-device SSID sets
            from collections import defaultdict
            device_ssids: dict[int, list[str]] = defaultdict(list)
            for did, ssid in all_probes:
                device_ssids[did].append(ssid)

            def _is_mx(ssid: str) -> bool:
                sl = ssid.lower()
                return any(k in sl for k in ("infinitum", "totalplay", "izzi", "telmex"))

            rows = []
            all_mx_ssids: list[str] = []
            for dev, tag in border_devices_q:
                ssids = device_ssids.get(dev.id, [])
                mx_ssids = sorted({s for s in ssids if _is_mx(s)})
                us_ssids = sorted({s for s in ssids if not _is_mx(s)})
                all_mx_ssids.extend(mx_ssids)
                rows.append({
                    "device": dev,
                    "tag": tag,
                    "mx_ssids": mx_ssids,
                    "us_ssids": us_ssids,
                })

            # Summary stats
            total_border = len(rows)

            mx_carriers = set()
            carrier_map = {
                "INFINITUM": "Telmex/INFINITUM",
                "infinitum": "Telmex/INFINITUM",
                "Telmex": "Telmex/INFINITUM",
                "telmex": "Telmex/INFINITUM",
                "Totalplay": "Totalplay",
                "totalplay": "Totalplay",
                "izzi": "izzi",
            }
            for ssid in all_mx_ssids:
                sl = ssid.lower()
                if "infinitum" in sl or "telmex" in sl:
                    mx_carriers.add("Telmex/INFINITUM")
                if "totalplay" in sl:
                    mx_carriers.add("Totalplay")
                if "izzi" in sl:
                    mx_carriers.add("izzi")

            # Most common Mexican SSID
            from collections import Counter
            mx_counter = Counter(all_mx_ssids)
            top_mx_ssid = mx_counter.most_common(1)[0][0] if mx_counter else None

            return render_template(
                "border.html",
                rows=rows,
                total_border=total_border,
                unique_carriers=sorted(mx_carriers),
                top_mx_ssid=top_mx_ssid,
            )
        finally:
            session.close()

    # -- API routes --

    @app.route("/api/vehicles/<int:profile_id>", methods=["POST"])
    def api_vehicle_update(profile_id):
        session = get_session()
        try:
            profile = session.get(VehicleProfile, profile_id)
            if not profile:
                return jsonify({"status": "error", "message": "not found"}), 404
            data = request.get_json(silent=True) or request.form
            if "model" in data:
                profile.model = (data["model"] or "").strip() or None
            if "notes" in data:
                profile.notes = (data["notes"] or "").strip() or None
            session.commit()
            return jsonify({
                "status": "ok",
                "model": profile.model,
                "notes": profile.notes,
            })
        except Exception as e:
            session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 400
        finally:
            session.close()

    @app.route("/api/vehicles")
    def api_vehicles():
        session = get_session()
        try:
            profiles = (
                session.query(VehicleProfile)
                .order_by(VehicleProfile.sighting_count.desc())
                .all()
            )
            return jsonify([
                {
                    "id": p.id,
                    "sensor_id": p.sensor_id,
                    "model": p.model,
                    "first_seen": p.first_seen.isoformat() if p.first_seen else None,
                    "last_seen": p.last_seen.isoformat() if p.last_seen else None,
                    "sighting_count": p.sighting_count,
                    "avg_rssi": p.avg_rssi,
                    "flagged": p.flagged,
                    "flag_reason": p.flag_reason,
                    "notes": p.notes,
                }
                for p in profiles
            ])
        finally:
            session.close()

    @app.route("/api/vehicles/model/<model_name>/timeline")
    def api_vehicle_model_timeline(model_name):
        session = get_session()
        try:
            signals = (
                session.query(SdrSignal.timestamp)
                .filter(SdrSignal.model == model_name)
                .order_by(SdrSignal.timestamp)
                .all()
            )
            if not signals:
                return jsonify({"status": "error", "message": "no signals found"}), 404

            hourly = [0] * 24
            daily  = [0] * 7

            from zoneinfo import ZoneInfo
            tz = ZoneInfo("America/Denver")

            visits = []
            visit_start = None
            visit_last  = None

            for (ts,) in signals:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                local_ts = ts.astimezone(tz)
                hourly[local_ts.hour] += 1
                daily[local_ts.weekday()] += 1

                if visit_start is None:
                    visit_start = visit_last = ts
                elif (ts - visit_last).total_seconds() > 300:
                    visits.append((visit_start, visit_last))
                    visit_start = visit_last = ts
                else:
                    visit_last = ts

            if visit_start is not None:
                visits.append((visit_start, visit_last))

            total_visits = len(visits)
            if visits:
                durations = [(v[1] - v[0]).total_seconds() / 60.0 for v in visits]
                avg_dur = round(sum(durations) / len(durations), 1)
            else:
                avg_dur = 0.0

            return jsonify({
                "model": model_name,
                "hourly": hourly,
                "daily": daily,
                "total_visits": total_visits,
                "avg_visit_duration_minutes": avg_dur,
            })
        finally:
            session.close()

    @app.route("/api/vehicles/<path:sensor_id>/timeline")
    def api_vehicle_timeline(sensor_id):
        session = get_session()
        try:
            profile = (
                session.query(VehicleProfile)
                .filter(VehicleProfile.sensor_id == sensor_id)
                .first()
            )
            if not profile:
                return jsonify({"status": "error", "message": "not found"}), 404

            signals = (
                session.query(SdrSignal.timestamp)
                .filter(SdrSignal.device_uid == sensor_id)
                .order_by(SdrSignal.timestamp)
                .all()
            )

            hourly = [0] * 24
            daily  = [0] * 7  # 0=Mon … 6=Sun

            from zoneinfo import ZoneInfo
            tz = ZoneInfo("America/Denver")

            visits = []
            visit_start = None
            visit_last  = None

            for (ts,) in signals:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                local_ts = ts.astimezone(tz)
                hourly[local_ts.hour] += 1
                daily[local_ts.weekday()] += 1

                # Visit clustering: gap > 5 min → new visit
                if visit_start is None:
                    visit_start = visit_last = ts
                elif (ts - visit_last).total_seconds() > 300:
                    visits.append((visit_start, visit_last))
                    visit_start = visit_last = ts
                else:
                    visit_last = ts

            if visit_start is not None:
                visits.append((visit_start, visit_last))

            total_visits = len(visits)
            if visits:
                durations = [(v[1] - v[0]).total_seconds() / 60.0 for v in visits]
                avg_dur = round(sum(durations) / len(durations), 1)
            else:
                avg_dur = 0.0

            return jsonify({
                "sensor_id": sensor_id,
                "model": profile.model,
                "hourly": hourly,
                "daily": daily,
                "total_visits": total_visits,
                "avg_visit_duration_minutes": avg_dur,
            })
        finally:
            session.close()

    @app.route("/api/stats")
    def api_stats():
        session = get_session()
        try:
            return jsonify(get_stats(session))
        finally:
            session.close()

    @app.route("/api/devices/<int:device_id>/tag", methods=["POST"])
    def api_tag_device(device_id):
        session = get_session()
        try:
            data = request.get_json(silent=True) or request.form
            tag = session.query(Tag).filter(Tag.device_id == device_id).first()
            if not tag:
                tag = Tag(device_id=device_id)
                session.add(tag)

            if "category" in data:
                tag.category = data["category"]
            if "label" in data:
                tag.label = data["label"]
            if "notes" in data:
                tag.notes = data["notes"]
            if "flagged" in data:
                tag.flagged = str(data["flagged"]).lower() in ("true", "1", "yes")

            tag.tagged_by = "user"
            tag.tagged_at = datetime.now(timezone.utc)
            session.commit()

            return jsonify({"status": "ok", "category": tag.category, "label": tag.label})
        except Exception as e:
            session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 400
        finally:
            session.close()

    @app.route("/api/devices/<int:device_id>/alias", methods=["POST"])
    def api_alias_device(device_id):
        session = get_session()
        try:
            data = request.get_json(silent=True) or request.form
            device = session.get(Device, device_id)
            if not device:
                return jsonify({"status": "error", "message": "not found"}), 404
            device.alias = data.get("alias", "").strip() or None
            if "notes" in data:
                device.notes = data.get("notes", "").strip() or None
            session.commit()
            return jsonify({"status": "ok", "alias": device.alias})
        except Exception as e:
            session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 400
        finally:
            session.close()

    @app.route("/api/sdr/tag/<path:device_uid>", methods=["POST"])
    def api_sdr_tag(device_uid):
        session = get_session()
        try:
            data = request.get_json(silent=True) or request.form
            stag = session.query(SdrDeviceTag).filter(SdrDeviceTag.device_uid == device_uid).first()
            if not stag:
                stag = SdrDeviceTag(device_uid=device_uid)
                session.add(stag)

            if "category" in data:
                stag.category = data["category"]
            if "label" in data:
                stag.label = data["label"] or None
            if "flagged" in data:
                stag.flagged = str(data["flagged"]).lower() in ("true", "1", "yes")
            if "notes" in data:
                stag.notes = data["notes"] or None

            stag.tagged_by = "user"
            stag.tagged_at = datetime.now(timezone.utc)
            session.commit()

            return jsonify({
                "status": "ok",
                "category": stag.category,
                "label": stag.label,
                "flagged": stag.flagged,
            })
        except Exception as e:
            session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 400
        finally:
            session.close()

    @app.route("/api/sdr/correlations")
    def api_sdr_correlations():
        session = get_session()
        try:
            limit = request.args.get("limit", 50, type=int)
            rows = (
                session.query(SdrFrigateCorrelation, SdrSignal, FrigateEvent)
                .join(SdrSignal,
                      SdrFrigateCorrelation.sdr_signal_id == SdrSignal.id)
                .join(FrigateEvent,
                      SdrFrigateCorrelation.frigate_event_id == FrigateEvent.id)
                .order_by(SdrFrigateCorrelation.created_at.desc())
                .limit(limit)
                .all()
            )
            result = []
            for corr, sig, fe in rows:
                result.append({
                    "id": corr.id,
                    "created_at": (
                        corr.created_at.isoformat() if corr.created_at else None
                    ),
                    "device_uid": sig.device_uid,
                    "tpms_model": sig.model,
                    "camera": fe.camera,
                    "frigate_label": fe.label,
                    "frigate_confidence": fe.confidence,
                    "correlation_confidence": corr.confidence,
                    "correlation_window_seconds": corr.correlation_window_seconds,
                    "notes": corr.notes,
                })
            return jsonify(result)
        finally:
            session.close()

    @app.route("/api/auto-tag", methods=["POST"])
    def api_auto_tag():
        """Re-run probe-pattern auto-tagging across all devices.

        Returns a count of newly tagged devices.
        Only tags devices currently categorised as 'unknown' with
        non-randomized MACs.
        """
        from analysis.correlation import auto_tag_by_probes

        session = get_session()
        try:
            device_ids = [row[0] for row in session.query(Device.id).all()]
        finally:
            session.close()

        tagged = 0
        for did in device_ids:
            if auto_tag_by_probes(did):
                tagged += 1

        logger.info("api/auto-tag: tagged %d/%d devices", tagged, len(device_ids))
        return jsonify({
            "status": "ok",
            "tagged": tagged,
            "total": len(device_ids),
        })

    @app.route("/snapshots/<path:filename>")
    def serve_snapshot(filename):
        return send_from_directory(snapshot_dir, filename)

    # -- SocketIO --

    @sio.on("connect")
    def handle_connect():
        logger.debug("Client connected: %s", request.sid)

    @sio.on("disconnect")
    def handle_disconnect():
        logger.debug("Client disconnected: %s", request.sid)

    def background_emitter():
        """Emit real-time updates to all connected clients."""
        last_event_id = 0
        last_sdr_id = 0
        # Seed to current max IDs
        session = get_session()
        try:
            row = session.query(Event.id).order_by(Event.id.desc()).first()
            if row:
                last_event_id = row[0]
            row = session.query(SdrSignal.id).order_by(SdrSignal.id.desc()).first()
            if row:
                last_sdr_id = row[0]
        finally:
            session.close()

        while True:
            sio.sleep(3)
            session = get_session()
            try:
                stats = get_stats(session)
                sio.emit("stats_update", stats)

                new_events = (
                    session.query(Event, Device, Tag)
                    .outerjoin(Device, Event.device_id == Device.id)
                    .outerjoin(Tag, Device.id == Tag.device_id)
                    .filter(Event.id > last_event_id)
                    .order_by(Event.id)
                    .limit(25)
                    .all()
                )
                for evt, dev, tag in new_events:
                    sio.emit("new_event", serialize_event(evt, dev, tag))
                    last_event_id = evt.id

                new_sdr = (
                    session.query(SdrSignal)
                    .filter(SdrSignal.id > last_sdr_id)
                    .order_by(SdrSignal.id)
                    .limit(25)
                    .all()
                )
                for sig in new_sdr:
                    sio.emit("new_sdr_signal", {
                        "id": sig.id,
                        "timestamp": sig.timestamp.isoformat() if sig.timestamp else None,
                        "model": sig.model,
                        "device_uid": sig.device_uid,
                        "signal_class": sig.signal_class,
                        "frequency": sig.frequency,
                        "rssi": sig.rssi,
                        "snr": sig.snr,
                        "protocol": sig.protocol,
                    })
                    last_sdr_id = sig.id

            except Exception as e:
                logger.error("Background emitter error: %s", e)
            finally:
                session.close()

    sio.start_background_task(background_emitter)

    return app, sio


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = config.load()
    config.setup_logging()
    init_db()

    web_cfg = cfg.get("web", {})
    host = web_cfg.get("host", "0.0.0.0")
    port = web_cfg.get("port", 8080)

    app, sio = create_app()

    def shutdown(signum, frame):
        logger.info("Received %s, shutting down...", signal.Signals(signum).name)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("=" * 60)
    logger.info("SENTINEL Web Dashboard")
    logger.info("Listening on %s:%d", host, port)
    logger.info("=" * 60)

    sio.run(app, host=host, port=port, debug=False, use_reloader=False,
            log_output=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
