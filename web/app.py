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
import subprocess
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
    ArrivalEvent,
    Baseline,
    Device,
    DeviceHeartbeat,
    DroneIdEvent,
    Event,
    FrigateEvent,
    PresenceBundle,
    ProbeRequest,
    SdrDeviceTag,
    SdrFrigateCorrelation,
    SdrSignal,
    Tag,
    VehicleIdentityCluster,
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
        drones_detected = (
            session.query(Device)
            .join(Tag, Device.id == Tag.device_id)
            .filter(Tag.category == "drone")
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
            "drones_detected": drones_detected,
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

            # Heartbeat status map for resident devices (device_id → status)
            resident_ids = [
                dev.id for dev, tag in devices_list
                if tag and tag.category == "resident"
            ]
            heartbeat_map = {}
            if resident_ids:
                hb_rows = (
                    session.query(DeviceHeartbeat)
                    .filter(DeviceHeartbeat.device_id.in_(resident_ids))
                    .all()
                )
                heartbeat_map = {hb.device_id: hb.status for hb in hb_rows}

            return render_template(
                "devices.html",
                devices=devices_list,
                search=search,
                tag_filter=tag_filter,
                type_filter=type_filter,
                page=page,
                per_page=per_page,
                total=total,
                heartbeat_map=heartbeat_map,
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

            # 6. Correlated arrivals: WiFi + TPMS within 2 minutes, last 24h
            arrival_rows = (
                session.query(ArrivalEvent, Device, Tag)
                .outerjoin(Device, ArrivalEvent.wifi_device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(ArrivalEvent.timestamp >= cutoff_24h)
                .order_by(ArrivalEvent.timestamp.desc())
                .limit(50)
                .all()
            )
            correlated_arrivals = [
                {"arrival": arr, "device": dev, "tag": tag}
                for arr, dev, tag in arrival_rows
            ]

            # 7. Drone detections: all devices tagged 'drone'
            drone_devices = (
                session.query(Device, Tag)
                .join(Tag, Device.id == Tag.device_id)
                .filter(Tag.category == "drone")
                .order_by(Device.last_seen.desc())
                .all()
            )

            return render_template(
                "intelligence.html",
                high_threat=high_threat,
                new_unknown=new_unknown,
                tpms_counts=tpms_counts,
                tpms_tags=tpms_tags,
                night_events=night_events,
                heatmap_data=heatmap_data,
                heatmap_max=heatmap_max,
                correlated_arrivals=correlated_arrivals,
                drone_devices=drone_devices,
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

    @app.route("/droneid")
    def droneid():
        session = get_session()
        try:
            from sqlalchemy import func

            page = max(1, request.args.get("page", 1, type=int))
            per_page = 50

            total = session.query(func.count(DroneIdEvent.id)).scalar() or 0
            events = (
                session.query(DroneIdEvent)
                .order_by(DroneIdEvent.timestamp.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            # Unique drones seen
            unique_macs = (
                session.query(DroneIdEvent.mac)
                .distinct()
                .count()
            )

            # Events with GPS fix
            gps_count = (
                session.query(func.count(DroneIdEvent.id))
                .filter(DroneIdEvent.drone_lat.isnot(None))
                .scalar()
            ) or 0

            # Events with pilot GPS
            pilot_count = (
                session.query(func.count(DroneIdEvent.id))
                .filter(DroneIdEvent.pilot_lat.isnot(None))
                .scalar()
            ) or 0

            # Most recent event per unique MAC for map display
            subq = (
                session.query(
                    DroneIdEvent.mac,
                    func.max(DroneIdEvent.id).label("max_id"),
                )
                .group_by(DroneIdEvent.mac)
                .subquery()
            )
            latest_events = (
                session.query(DroneIdEvent)
                .join(subq, DroneIdEvent.id == subq.c.max_id)
                .filter(DroneIdEvent.drone_lat.isnot(None))
                .all()
            )

            map_markers = []
            for e in latest_events:
                marker = {
                    "mac": e.mac,
                    "serial": e.serial_number or "UNKNOWN",
                    "drone_lat": e.drone_lat,
                    "drone_lon": e.drone_lon,
                    "drone_alt": e.drone_alt_meters,
                    "pilot_lat": e.pilot_lat,
                    "pilot_lon": e.pilot_lon,
                    "speed_ms": e.speed_ms,
                    "heading": e.heading,
                    "rssi": e.rssi,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                }
                map_markers.append(marker)

            return render_template(
                "droneid.html",
                events=events,
                total=total,
                unique_macs=unique_macs,
                gps_count=gps_count,
                pilot_count=pilot_count,
                map_markers=map_markers,
                page=page,
                per_page=per_page,
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

    @app.route("/api/heartbeats")
    def api_heartbeats():
        session = get_session()
        try:
            rows = (
                session.query(DeviceHeartbeat, Device, Tag)
                .join(Device, DeviceHeartbeat.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .all()
            )
            return jsonify([
                {
                    "device_id": dev.id,
                    "mac": dev.mac,
                    "label": (tag.label if tag else None) or dev.alias or dev.vendor or dev.mac,
                    "last_seen": hb.last_seen.isoformat() if hb.last_seen else None,
                    "expected_interval_minutes": hb.expected_interval_minutes,
                    "status": hb.status,
                    "consecutive_misses": hb.consecutive_misses,
                    "alerted_at": hb.alerted_at.isoformat() if hb.alerted_at else None,
                }
                for hb, dev, tag in rows
            ])
        finally:
            session.close()

    @app.route("/api/arrivals")
    def api_arrivals():
        """Return recent correlated arrival events (WiFi + TPMS within 2 minutes)."""
        session = get_session()
        try:
            limit = min(int(request.args.get("limit", 100)), 500)
            rows = (
                session.query(ArrivalEvent, Device, Tag)
                .outerjoin(Device, ArrivalEvent.wifi_device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .order_by(ArrivalEvent.timestamp.desc())
                .limit(limit)
                .all()
            )
            result = []
            for arr, dev, tag in rows:
                tpms_rssi = arr.tpms_rssi
                if tpms_rssi is not None and tpms_rssi > -60:
                    distance = "very close (<5m)"
                elif tpms_rssi is not None and tpms_rssi > -70:
                    distance = "close (<10m)"
                elif tpms_rssi is not None and tpms_rssi > -80:
                    distance = "medium (10–30m)"
                else:
                    distance = "far (>30m)"
                result.append({
                    "id": arr.id,
                    "timestamp": arr.timestamp.isoformat() if arr.timestamp else None,
                    "confidence": arr.confidence,
                    "tpms_sensor_id": arr.tpms_sensor_id,
                    "tpms_model": arr.tpms_model,
                    "tpms_rssi": tpms_rssi,
                    "distance_estimate": distance,
                    "notes": arr.notes,
                    "reviewed": arr.reviewed,
                    "wifi_device": {
                        "id": dev.id,
                        "mac": dev.mac,
                        "vendor": dev.vendor,
                        "alias": dev.alias,
                        "is_randomized": dev.is_randomized,
                    } if dev else None,
                    "tag": {
                        "category": tag.category,
                        "label": tag.label,
                        "flagged": tag.flagged,
                    } if tag else None,
                })
            return jsonify(result)
        finally:
            session.close()

    @app.route("/snapshots/<path:filename>")
    def serve_snapshot(filename):
        return send_from_directory(snapshot_dir, filename)

    # -- Placeholder pages --

    @app.route("/investigate")
    def investigate():
        return render_template("investigate.html")

    @app.route("/api/investigate", methods=["POST"])
    def api_investigate():
        from collections import Counter
        from sqlalchemy import func, distinct as sa_distinct, or_

        data = request.get_json(silent=True) or {}
        q = (data.get("query") or "").strip()
        scope = data.get("scope", "all")

        if not q or len(q) < 2:
            return jsonify({"error": "query too short", "devices": [], "vehicles": [], "signals": [], "alerts": [], "total": 0}), 400

        like = f"%{q}%"
        session = get_session()
        results = {"devices": [], "vehicles": [], "signals": [], "alerts": []}

        try:
            now = datetime.now(timezone.utc)

            if scope in ("all", "devices"):
                # Device IDs that probed for SSIDs matching the query
                ssid_device_ids = list(set(
                    r[0] for r in session.query(ProbeRequest.device_id)
                    .filter(ProbeRequest.ssid.ilike(like), ProbeRequest.device_id.isnot(None))
                    .distinct().limit(200).all()
                ))

                dev_filters = [
                    Device.mac.ilike(like),
                    Device.vendor.ilike(like),
                    Device.alias.ilike(like),
                    Device.hostname.ilike(like),
                    Tag.label.ilike(like),
                ]
                if ssid_device_ids:
                    dev_filters.append(Device.id.in_(ssid_device_ids))

                device_rows = (
                    session.query(Device, Tag)
                    .outerjoin(Tag, Device.id == Tag.device_id)
                    .filter(or_(*dev_filters))
                    .order_by(Device.total_sightings.desc())
                    .limit(5).all()
                )

                # Arrival sensor set for ghost checks (done once for batch)
                arrival_sensors = set(
                    r[0] for r in session.query(ArrivalEvent.tpms_sensor_id)
                    .filter(ArrivalEvent.tpms_sensor_id.isnot(None))
                    .distinct().all()
                )

                for dev, tag in device_rows:
                    days_seen = session.query(
                        func.count(sa_distinct(func.date(Visit.arrived_at)))
                    ).filter(Visit.device_id == dev.id).scalar() or 0

                    avg_dwell_s = session.query(func.avg(Visit.duration_seconds)).filter(
                        Visit.device_id == dev.id,
                        Visit.duration_seconds.isnot(None),
                    ).scalar()
                    avg_dwell_min = round(avg_dwell_s / 60.0, 1) if avg_dwell_s else None

                    ssid_rows = (
                        session.query(ProbeRequest.ssid)
                        .filter(ProbeRequest.device_id == dev.id,
                                ProbeRequest.ssid.isnot(None),
                                ProbeRequest.ssid != "")
                        .group_by(ProbeRequest.ssid)
                        .order_by(func.count(ProbeRequest.id).desc())
                        .limit(5).all()
                    )
                    probe_ssids = [r[0] for r in ssid_rows]

                    bl = session.query(Baseline).filter(Baseline.device_id == dev.id).first()
                    baseline_data = {
                        "typical_start": bl.typical_start_hour,
                        "typical_end": bl.typical_end_hour,
                        "avg_visits_per_day": bl.avg_visits_per_day,
                    } if bl else None

                    arr = (
                        session.query(ArrivalEvent.tpms_sensor_id)
                        .filter(ArrivalEvent.wifi_device_id == dev.id,
                                ArrivalEvent.tpms_sensor_id.isnot(None))
                        .order_by(ArrivalEvent.timestamp.desc()).first()
                    )
                    correlated_vehicle = arr[0] if arr else None

                    frigate_count = session.query(func.count(FrigateEvent.id)).filter(
                        FrigateEvent.correlated_device_id == dev.id
                    ).scalar() or 0

                    last_alert = (
                        session.query(AlertLog.alert_type)
                        .filter(AlertLog.device_id == dev.id)
                        .order_by(AlertLog.timestamp.desc()).first()
                    )
                    threat_level = None
                    if last_alert:
                        at = last_alert[0] or ""
                        threat_level = "red" if at.startswith("red:") else ("yellow" if at.startswith("yellow:") else None)

                    results["devices"].append({
                        "type": "device",
                        "id": dev.id,
                        "mac": dev.mac,
                        "device_type": dev.device_type,
                        "vendor": dev.vendor,
                        "alias": dev.alias,
                        "category": tag.category if tag else "unknown",
                        "tag_label": tag.label if tag else None,
                        "flagged": tag.flagged if tag else False,
                        "is_randomized": dev.is_randomized,
                        "total_sightings": dev.total_sightings,
                        "first_seen": dev.first_seen.isoformat() if dev.first_seen else None,
                        "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
                        "days_seen": days_seen,
                        "avg_dwell_minutes": avg_dwell_min,
                        "probe_ssids": probe_ssids,
                        "baseline": baseline_data,
                        "correlated_vehicle": correlated_vehicle,
                        "frigate_appearances": frigate_count,
                        "threat_level": threat_level,
                    })

            if scope in ("all", "vehicles"):
                veh_rows = (
                    session.query(VehicleProfile)
                    .filter(or_(
                        VehicleProfile.sensor_id.ilike(like),
                        VehicleProfile.model.ilike(like),
                        VehicleProfile.notes.ilike(like),
                    ))
                    .order_by(VehicleProfile.sighting_count.desc())
                    .limit(5).all()
                )

                arrival_sensors = set(
                    r[0] for r in session.query(ArrivalEvent.tpms_sensor_id)
                    .filter(ArrivalEvent.tpms_sensor_id.isnot(None))
                    .distinct().all()
                )

                for vp in veh_rows:
                    cluster = (
                        session.query(VehicleIdentityCluster)
                        .filter(VehicleIdentityCluster.tpms_sensor_id == vp.sensor_id).first()
                    )
                    identity_cluster = None
                    if cluster:
                        identity_cluster = {
                            "representative_ssids": json.loads(cluster.representative_ssids or "[]"),
                            "associated_bt_vendors": json.loads(cluster.associated_bt_vendors or "[]"),
                            "camera_appearances": cluster.camera_appearances,
                            "dominant_camera": cluster.dominant_camera,
                            "bundle_count": cluster.bundle_count,
                        }
                    results["vehicles"].append({
                        "type": "vehicle",
                        "sensor_id": vp.sensor_id,
                        "model": vp.model,
                        "sighting_count": vp.sighting_count,
                        "first_seen": vp.first_seen.isoformat() if vp.first_seen else None,
                        "last_seen": vp.last_seen.isoformat() if vp.last_seen else None,
                        "flagged": vp.flagged,
                        "avg_rssi": vp.avg_rssi,
                        "identity_cluster": identity_cluster,
                        "ghost": (vp.sighting_count > 20 and vp.sensor_id not in arrival_sensors),
                    })

            if scope in ("all", "signals"):
                sig_rows = (
                    session.query(
                        SdrSignal.device_uid,
                        SdrSignal.model,
                        SdrSignal.signal_class,
                        func.count(SdrSignal.id).label("cnt"),
                        func.min(SdrSignal.timestamp).label("first_seen"),
                        func.max(SdrSignal.timestamp).label("last_seen"),
                        func.avg(SdrSignal.rssi).label("avg_rssi"),
                    )
                    .filter(or_(
                        SdrSignal.model.ilike(like),
                        SdrSignal.device_uid.ilike(like),
                        SdrSignal.signal_class.ilike(like),
                    ))
                    .group_by(SdrSignal.device_uid, SdrSignal.model, SdrSignal.signal_class)
                    .order_by(func.count(SdrSignal.id).desc())
                    .limit(5).all()
                )
                for row in sig_rows:
                    results["signals"].append({
                        "type": "signal",
                        "device_uid": row.device_uid,
                        "model": row.model,
                        "signal_class": row.signal_class,
                        "count": row.cnt,
                        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                        "avg_rssi": round(row.avg_rssi, 1) if row.avg_rssi else None,
                    })

            if scope == "all":
                alert_rows = (
                    session.query(AlertLog)
                    .filter(AlertLog.message.ilike(like))
                    .order_by(AlertLog.timestamp.desc())
                    .limit(5).all()
                )
                for al in alert_rows:
                    at = al.alert_type or ""
                    level = "red" if at.startswith("red:") else ("yellow" if at.startswith("yellow:") else "green")
                    results["alerts"].append({
                        "type": "alert",
                        "id": al.id,
                        "timestamp": al.timestamp.isoformat() if al.timestamp else None,
                        "alert_type": al.alert_type,
                        "level": level,
                        "device_id": al.device_id,
                        "message": (al.message or "")[:200],
                    })

            results["total"] = sum(len(v) for v in results.values())
            results["query"] = q
            results["scope"] = scope
            return jsonify(results)

        finally:
            session.close()

    @app.route("/api/investigate/connections/<int:device_id>")
    def api_investigate_connections(device_id):
        from collections import Counter
        from sqlalchemy import func

        session = get_session()
        try:
            now = datetime.now(timezone.utc)
            cutoff_14d = (now - timedelta(days=14)).replace(tzinfo=None)

            # Load recent presence bundles and filter Python-side for this device
            recent_bundles = (
                session.query(PresenceBundle)
                .filter(PresenceBundle.timestamp >= cutoff_14d)
                .order_by(PresenceBundle.timestamp.desc())
                .limit(500).all()
            )

            co_device_counter: Counter = Counter()
            tpms_counter: Counter = Counter()

            for b in recent_bundles:
                wifi_ids = json.loads(b.wifi_device_ids or "[]")
                if device_id in wifi_ids:
                    for did in wifi_ids:
                        if did != device_id:
                            co_device_counter[did] += 1
                    if b.tpms_sensor_id:
                        tpms_counter[b.tpms_sensor_id] += 1

            # Top 3 co-present devices
            co_present_devices = []
            for co_id, appearances in co_device_counter.most_common(3):
                co_dev = session.get(Device, co_id)
                if not co_dev:
                    continue
                co_tag = session.query(Tag).filter(Tag.device_id == co_id).first()
                co_present_devices.append({
                    "type": "device",
                    "id": co_dev.id,
                    "mac": co_dev.mac,
                    "vendor": co_dev.vendor,
                    "alias": co_dev.alias,
                    "category": co_tag.category if co_tag else "unknown",
                    "tag_label": co_tag.label if co_tag else None,
                    "is_randomized": co_dev.is_randomized,
                    "total_sightings": co_dev.total_sightings,
                    "first_seen": co_dev.first_seen.isoformat() if co_dev.first_seen else None,
                    "last_seen": co_dev.last_seen.isoformat() if co_dev.last_seen else None,
                    "co_appearances": appearances,
                })

            # Top co-present vehicle
            co_present_vehicle = None
            if tpms_counter:
                top_sensor, top_count = tpms_counter.most_common(1)[0]
                vp = session.query(VehicleProfile).filter(VehicleProfile.sensor_id == top_sensor).first()
                if vp:
                    cluster = (
                        session.query(VehicleIdentityCluster)
                        .filter(VehicleIdentityCluster.tpms_sensor_id == top_sensor).first()
                    )
                    arrival_sensors = set(
                        r[0] for r in session.query(ArrivalEvent.tpms_sensor_id)
                        .filter(ArrivalEvent.tpms_sensor_id.isnot(None))
                        .distinct().all()
                    )
                    identity_cluster = None
                    if cluster:
                        identity_cluster = {
                            "representative_ssids": json.loads(cluster.representative_ssids or "[]"),
                            "associated_bt_vendors": json.loads(cluster.associated_bt_vendors or "[]"),
                            "camera_appearances": cluster.camera_appearances,
                            "dominant_camera": cluster.dominant_camera,
                            "bundle_count": cluster.bundle_count,
                        }
                    co_present_vehicle = {
                        "type": "vehicle",
                        "sensor_id": vp.sensor_id,
                        "model": vp.model,
                        "sighting_count": vp.sighting_count,
                        "first_seen": vp.first_seen.isoformat() if vp.first_seen else None,
                        "last_seen": vp.last_seen.isoformat() if vp.last_seen else None,
                        "flagged": vp.flagged,
                        "avg_rssi": vp.avg_rssi,
                        "identity_cluster": identity_cluster,
                        "ghost": (vp.sighting_count > 20 and vp.sensor_id not in arrival_sensors),
                        "co_appearances": top_count,
                    }

            # Last 3 alerts for this device
            alert_rows = (
                session.query(AlertLog)
                .filter(AlertLog.device_id == device_id)
                .order_by(AlertLog.timestamp.desc())
                .limit(3).all()
            )
            alerts = []
            for al in alert_rows:
                at = al.alert_type or ""
                level = "red" if at.startswith("red:") else ("yellow" if at.startswith("yellow:") else "green")
                alerts.append({
                    "level": level,
                    "alert_type": al.alert_type,
                    "timestamp": al.timestamp.isoformat() if al.timestamp else None,
                    "message": (al.message or "")[:150],
                })

            # Visit sparkline: count per day for last 7 days
            sparkline = []
            for i in range(7):
                day_start = (now - timedelta(days=6 - i)).replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=None)
                day_end = day_start + timedelta(days=1)
                cnt = session.query(func.count(Visit.id)).filter(
                    Visit.device_id == device_id,
                    Visit.arrived_at >= day_start,
                    Visit.arrived_at < day_end,
                ).scalar() or 0
                sparkline.append(cnt)

            return jsonify({
                "device_id": device_id,
                "co_present_devices": co_present_devices,
                "co_present_vehicle": co_present_vehicle,
                "alerts": alerts,
                "visit_sparkline": sparkline,
            })

        finally:
            session.close()

    @app.route("/patterns")
    def patterns():
        return render_template("patterns.html")

    # ── Patterns API ──────────────────────────────────────────────────────────

    @app.route("/api/patterns/environment")
    def api_patterns_environment():
        from sqlalchemy import func

        session = get_session()
        try:
            now = datetime.now(timezone.utc)
            cutoff_14d = now - timedelta(days=14)
            cutoff_24h = now - timedelta(hours=24)

            bl_path = Path("/opt/sentinel/data/env_baselines.json")
            bl_data = json.loads(bl_path.read_text()) if bl_path.exists() else {}
            bl_hourly = bl_data.get("hourly", {})
            bl_composite = bl_hourly.get("composite_activity", [0] * 24)

            # ── Heatmap 7×24 (composite: frigate_car + sdr_tpms) ──
            # SQLite strftime '%w': 0=Sun, 1=Mon … 6=Sat → remap to 0=Mon
            heatmap = [[0] * 24 for _ in range(7)]

            frg_rows = session.query(
                func.strftime("%w", FrigateEvent.timestamp).label("dow"),
                func.strftime("%H", FrigateEvent.timestamp).label("hr"),
                func.count(FrigateEvent.id).label("cnt"),
            ).filter(
                FrigateEvent.label == "car",
                FrigateEvent.timestamp >= cutoff_14d,
            ).group_by("dow", "hr").all()

            for row in frg_rows:
                py_dow = (int(row.dow) - 1) % 7
                heatmap[py_dow][int(row.hr)] += row.cnt

            tpms_rows = session.query(
                func.strftime("%w", SdrSignal.timestamp).label("dow"),
                func.strftime("%H", SdrSignal.timestamp).label("hr"),
                func.count(SdrSignal.id).label("cnt"),
            ).filter(
                SdrSignal.signal_class == "tpms",
                SdrSignal.timestamp >= cutoff_14d,
            ).group_by("dow", "hr").all()

            for row in tpms_rows:
                py_dow = (int(row.dow) - 1) % 7
                heatmap[py_dow][int(row.hr)] += row.cnt

            flat = [v for row in heatmap for v in row]
            heatmap_max = max(flat) if flat else 1

            # ── Insights ──
            day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            peak_val, peak_day, peak_hour = 0, 0, 0
            for d in range(7):
                for h in range(24):
                    if heatmap[d][h] > peak_val:
                        peak_val, peak_day, peak_hour = heatmap[d][h], d, h

            hour_totals = [sum(heatmap[d][h] for d in range(7)) for h in range(24)]
            min_4h, min_4h_start = float("inf"), 0
            for h in range(24):
                s = sum(hour_totals[(h + i) % 24] for i in range(4))
                if s < min_4h:
                    min_4h, min_4h_start = s, h

            bl_daily = bl_data.get("daily", {})
            day_totals = [
                bl_daily.get("frigate_car", [0] * 7)[i] + bl_daily.get("sdr_tpms", [0] * 7)[i]
                for i in range(7)
            ]
            busiest_idx = day_totals.index(max(day_totals))

            insights = [
                f"Peak activity: {day_names[peak_day]} {peak_hour:02d}:00 ({peak_val} events over 2 weeks)",
                f"Quietest 4-hour window: {min_4h_start:02d}:00–{(min_4h_start+4)%24:02d}:00",
                f"Busiest baseline day: {day_names[busiest_idx]} (~{int(max(day_totals)//6):,} events/day)",
            ]

            # ── Today vs baseline (composite scale) ──
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            today_frg_car = session.query(func.count(FrigateEvent.id)).filter(
                FrigateEvent.label == "car", FrigateEvent.timestamp >= today_start
            ).scalar() or 0
            today_tpms = session.query(func.count(SdrSignal.id)).filter(
                SdrSignal.signal_class == "tpms", SdrSignal.timestamp >= today_start
            ).scalar() or 0
            today_frg_person = session.query(func.count(FrigateEvent.id)).filter(
                FrigateEvent.label == "person", FrigateEvent.timestamp >= today_start
            ).scalar() or 0
            today_composite = today_frg_car + today_tpms + today_frg_person * 3
            baseline_daily_total = sum(bl_composite)
            today_vs_baseline = round(today_composite / max(baseline_daily_total, 1), 2)

            # ── Hourly breakdown last 24h ──
            hourly = {k: [0] * 24 for k in ["wifi", "bt", "frigate_car", "frigate_person", "sdr_tpms", "sdr_weather"]}

            wifi_rows = session.query(
                func.strftime("%H", ProbeRequest.timestamp).label("hr"),
                func.count(ProbeRequest.id).label("cnt"),
            ).filter(ProbeRequest.timestamp >= cutoff_24h).group_by("hr").all()
            for row in wifi_rows:
                hourly["wifi"][int(row.hr)] = row.cnt

            bt_rows = session.query(
                func.strftime("%H", Event.timestamp).label("hr"),
                func.count(Event.id).label("cnt"),
            ).filter(
                Event.timestamp >= cutoff_24h,
                Event.event_type.in_(["bt_ble", "bt_classic"]),
            ).group_by("hr").all()
            for row in bt_rows:
                hourly["bt"][int(row.hr)] = row.cnt

            frg24 = session.query(
                FrigateEvent.label,
                func.strftime("%H", FrigateEvent.timestamp).label("hr"),
                func.count(FrigateEvent.id).label("cnt"),
            ).filter(
                FrigateEvent.timestamp >= cutoff_24h,
                FrigateEvent.label.in_(["car", "person"]),
            ).group_by(FrigateEvent.label, "hr").all()
            for row in frg24:
                k = "frigate_" + row.label
                if k in hourly:
                    hourly[k][int(row.hr)] = row.cnt

            sdr24 = session.query(
                SdrSignal.signal_class,
                func.strftime("%H", SdrSignal.timestamp).label("hr"),
                func.count(SdrSignal.id).label("cnt"),
            ).filter(
                SdrSignal.timestamp >= cutoff_24h,
                SdrSignal.signal_class.in_(["tpms", "weather"]),
            ).group_by(SdrSignal.signal_class, "hr").all()
            for row in sdr24:
                k = "sdr_" + row.signal_class
                if k in hourly:
                    hourly[k][int(row.hr)] = row.cnt

            return jsonify({
                "heatmap": heatmap,
                "heatmap_max": heatmap_max,
                "insights": insights,
                "today_vs_baseline": today_vs_baseline,
                "hourly_breakdown": hourly,
                "baseline": {
                    "wifi": bl_hourly.get("wifi_probes", [0] * 24),
                    "bt": bl_hourly.get("bt_events", [0] * 24),
                    "frigate_car": bl_hourly.get("frigate_car", [0] * 24),
                    "frigate_person": bl_hourly.get("frigate_person", [0] * 24),
                    "sdr_tpms": bl_hourly.get("sdr_tpms", [0] * 24),
                    "sdr_weather": bl_hourly.get("sdr_weather", [0] * 24),
                    "composite": bl_composite,
                },
            })
        finally:
            session.close()

    @app.route("/api/patterns/recurring-unknowns")
    def api_patterns_recurring_unknowns():
        from sqlalchemy import func, distinct as sa_distinct

        session = get_session()
        try:
            day_subq = (
                session.query(
                    Visit.device_id,
                    func.count(sa_distinct(func.date(Visit.arrived_at))).label("day_count"),
                    func.count(Visit.id).label("visit_count"),
                    func.avg(Visit.duration_seconds).label("avg_dur"),
                )
                .filter(Visit.arrived_at.isnot(None))
                .group_by(Visit.device_id)
                .having(func.count(sa_distinct(func.date(Visit.arrived_at))) >= 3)
                .subquery()
            )

            rows = (
                session.query(Device, Tag, day_subq.c.day_count, day_subq.c.visit_count, day_subq.c.avg_dur)
                .join(day_subq, Device.id == day_subq.c.device_id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter((Tag.category == "unknown") | (Tag.id.is_(None)))
                .order_by(day_subq.c.day_count.desc(), day_subq.c.visit_count.desc())
                .limit(25)
                .all()
            )

            result = []
            for dev, tag, days, visits, avg_dur in rows:
                avg_vpd = round(visits / max(days, 1), 1)
                score = days * avg_vpd * 10 * (0.5 if dev.is_randomized else 1.0)

                ssids = [r[0] for r in session.query(ProbeRequest.ssid, func.count(ProbeRequest.id).label("cnt"))
                    .filter(ProbeRequest.device_id == dev.id, ProbeRequest.ssid.isnot(None), ProbeRequest.ssid != "")
                    .group_by(ProbeRequest.ssid).order_by(func.count(ProbeRequest.id).desc()).limit(3).all()]

                bl = session.query(Baseline).filter(Baseline.device_id == dev.id).first()
                typical_hours = None
                if bl and bl.typical_start_hour is not None and bl.typical_end_hour is not None:
                    typical_hours = f"{bl.typical_start_hour:02d}:00–{bl.typical_end_hour:02d}:00"

                result.append({
                    "id": dev.id,
                    "mac": dev.mac,
                    "vendor": dev.vendor,
                    "is_randomized": dev.is_randomized,
                    "days_seen": days,
                    "total_visits": visits,
                    "avg_visits_per_day": avg_vpd,
                    "avg_dwell_minutes": round(avg_dur / 60.0, 1) if avg_dur else None,
                    "typical_hours": typical_hours,
                    "probe_ssids": ssids,
                    "consistency_score": round(score, 1),
                    "first_seen": dev.first_seen.isoformat() if dev.first_seen else None,
                    "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
                })

            result.sort(key=lambda x: x["consistency_score"], reverse=True)
            return jsonify(result[:20])
        finally:
            session.close()

    @app.route("/api/patterns/vehicle-clusters")
    def api_patterns_vehicle_clusters():
        session = get_session()
        try:
            arrival_sensors = set(
                r[0] for r in session.query(ArrivalEvent.tpms_sensor_id)
                .filter(ArrivalEvent.tpms_sensor_id.isnot(None)).distinct().all()
            )

            profiles = session.query(VehicleProfile).order_by(VehicleProfile.sighting_count.desc()).all()
            known, ghost = [], []

            for vp in profiles:
                is_ghost = vp.sighting_count > 20 and vp.sensor_id not in arrival_sensors
                cluster = (
                    session.query(VehicleIdentityCluster)
                    .filter(VehicleIdentityCluster.tpms_sensor_id == vp.sensor_id).first()
                )
                pd = {
                    "sensor_id": vp.sensor_id,
                    "model": vp.model,
                    "sighting_count": vp.sighting_count,
                    "first_seen": vp.first_seen.isoformat() if vp.first_seen else None,
                    "last_seen": vp.last_seen.isoformat() if vp.last_seen else None,
                    "flagged": vp.flagged,
                    "avg_rssi": vp.avg_rssi,
                    "ghost": is_ghost,
                }
                if is_ghost:
                    ghost.append(pd)
                elif cluster:
                    pd["cluster"] = {
                        "representative_ssids": json.loads(cluster.representative_ssids or "[]"),
                        "associated_bt_vendors": json.loads(cluster.associated_bt_vendors or "[]"),
                        "bundle_count": cluster.bundle_count,
                        "camera_appearances": cluster.camera_appearances,
                        "dominant_camera": cluster.dominant_camera,
                        "cluster_label": cluster.cluster_label,
                    }
                    known.append(pd)

            from analysis.presence_engine import find_same_person_different_vehicle
            try:
                same_person = find_same_person_different_vehicle(min_ssid_overlap=2)[:5]
            except Exception:
                same_person = []

            return jsonify({
                "known": known[:20],
                "ghost": ghost[:20],
                "same_person_candidates": same_person,
            })
        finally:
            session.close()

    @app.route("/api/patterns/anomalies")
    def api_patterns_anomalies():
        from sqlalchemy import func, distinct as sa_distinct

        session = get_session()
        try:
            now = datetime.now(timezone.utc)
            cutoff_7d = now - timedelta(days=7)

            bl_path = Path("/opt/sentinel/data/env_baselines.json")
            bl_data = json.loads(bl_path.read_text()) if bl_path.exists() else {}
            bl_composite = bl_data.get("hourly", {}).get("composite_activity", [0] * 24)
            busy_hours = set(bl_data.get("busy_hours", []))

            anomalies = []

            # ── Activity spike / dead zone ──
            # Compare hourly (frigate_car + sdr_tpms + person*3) vs composite baseline
            frg_hourly = session.query(
                func.strftime("%Y-%m-%d %H", FrigateEvent.timestamp).label("hk"),
                FrigateEvent.label,
                func.count(FrigateEvent.id).label("cnt"),
            ).filter(
                FrigateEvent.timestamp >= cutoff_7d,
                FrigateEvent.label.in_(["car", "person"]),
            ).group_by("hk", FrigateEvent.label).all()

            tpms_hourly = session.query(
                func.strftime("%Y-%m-%d %H", SdrSignal.timestamp).label("hk"),
                func.count(SdrSignal.id).label("cnt"),
            ).filter(
                SdrSignal.signal_class == "tpms",
                SdrSignal.timestamp >= cutoff_7d,
            ).group_by("hk").all()

            hour_actuals: dict = {}
            for row in frg_hourly:
                d = hour_actuals.setdefault(row.hk, {"car": 0, "person": 0, "tpms": 0})
                d[row.label] = row.cnt
            for row in tpms_hourly:
                hour_actuals.setdefault(row.hk, {"car": 0, "person": 0, "tpms": 0})["tpms"] = row.cnt

            for hk, counts in hour_actuals.items():
                try:
                    dt_naive = datetime.strptime(hk, "%Y-%m-%d %H")
                except (ValueError, TypeError):
                    continue
                h = dt_naive.hour
                actual = counts["car"] + counts["tpms"] + counts["person"] * 3
                baseline_val = bl_composite[h] if h < len(bl_composite) else 0
                if baseline_val <= 0:
                    continue
                ratio = actual / baseline_val
                day_abbr = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt_naive.weekday()]
                if ratio >= 2.0:
                    anomalies.append({
                        "timestamp": dt_naive.isoformat(),
                        "type": "ACTIVITY_SPIKE",
                        "severity": "high" if ratio >= 3.0 else "medium",
                        "description": f"Activity {ratio:.1f}× above baseline at {day_abbr} {h:02d}:00 — {actual} vs {baseline_val:.0f} expected",
                        "entity_id": None, "entity_type": None, "entity_ref": None,
                    })
                elif ratio <= 0.25 and h in busy_hours:
                    anomalies.append({
                        "timestamp": dt_naive.isoformat(),
                        "type": "DEAD_ZONE",
                        "severity": "medium",
                        "description": f"Dead zone during busy hour {day_abbr} {h:02d}:00 — only {actual} events ({ratio:.0%} of baseline)",
                        "entity_id": None, "entity_type": None, "entity_ref": None,
                    })

            # ── Alert log: night unknown / pattern break ──
            alert_types = ["yellow:night_gate", "yellow:pattern_anomaly", "red:pattern_anomaly",
                           "yellow:after_hours", "red:after_hours"]
            alert_rows = (
                session.query(AlertLog)
                .filter(AlertLog.timestamp >= cutoff_7d, AlertLog.alert_type.in_(alert_types))
                .order_by(AlertLog.timestamp.desc()).limit(20).all()
            )
            for al in alert_rows:
                at = al.alert_type or ""
                atype = "NIGHT_UNKNOWN" if "night" in at else "PATTERN_BREAK"
                severity = "high" if at.startswith("red:") else "medium"
                strip = (al.message or "").replace("<b>", "").replace("</b>", "").replace("\n", " ").strip()[:120]
                anomalies.append({
                    "timestamp": al.timestamp.isoformat() if al.timestamp else None,
                    "type": atype, "severity": severity, "description": strip,
                    "entity_id": al.device_id,
                    "entity_type": "device" if al.device_id else None,
                    "entity_ref": None,
                })

            # ── New persistent unknowns (first seen ≥7d ago, 3+ days) ──
            persistent_subq = (
                session.query(
                    Visit.device_id,
                    func.count(sa_distinct(func.date(Visit.arrived_at))).label("dc"),
                )
                .group_by(Visit.device_id)
                .having(func.count(sa_distinct(func.date(Visit.arrived_at))) >= 3)
                .subquery()
            )
            new_persist = (
                session.query(Device, Tag)
                .join(persistent_subq, Device.id == persistent_subq.c.device_id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(
                    Device.first_seen >= cutoff_7d,
                    (Tag.category == "unknown") | (Tag.id.is_(None)),
                )
                .order_by(Device.first_seen.desc()).limit(10).all()
            )
            for dev, tag in new_persist:
                anomalies.append({
                    "timestamp": dev.first_seen.isoformat() if dev.first_seen else None,
                    "type": "NEW_PERSISTENT",
                    "severity": "medium",
                    "description": f"Unknown device {dev.vendor or dev.mac} reached 3-day threshold — new recurring unknown",
                    "entity_id": dev.id, "entity_type": "device", "entity_ref": dev.mac,
                })

            # ── Ghost arrivals ──
            arrival_sensors = set(
                r[0] for r in session.query(ArrivalEvent.tpms_sensor_id)
                .filter(ArrivalEvent.tpms_sensor_id.isnot(None)).distinct().all()
            )
            ghost_ids = set(
                r[0] for r in session.query(VehicleProfile.sensor_id)
                .filter(VehicleProfile.sighting_count > 20).all()
                if r[0] not in arrival_sensors
            )
            if ghost_ids:
                ghost_bundles = (
                    session.query(PresenceBundle)
                    .filter(
                        PresenceBundle.timestamp >= cutoff_7d,
                        PresenceBundle.has_person.is_(True),
                        PresenceBundle.tpms_sensor_id.in_(list(ghost_ids)[:20]),
                    )
                    .order_by(PresenceBundle.timestamp.desc()).limit(10).all()
                )
                for b in ghost_bundles:
                    anomalies.append({
                        "timestamp": b.timestamp.isoformat() if b.timestamp else None,
                        "type": "GHOST_ARRIVAL",
                        "severity": "high",
                        "description": f"Ghost vehicle {b.tpms_sensor_id} — arrived with camera person, no WiFi correlation ever recorded",
                        "entity_id": None, "entity_type": "vehicle", "entity_ref": b.tpms_sensor_id,
                    })

            anomalies.sort(key=lambda x: x["timestamp"] or "", reverse=True)
            return jsonify(anomalies[:50])
        finally:
            session.close()

    @app.route("/settings")
    def settings():
        return render_template(
            "coming_soon.html",
            page_title="SETTINGS",
            page_desc="System configuration — sensors, alerts, thresholds",
        )

    # -- Operations API --

    @app.route("/api/service-status")
    def api_service_status():
        """Return systemd active/inactive status for each sentinel service."""
        services = [
            "sentinel-wifi",
            "sentinel-bt",
            "sentinel-sdr",
            "sentinel-frigate",
            "sentinel-droneid",
            "sentinel-web",
        ]
        result = {}
        for svc in services:
            try:
                r = subprocess.run(
                    ["systemctl", "is-active", svc],
                    capture_output=True, text=True, timeout=3
                )
                result[svc] = r.stdout.strip() or "unknown"
            except Exception:
                result[svc] = "unknown"
        return jsonify(result)

    @app.route("/api/ops-data")
    def api_ops_data():
        """Single endpoint returning all data needed for the Operations page."""
        from collections import defaultdict
        from sqlalchemy import func, distinct as sa_distinct

        session = get_session()
        try:
            now = datetime.now(timezone.utc)
            active_window = now - timedelta(minutes=10)
            cutoff_24h   = now - timedelta(hours=24)
            cutoff_2h    = now - timedelta(hours=2)

            # ── 1. Active devices by tag category ──
            active_rows = (
                session.query(Device, Tag)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(Device.last_seen >= active_window)
                .all()
            )
            by_cat = defaultdict(int)
            for dev, tag in active_rows:
                by_cat[tag.category if tag else "unknown"] += 1

            active_devices = {
                "total":    len(active_rows),
                "resident": by_cat.get("resident", 0),
                "neighbor": by_cat.get("neighbor", 0),
                "unknown":  by_cat.get("unknown", 0),
            }

            # ── 2. Open visits ──
            open_visit_rows = (
                session.query(Visit, Device, Tag)
                .join(Device, Visit.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(Visit.departed_at.is_(None))
                .order_by(Visit.arrived_at.asc())
                .limit(15)
                .all()
            )
            open_visits = []
            for v, dev, tag in open_visit_rows:
                arrived = v.arrived_at
                if arrived and arrived.tzinfo is None:
                    arrived = arrived.replace(tzinfo=timezone.utc)
                dwell = int((now - arrived).total_seconds()) if arrived else 0
                open_visits.append({
                    "mac":          dev.mac,
                    "vendor":       dev.vendor,
                    "alias":        dev.alias,
                    "device_id":    dev.id,
                    "tag_category": tag.category if tag else "unknown",
                    "tag_label":    tag.label if tag else None,
                    "dwell_seconds": dwell,
                    "rssi":         v.max_rssi,
                    "arrived_at":   v.arrived_at.isoformat() if v.arrived_at else None,
                })

            # ── 3. Recent correlated arrivals ──
            arr_rows = (
                session.query(ArrivalEvent, Device, Tag)
                .outerjoin(Device, ArrivalEvent.wifi_device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .order_by(ArrivalEvent.timestamp.desc())
                .limit(5)
                .all()
            )
            recent_arrivals = [
                {
                    "timestamp":    arr.timestamp.isoformat() if arr.timestamp else None,
                    "tpms_model":   arr.tpms_model,
                    "tpms_sensor_id": arr.tpms_sensor_id,
                    "confidence":   arr.confidence,
                    "tpms_rssi":    arr.tpms_rssi,
                    "wifi_vendor":  dev.vendor if dev else None,
                    "wifi_mac":     dev.mac if dev else None,
                    "wifi_device_id": dev.id if dev else None,
                    "tag_category": tag.category if tag else None,
                }
                for arr, dev, tag in arr_rows
            ]

            # ── 4a. Persistent unknowns: 3+ distinct days, not yet tagged ──
            day_subq = (
                session.query(
                    Visit.device_id,
                    func.count(sa_distinct(func.date(Visit.arrived_at))).label("day_count"),
                    func.count(Visit.id).label("visit_count"),
                )
                .filter(Visit.arrived_at.isnot(None))
                .group_by(Visit.device_id)
                .having(func.count(sa_distinct(func.date(Visit.arrived_at))) >= 3)
                .subquery()
            )
            pers_rows = (
                session.query(Device, Tag,
                              day_subq.c.day_count, day_subq.c.visit_count)
                .join(day_subq, Device.id == day_subq.c.device_id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter((Tag.id.is_(None)) | (Tag.category == "unknown"))
                .order_by(day_subq.c.day_count.desc())
                .limit(10)
                .all()
            )
            persistent_unknowns = [
                {
                    "device_id":    dev.id,
                    "mac":          dev.mac,
                    "vendor":       dev.vendor,
                    "days_seen":    day_count or 0,
                    "total_visits": visit_count or 0,
                    "last_seen":    dev.last_seen.isoformat() if dev.last_seen else None,
                    "is_randomized": dev.is_randomized,
                }
                for dev, tag, day_count, visit_count in pers_rows
            ]

            # ── 4b. Ghost vehicles: 20+ sightings, never WiFi-correlated ──
            wifi_sensors = (
                session.query(ArrivalEvent.tpms_sensor_id)
                .filter(ArrivalEvent.tpms_sensor_id.isnot(None))
                .distinct()
                .subquery()
            )
            ghost_rows = (
                session.query(VehicleProfile)
                .filter(
                    VehicleProfile.sighting_count > 20,
                    ~VehicleProfile.sensor_id.in_(wifi_sensors),
                )
                .order_by(VehicleProfile.sighting_count.desc())
                .limit(10)
                .all()
            )
            ghost_vehicles = [
                {
                    "sensor_id":     vp.sensor_id,
                    "model":         vp.model,
                    "sighting_count": vp.sighting_count,
                    "last_seen":     vp.last_seen.isoformat() if vp.last_seen else None,
                    "avg_rssi":      vp.avg_rssi,
                }
                for vp in ghost_rows
            ]

            # ── 4c. Unreviewed person detections (last 24h) ──
            person_rows = (
                session.query(FrigateEvent)
                .filter(
                    FrigateEvent.label == "person",
                    FrigateEvent.correlated_device_id.is_(None),
                    FrigateEvent.timestamp >= cutoff_24h,
                )
                .order_by(FrigateEvent.timestamp.desc())
                .limit(10)
                .all()
            )
            unreviewed_persons = [
                {
                    "id":            fe.id,
                    "timestamp":     fe.timestamp.isoformat() if fe.timestamp else None,
                    "camera":        fe.camera,
                    "confidence":    fe.confidence,
                    "snapshot_path": fe.snapshot_path.split("/")[-1] if fe.snapshot_path else None,
                }
                for fe in person_rows
            ]

            # ── 4d. Hacker hardware hits (last 24h) ──
            hacker_rows = (
                session.query(AlertLog, Device, Tag)
                .outerjoin(Device, AlertLog.device_id == Device.id)
                .outerjoin(Tag, Device.id == Tag.device_id)
                .filter(
                    AlertLog.timestamp >= cutoff_24h,
                    AlertLog.alert_type.ilike("%hacker%"),
                )
                .order_by(AlertLog.timestamp.desc())
                .limit(10)
                .all()
            )
            hacker_hits = [
                {
                    "timestamp":  al.timestamp.isoformat() if al.timestamp else None,
                    "alert_type": al.alert_type,
                    "message":    al.message,
                    "mac":        dev.mac if dev else None,
                    "vendor":     dev.vendor if dev else None,
                    "device_id":  dev.id if dev else None,
                }
                for al, dev, tag in hacker_rows
            ]

            # ── 5. Camera latest (most recent FrigateEvent per camera) ──
            cam_subq = (
                session.query(
                    FrigateEvent.camera,
                    func.max(FrigateEvent.id).label("max_id"),
                )
                .group_by(FrigateEvent.camera)
                .subquery()
            )
            cam_events = (
                session.query(FrigateEvent)
                .join(cam_subq, FrigateEvent.id == cam_subq.c.max_id)
                .all()
            )
            camera_latest = {}
            for fe in cam_events:
                camera_latest[fe.camera] = {
                    "label":        fe.label,
                    "timestamp":    fe.timestamp.isoformat() if fe.timestamp else None,
                    "snapshot_path": fe.snapshot_path.split("/")[-1] if fe.snapshot_path else None,
                    "confidence":   fe.confidence,
                }
            # Ensure all configured cameras appear
            for cam in cfg.get("frigate", {}).get(
                "cameras",
                ["front_yard_east", "front_yard_west", "east_corridor", "west_corridor"]
            ):
                camera_latest.setdefault(cam, None)

            # ── 6. Recent SDR signals ──
            sdr_rows = (
                session.query(SdrSignal)
                .order_by(SdrSignal.timestamp.desc())
                .limit(5)
                .all()
            )
            sdr_recent = [
                {
                    "timestamp":    s.timestamp.isoformat() if s.timestamp else None,
                    "signal_class": s.signal_class,
                    "model":        s.model,
                    "device_uid":   s.device_uid,
                    "rssi":         s.rssi,
                    "frequency":    s.frequency,
                }
                for s in sdr_rows
            ]

            # ── 7. Drone events (last 24h) ──
            drone_rows = (
                session.query(DroneIdEvent)
                .filter(DroneIdEvent.timestamp >= cutoff_24h)
                .order_by(DroneIdEvent.timestamp.desc())
                .limit(5)
                .all()
            )
            drone_recent = [
                {
                    "timestamp":     de.timestamp.isoformat() if de.timestamp else None,
                    "mac":           de.mac,
                    "serial_number": de.serial_number,
                    "drone_lat":     de.drone_lat,
                    "drone_lon":     de.drone_lon,
                    "rssi":          de.rssi,
                }
                for de in drone_rows
            ]

            # ── 8. Threat band: RED/YELLOW alerts in last 2h ──
            threat_rows = (
                session.query(AlertLog, Device)
                .outerjoin(Device, AlertLog.device_id == Device.id)
                .filter(
                    AlertLog.timestamp >= cutoff_2h,
                    (AlertLog.alert_type.startswith("red:"))
                    | (AlertLog.alert_type.startswith("yellow:")),
                )
                .order_by(AlertLog.timestamp.desc())
                .limit(20)
                .all()
            )
            threat_band = []
            for al, dev in threat_rows:
                parts = al.alert_type.split(":", 1)
                threat_band.append({
                    "level":      parts[0] if len(parts) > 1 else "unknown",
                    "alert_type": parts[1] if len(parts) > 1 else al.alert_type,
                    "mac":        dev.mac if dev else None,
                    "device_id":  dev.id if dev else None,
                    "timestamp":  al.timestamp.isoformat() if al.timestamp else None,
                    "message":    al.message,
                })

            # ── 9. Activity pulse: 24h hourly event counts + env baseline ──
            hourly_counts = []
            for h in range(24):
                h_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23 - h)
                h_end   = h_start + timedelta(hours=1)
                cnt = session.query(func.count(Event.id)).filter(
                    Event.timestamp.between(h_start, h_end)
                ).scalar() or 0
                hourly_counts.append(cnt)

            # Load baseline from env_baselines.json, compute composite
            baseline_counts = [0.0] * 24
            try:
                bl_path = Path("/opt/sentinel/data/env_baselines.json")
                if bl_path.exists():
                    with open(bl_path) as f:
                        bl_data = json.load(f)
                    bl_h = bl_data.get("hourly", {})
                    tpms_h   = bl_h.get("sdr_tpms",       [0] * 24)
                    car_h    = bl_h.get("frigate_car",     [0] * 24)
                    person_h = bl_h.get("frigate_person",  [0] * 24)
                    raw = [tpms_h[i] + car_h[i] + person_h[i] * 3 for i in range(24)]
                    max_raw    = max(raw) or 1
                    max_actual = max(hourly_counts) or 1
                    scale = max_actual / max_raw
                    baseline_counts = [round(v * scale, 1) for v in raw]
            except Exception as e:
                logger.warning("env_baselines load failed: %s", e)

            return jsonify({
                "active_devices":  active_devices,
                "open_visits":     open_visits,
                "recent_arrivals": recent_arrivals,
                "attention": {
                    "persistent_unknowns": persistent_unknowns,
                    "ghost_vehicles":      ghost_vehicles,
                    "unreviewed_persons":  unreviewed_persons,
                    "hacker_hits":         hacker_hits,
                },
                "camera_latest": camera_latest,
                "sdr_recent":    sdr_recent,
                "drone_recent":  drone_recent,
                "threat_band":   threat_band,
                "activity_pulse": {
                    "counts":           hourly_counts,
                    "baseline":         baseline_counts,
                    "current_hour_idx": 23,
                },
                "generated_at": now.isoformat(),
            })
        finally:
            session.close()

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
