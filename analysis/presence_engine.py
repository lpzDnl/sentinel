"""SENTINEL Presence Bundle Engine.

Correlates TPMS vehicle arrivals with co-present WiFi/BT devices and
Frigate camera events to build rich vehicle identity profiles.

Tables used: PresenceBundle, VehicleIdentityCluster (see database.py)

Entry points
────────────
  build_presence_bundle(tpms_signal_id)   → PresenceBundle | None
  backfill_presence_bundles(days=6)       → stats dict
  cluster_vehicle_identities()            → stats dict
  get_vehicle_profile_enriched(sensor_id) → dict
  find_same_person_different_vehicle()    → list[dict]
  run_presence_analysis()                 → combined stats dict
"""

import json
import logging
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/opt/sentinel")

from sqlalchemy.exc import IntegrityError

from database import (
    Device,
    Event,
    FrigateEvent,
    PresenceBundle,
    ProbeRequest,
    SdrSignal,
    Tag,
    VehicleIdentityCluster,
    VehicleProfile,
    get_session,
    init_db,
)

logger = logging.getLogger("sentinel.presence_engine")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _naive(dt: datetime) -> datetime:
    """Strip tzinfo for SQLite comparisons (DB stores naive UTC)."""
    if dt is None:
        return dt
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


# ---------------------------------------------------------------------------
# Core bundle builder
# ---------------------------------------------------------------------------

def build_presence_bundle(
    tpms_signal_id: int,
    resident_ids: set[int] | None = None,
) -> "PresenceBundle | None":
    """Build a PresenceBundle for a TPMS SdrSignal.

    Queries WiFi (±3 min), BT (±3 min), and Frigate (±5 min) events
    co-present with the TPMS signal.  Resident-tagged WiFi devices are
    excluded from wifi_device_ids (they're known quantities).

    Args:
        tpms_signal_id: SdrSignal.id for a TPMS signal.
        resident_ids: Optional pre-fetched set of resident device IDs for
            performance (avoids a subquery per call during backfill).

    Returns the new bundle, or None if already exists / signal not found.
    """
    session = get_session()
    try:
        sig = session.get(SdrSignal, tpms_signal_id)
        if not sig or sig.signal_class != "tpms":
            return None

        # Dedup: one bundle per TPMS signal
        existing = (
            session.query(PresenceBundle)
            .filter(PresenceBundle.tpms_signal_id == tpms_signal_id)
            .first()
        )
        if existing:
            return None

        ts = _naive(sig.timestamp)
        wifi_lo = ts - timedelta(minutes=3)
        wifi_hi = ts + timedelta(minutes=3)
        frg_lo  = ts - timedelta(minutes=5)
        frg_hi  = ts + timedelta(minutes=5)

        # Resident IDs: use provided set or fetch inline
        if resident_ids is None:
            resident_ids = set(
                r[0]
                for r in session.query(Tag.device_id)
                .filter(Tag.category == "resident")
                .all()
            )

        # ── WiFi device IDs (probe_requests + wifi/arrival events) ──
        probe_ids = set(
            r[0]
            for r in session.query(ProbeRequest.device_id)
            .filter(
                ProbeRequest.timestamp.between(wifi_lo, wifi_hi),
                ProbeRequest.device_id.isnot(None),
            )
            .distinct()
            .all()
        ) - resident_ids

        wifi_event_ids = set(
            r[0]
            for r in session.query(Event.device_id)
            .filter(
                Event.timestamp.between(wifi_lo, wifi_hi),
                Event.event_type.in_(["wifi_probe", "wifi_data", "arrival"]),
                Event.device_id.isnot(None),
            )
            .distinct()
            .all()
        ) - resident_ids

        wifi_device_ids = sorted(probe_ids | wifi_event_ids)

        # ── BT device IDs ──
        bt_device_ids = sorted(set(
            r[0]
            for r in session.query(Event.device_id)
            .filter(
                Event.timestamp.between(wifi_lo, wifi_hi),
                Event.event_type.in_(["bt_ble", "bt_classic"]),
                Event.device_id.isnot(None),
            )
            .distinct()
            .all()
        ))

        # ── Frigate events ──
        frigate_rows = (
            session.query(FrigateEvent.id, FrigateEvent.label)
            .filter(FrigateEvent.timestamp.between(frg_lo, frg_hi))
            .all()
        )
        frigate_event_ids = [r[0] for r in frigate_rows]
        has_person = any(r[1] == "person" for r in frigate_rows)

        # ── Probe SSID fingerprint ──
        # SSIDs probed by co-present (non-resident) WiFi devices in window
        if wifi_device_ids:
            ssid_rows = (
                session.query(ProbeRequest.ssid)
                .filter(
                    ProbeRequest.timestamp.between(wifi_lo, wifi_hi),
                    ProbeRequest.device_id.in_(wifi_device_ids),
                    ProbeRequest.ssid.isnot(None),
                    ProbeRequest.ssid != "",
                )
                .distinct()
                .all()
            )
            ssids = sorted(r[0] for r in ssid_rows)
        else:
            ssids = []

        probe_ssid_fingerprint = ",".join(ssids)

        # ── Save ──
        bundle = PresenceBundle(
            timestamp=sig.timestamp,
            tpms_signal_id=tpms_signal_id,
            tpms_sensor_id=sig.device_uid,
            tpms_model=sig.model,
            tpms_rssi=sig.rssi,
            wifi_device_ids=json.dumps(wifi_device_ids),
            bt_device_ids=json.dumps(bt_device_ids),
            frigate_event_ids=json.dumps(frigate_event_ids),
            has_person=has_person,
            probe_ssid_fingerprint=probe_ssid_fingerprint,
        )
        session.add(bundle)
        session.commit()
        session.refresh(bundle)
        session.expunge(bundle)

        logger.debug(
            "Bundle tpms=%s  wifi=%d  bt=%d  frigate=%d  person=%s  ssids=%d",
            sig.device_uid, len(wifi_device_ids), len(bt_device_ids),
            len(frigate_event_ids), has_person, len(ssids),
        )
        return bundle

    except IntegrityError:
        # Another process already created this bundle (race during backfill)
        session.rollback()
        logger.debug("Bundle already exists for signal %d (race skip)", tpms_signal_id)
        return None
    except Exception as e:
        session.rollback()
        logger.error("build_presence_bundle(%d) failed: %s", tpms_signal_id, e)
        return None
    finally:
        session.close()


# ---------------------------------------------------------------------------
# BT vendor backfill
# ---------------------------------------------------------------------------

def backfill_bt_vendors() -> dict:
    """Resolve OUI vendor names for BT devices currently missing them.

    Uses the same scapy OUI database as wifi_capture.resolve_vendor().
    Skips devices flagged is_randomized=True and any device where scapy
    returns the MAC string itself (no OUI match).

    Returns stats: {total, resolved, failed, already_had_vendor}
    """
    try:
        from capture.wifi_capture import resolve_vendor
    except ImportError:
        # Fallback: inline the same scapy lookup if capture module isn't importable
        from scapy.all import conf as _scapy_conf
        _db = _scapy_conf.manufdb

        def resolve_vendor(mac: str):
            try:
                r = _db.lookup(mac)
                if r and r[0]:
                    return str(r[1] if len(r) > 1 and r[1] else r[0])
            except Exception:
                pass
            return None

    session = get_session()
    try:
        bt_devices = (
            session.query(Device)
            .filter(
                Device.device_type.in_(["bluetooth_le", "bluetooth_classic"]),
                Device.vendor.is_(None),
                Device.is_randomized == False,
            )
            .all()
        )
    finally:
        session.close()

    stats = {
        "total":              len(bt_devices),
        "resolved":           0,
        "failed":             0,
        "already_had_vendor": 0,
    }

    logger.info("BT vendor backfill: %d devices to resolve", len(bt_devices))

    BATCH = 100
    updates: list[tuple[int, str]] = []  # (device_id, vendor)

    for dev in bt_devices:
        vendor = resolve_vendor(dev.mac)
        # Scapy returns the MAC itself when the OUI is unknown — discard those
        if vendor and vendor.upper() != dev.mac.upper():
            updates.append((dev.id, vendor))
            stats["resolved"] += 1
        else:
            stats["failed"] += 1

        if len(updates) >= BATCH:
            _flush_vendor_updates(updates)
            updates.clear()

    if updates:
        _flush_vendor_updates(updates)

    logger.info(
        "BT vendor backfill done: resolved=%d  failed=%d  total=%d",
        stats["resolved"], stats["failed"], stats["total"],
    )
    return stats


def _flush_vendor_updates(updates: list[tuple[int, str]]) -> None:
    """Batch-write vendor strings to device rows."""
    session = get_session()
    try:
        for dev_id, vendor in updates:
            dev = session.get(Device, dev_id)
            if dev:
                dev.vendor = vendor
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error("vendor update flush failed: %s", e)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------

def backfill_presence_bundles(days: int = 6) -> dict:
    """Build PresenceBundles for all TPMS signals in the last N days.

    Uses a memory-resident approach: loads all WiFi/BT/Frigate events and
    probe SSIDs from the window into sorted Python lists, then does fast
    binary-search range lookups instead of per-signal DB queries.

    Already-bundled signals are skipped (idempotent).

    Returns stats: {total_tpms, bundles_created, skipped, with_person,
                    with_wifi, with_bt}
    """
    import bisect

    cutoff = _naive(datetime.now(timezone.utc) - timedelta(days=days))
    # Load slightly wider than the window to cover ±5 min Frigate lookback
    load_lo = cutoff - timedelta(minutes=6)

    logger.info("Loading sensor data from the last %d days into memory...", days)

    session = get_session()
    try:
        # TPMS signals to process
        tpms_rows = session.query(
            SdrSignal.id, SdrSignal.timestamp,
            SdrSignal.device_uid, SdrSignal.model, SdrSignal.rssi,
        ).filter(
            SdrSignal.signal_class == "tpms",
            SdrSignal.timestamp >= cutoff,
        ).order_by(SdrSignal.timestamp).all()

        already_bundled: set[int] = set(
            r[0] for r in session.query(PresenceBundle.tpms_signal_id).all()
        )
        resident_ids: set[int] = set(
            r[0] for r in session.query(Tag.device_id)
            .filter(Tag.category == "resident").all()
        )

        # WiFi: (timestamp, device_id) from probe_requests + wifi events
        wifi_probe_rows = session.query(
            ProbeRequest.timestamp, ProbeRequest.device_id,
        ).filter(
            ProbeRequest.timestamp >= load_lo,
            ProbeRequest.device_id.isnot(None),
        ).all()

        wifi_event_rows = session.query(
            Event.timestamp, Event.device_id,
        ).filter(
            Event.timestamp >= load_lo,
            Event.event_type.in_(["wifi_probe", "wifi_data", "arrival"]),
            Event.device_id.isnot(None),
        ).all()

        # BT: (timestamp, device_id)
        bt_rows = session.query(
            Event.timestamp, Event.device_id,
        ).filter(
            Event.timestamp >= load_lo,
            Event.event_type.in_(["bt_ble", "bt_classic"]),
            Event.device_id.isnot(None),
        ).all()

        # Frigate: (timestamp, id, label)
        frigate_rows = session.query(
            FrigateEvent.timestamp, FrigateEvent.id, FrigateEvent.label,
        ).filter(FrigateEvent.timestamp >= load_lo).all()

        # Probe SSIDs: (timestamp, device_id, ssid)
        ssid_rows = session.query(
            ProbeRequest.timestamp, ProbeRequest.device_id, ProbeRequest.ssid,
        ).filter(
            ProbeRequest.timestamp >= load_lo,
            ProbeRequest.ssid.isnot(None),
            ProbeRequest.ssid != "",
        ).all()

    finally:
        session.close()

    logger.info(
        "Loaded: tpms=%d  wifi_probes=%d  wifi_events=%d  bt=%d  frigate=%d  ssids=%d",
        len(tpms_rows), len(wifi_probe_rows), len(wifi_event_rows),
        len(bt_rows), len(frigate_rows), len(ssid_rows),
    )

    # Build sorted (timestamp, payload) lists for binary-search lookups
    def _sort_ts(rows):
        return sorted((_naive(r[0]), r[1:]) for r in rows)

    # WiFi: merge probe + event sources, deduplicate by (ts, device_id)
    all_wifi = {}
    for ts_naive, (dev_id,) in _sort_ts(wifi_probe_rows):
        if dev_id not in resident_ids:
            all_wifi.setdefault(ts_naive, set()).add(dev_id)
    for ts_naive, (dev_id,) in _sort_ts(wifi_event_rows):
        if dev_id not in resident_ids:
            all_wifi.setdefault(ts_naive, set()).add(dev_id)
    # Flatten to sorted list of (ts, device_id) pairs
    wifi_ts_list = sorted(all_wifi.keys())
    wifi_ids_by_ts = all_wifi  # ts -> set of device_ids

    bt_sorted   = _sort_ts(bt_rows)       # [(ts, (dev_id,)), ...]
    frg_sorted  = _sort_ts(frigate_rows)  # [(ts, (id, label)), ...]
    ssid_sorted = _sort_ts(ssid_rows)     # [(ts, (dev_id, ssid)), ...]

    # Index lists for bisect on timestamps
    bt_ts   = [r[0] for r in bt_sorted]
    frg_ts  = [r[0] for r in frg_sorted]
    ssid_ts = [r[0] for r in ssid_sorted]

    def _range_idx(ts_list, lo, hi):
        """Return slice indices for items with timestamp in [lo, hi]."""
        return bisect.bisect_left(ts_list, lo), bisect.bisect_right(ts_list, hi)

    # Process pending signals
    pending = [r for r in tpms_rows if r[0] not in already_bundled]
    stats = {
        "total_tpms":      len(tpms_rows),
        "bundles_created": 0,
        "skipped":         len(tpms_rows) - len(pending),
        "with_person":     0,
        "with_wifi":       0,
        "with_bt":         0,
    }
    logger.info(
        "Backfilling: %d total TPMS, %d already done, %d pending",
        len(tpms_rows), stats["skipped"], len(pending),
    )

    BATCH = 200
    bundles_batch: list[PresenceBundle] = []

    def _flush_batch():
        if not bundles_batch:
            return
        s = get_session()
        try:
            for b in bundles_batch:
                s.add(b)
            s.commit()
        except Exception as e:
            s.rollback()
            logger.error("Batch flush error: %s", e)
        finally:
            s.close()
        bundles_batch.clear()

    for sig_id, sig_ts_raw, sensor_id, model, rssi in pending:
        sig_ts = _naive(sig_ts_raw)
        wifi_lo = sig_ts - timedelta(minutes=3)
        wifi_hi = sig_ts + timedelta(minutes=3)
        frg_lo  = sig_ts - timedelta(minutes=5)
        frg_hi  = sig_ts + timedelta(minutes=5)

        # WiFi device IDs from pre-loaded data
        wifi_device_ids: set[int] = set()
        wlo_idx = bisect.bisect_left(wifi_ts_list, wifi_lo)
        whi_idx = bisect.bisect_right(wifi_ts_list, wifi_hi)
        for wts in wifi_ts_list[wlo_idx:whi_idx]:
            wifi_device_ids |= wifi_ids_by_ts[wts]

        # BT device IDs
        i0, i1 = _range_idx(bt_ts, wifi_lo, wifi_hi)
        bt_device_ids: set[int] = {bt_sorted[i][1][0] for i in range(i0, i1)}

        # Frigate events
        i0, i1 = _range_idx(frg_ts, frg_lo, frg_hi)
        frigate_event_ids: list[int] = []
        has_person = False
        for i in range(i0, i1):
            fe_id, fe_label = frg_sorted[i][1]
            frigate_event_ids.append(fe_id)
            if fe_label == "person":
                has_person = True

        # Probe SSID fingerprint from co-present WiFi devices
        ssids: set[str] = set()
        if wifi_device_ids:
            i0, i1 = _range_idx(ssid_ts, wifi_lo, wifi_hi)
            for i in range(i0, i1):
                dev_id, ssid = ssid_sorted[i][1]
                if dev_id in wifi_device_ids:
                    ssids.add(ssid)

        probe_ssid_fingerprint = ",".join(sorted(ssids))
        wifi_ids_list = sorted(wifi_device_ids)
        bt_ids_list   = sorted(bt_device_ids)

        bundle = PresenceBundle(
            timestamp=sig_ts_raw,
            tpms_signal_id=sig_id,
            tpms_sensor_id=sensor_id,
            tpms_model=model,
            tpms_rssi=rssi,
            wifi_device_ids=json.dumps(wifi_ids_list),
            bt_device_ids=json.dumps(bt_ids_list),
            frigate_event_ids=json.dumps(frigate_event_ids),
            has_person=has_person,
            probe_ssid_fingerprint=probe_ssid_fingerprint,
        )
        bundles_batch.append(bundle)
        stats["bundles_created"] += 1
        if has_person:
            stats["with_person"] += 1
        if wifi_ids_list:
            stats["with_wifi"] += 1
        if bt_ids_list:
            stats["with_bt"] += 1

        if len(bundles_batch) >= BATCH:
            _flush_batch()

    _flush_batch()

    logger.info(
        "Backfill done: created=%d  skipped=%d  person=%d  wifi=%d  bt=%d",
        stats["bundles_created"], stats["skipped"],
        stats["with_person"], stats["with_wifi"], stats["with_bt"],
    )
    return stats


# ---------------------------------------------------------------------------
# Identity clustering
# ---------------------------------------------------------------------------

def cluster_vehicle_identities() -> dict:
    """Group PresenceBundles by vehicle and upsert VehicleIdentityCluster rows.

    For each TPMS sensor ID:
      - Most common probe SSID fingerprint becomes the representative signature
      - BT vendors are aggregated from all co-present BT device IDs
      - Camera appearances counted from Frigate person events

    Returns stats: {vehicles_clustered, with_ssid_signature, with_bt,
                    with_camera}
    """
    session = get_session()
    try:
        bundles = session.query(PresenceBundle).all()

        # Group by tpms_sensor_id
        by_vehicle: dict[str, list] = {}
        for b in bundles:
            by_vehicle.setdefault(b.tpms_sensor_id, []).append(b)

        stats = {
            "vehicles_clustered":  0,
            "with_ssid_signature": 0,
            "with_bt":             0,
            "with_camera":         0,
        }

        now_naive = _naive(datetime.now(timezone.utc))

        for sensor_id, vbundles in by_vehicle.items():
            # Sort chronologically for first/last timestamps
            vbundles.sort(key=lambda b: b.timestamp)

            fp_counter: Counter = Counter()
            all_bt_ids: list[int] = []
            person_frigate_ids: list[int] = []

            for b in vbundles:
                fp = b.probe_ssid_fingerprint or ""
                if fp:
                    fp_counter[fp] += 1

                all_bt_ids.extend(json.loads(b.bt_device_ids or "[]"))

                if b.has_person:
                    person_frigate_ids.extend(
                        json.loads(b.frigate_event_ids or "[]")
                    )

            # Representative SSID set = most common fingerprint
            representative_ssids: list[str] = []
            if fp_counter:
                most_common_fp = fp_counter.most_common(1)[0][0]
                representative_ssids = [s for s in most_common_fp.split(",") if s]

            # BT vendors from unique device IDs
            associated_bt_vendors: list[str] = []
            if all_bt_ids:
                vendor_rows = (
                    session.query(Device.vendor)
                    .filter(
                        Device.id.in_(list(set(all_bt_ids))),
                        Device.vendor.isnot(None),
                    )
                    .all()
                )
                vc: Counter = Counter()
                for (vendor,) in vendor_rows:
                    # Use the first word, stripped of trailing punctuation
                    mfr = vendor.split()[0].rstrip(",.;") if vendor else None
                    if mfr:
                        vc[mfr] += 1
                associated_bt_vendors = [v for v, _ in vc.most_common(5)]

            # Camera appearances from person Frigate events
            camera_appearances = 0
            dominant_camera = None
            if person_frigate_ids:
                cam_rows = (
                    session.query(FrigateEvent.camera)
                    .filter(
                        FrigateEvent.id.in_(list(set(person_frigate_ids))),
                        FrigateEvent.label == "person",
                    )
                    .all()
                )
                cam_counter: Counter = Counter(r[0] for r in cam_rows)
                camera_appearances = sum(cam_counter.values())
                if cam_counter:
                    dominant_camera = cam_counter.most_common(1)[0][0]

            # Upsert cluster
            cluster = (
                session.query(VehicleIdentityCluster)
                .filter(VehicleIdentityCluster.tpms_sensor_id == sensor_id)
                .first()
            )
            if cluster is None:
                cluster = VehicleIdentityCluster(
                    tpms_sensor_id=sensor_id,
                    first_seen=vbundles[0].timestamp,
                )
                session.add(cluster)

            cluster.representative_ssids  = json.dumps(representative_ssids)
            cluster.associated_bt_vendors = json.dumps(associated_bt_vendors)
            cluster.bundle_count          = len(vbundles)
            cluster.last_seen             = vbundles[-1].timestamp
            cluster.last_updated          = now_naive
            cluster.camera_appearances    = camera_appearances
            cluster.dominant_camera       = dominant_camera

            stats["vehicles_clustered"] += 1
            if representative_ssids:
                stats["with_ssid_signature"] += 1
            if associated_bt_vendors:
                stats["with_bt"] += 1
            if camera_appearances > 0:
                stats["with_camera"] += 1

        session.commit()

        logger.info(
            "Clustered %d vehicles: ssid_sig=%d  bt=%d  camera=%d",
            stats["vehicles_clustered"], stats["with_ssid_signature"],
            stats["with_bt"], stats["with_camera"],
        )
        return stats

    except Exception as e:
        session.rollback()
        logger.error("cluster_vehicle_identities failed: %s", e)
        return {
            "vehicles_clustered": 0, "with_ssid_signature": 0,
            "with_bt": 0, "with_camera": 0,
        }
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Enriched profile
# ---------------------------------------------------------------------------

def get_vehicle_profile_enriched(tpms_sensor_id: str) -> dict:
    """Return vehicle_profile + identity_cluster + recent bundles as one dict.

    Includes a human-readable summary line.
    """
    session = get_session()
    try:
        profile = (
            session.query(VehicleProfile)
            .filter(VehicleProfile.sensor_id == tpms_sensor_id)
            .first()
        )
        cluster = (
            session.query(VehicleIdentityCluster)
            .filter(VehicleIdentityCluster.tpms_sensor_id == tpms_sensor_id)
            .first()
        )
        recent = (
            session.query(PresenceBundle)
            .filter(PresenceBundle.tpms_sensor_id == tpms_sensor_id)
            .order_by(PresenceBundle.timestamp.desc())
            .limit(5)
            .all()
        )

        result: dict = {
            "tpms_sensor_id": tpms_sensor_id,
            "profile":        None,
            "cluster":        None,
            "recent_bundles": [],
            "summary":        None,
        }

        if profile:
            result["profile"] = {
                "model":          profile.model,
                "first_seen":     profile.first_seen,
                "last_seen":      profile.last_seen,
                "sighting_count": profile.sighting_count,
                "avg_rssi":       profile.avg_rssi,
                "flagged":        profile.flagged,
                "flag_reason":    profile.flag_reason,
                "notes":          profile.notes,
            }

        if cluster:
            ssids     = json.loads(cluster.representative_ssids  or "[]")
            bt_vendors = json.loads(cluster.associated_bt_vendors or "[]")
            result["cluster"] = {
                "cluster_label":         cluster.cluster_label,
                "representative_ssids":  ssids,
                "associated_bt_vendors": bt_vendors,
                "bundle_count":          cluster.bundle_count,
                "first_seen":            cluster.first_seen,
                "last_seen":             cluster.last_seen,
                "camera_appearances":    cluster.camera_appearances,
                "dominant_camera":       cluster.dominant_camera,
            }

        for b in recent:
            result["recent_bundles"].append({
                "timestamp":    b.timestamp,
                "wifi_count":   len(json.loads(b.wifi_device_ids   or "[]")),
                "bt_count":     len(json.loads(b.bt_device_ids     or "[]")),
                "frigate_count": len(json.loads(b.frigate_event_ids or "[]")),
                "has_person":   b.has_person,
                "probe_ssids":  b.probe_ssid_fingerprint or "",
            })

        # Human-readable summary
        parts: list[str] = []
        if profile:
            model = profile.model or tpms_sensor_id
            parts.append(f"Vehicle ({model}) seen {profile.sighting_count}x")
        if cluster:
            bt_v = json.loads(cluster.associated_bt_vendors or "[]")
            if bt_v:
                parts.append(f"likely driver has {bt_v[0]} device")
            ssids = json.loads(cluster.representative_ssids or "[]")
            if ssids:
                shown = ", ".join(ssids[:3])
                more  = f" +{len(ssids)-3} more" if len(ssids) > 3 else ""
                parts.append(f"probes for [{shown}{more}]")
            if cluster.camera_appearances:
                cam = cluster.dominant_camera or "camera"
                parts.append(f"appeared on {cam} {cluster.camera_appearances}x")

        result["summary"] = "; ".join(parts) if parts else "No data"
        return result

    finally:
        session.close()


# ---------------------------------------------------------------------------
# Cross-vehicle same-person detection
# ---------------------------------------------------------------------------

def find_same_person_different_vehicle(min_ssid_overlap: int = 2) -> list[dict]:
    """Identify VehicleIdentityClusters likely driven by the same person.

    Vehicles whose representative SSID sets share ≥ min_ssid_overlap SSIDs
    may belong to the same driver (their phone probes for the same networks).

    Returns list of match dicts sorted by overlap_score descending.
    """
    session = get_session()
    try:
        clusters = (
            session.query(VehicleIdentityCluster)
            .filter(VehicleIdentityCluster.representative_ssids.isnot(None))
            .all()
        )

        profiles: list[tuple[str, frozenset[str]]] = []
        for c in clusters:
            ssids = frozenset(json.loads(c.representative_ssids or "[]"))
            if len(ssids) >= min_ssid_overlap:
                profiles.append((c.tpms_sensor_id, ssids))

        matches: list[dict] = []
        for i in range(len(profiles)):
            for j in range(i + 1, len(profiles)):
                sid_a, ssids_a = profiles[i]
                sid_b, ssids_b = profiles[j]
                overlap = ssids_a & ssids_b
                if len(overlap) >= min_ssid_overlap:
                    matches.append({
                        "vehicle_a":     sid_a,
                        "vehicle_b":     sid_b,
                        "overlap_ssids": sorted(overlap),
                        "overlap_score": len(overlap),
                        "ssids_a":       sorted(ssids_a),
                        "ssids_b":       sorted(ssids_b),
                    })

        matches.sort(key=lambda x: x["overlap_score"], reverse=True)
        return matches

    finally:
        session.close()


# ---------------------------------------------------------------------------
# Master entry point
# ---------------------------------------------------------------------------

def run_presence_analysis() -> dict:
    """Backfill bundles → cluster identities → log top vehicles → return stats."""
    logger.info("Starting presence analysis...")
    init_db()  # ensure new tables exist

    backfill = backfill_presence_bundles(days=6)
    cluster  = cluster_vehicle_identities()

    # Log summary of top 5 most-profiled vehicles
    session = get_session()
    try:
        top5 = (
            session.query(VehicleProfile)
            .order_by(VehicleProfile.sighting_count.desc())
            .limit(5)
            .all()
        )
        logger.info("Top 5 most-profiled vehicles:")
        for vp in top5:
            cl = (
                session.query(VehicleIdentityCluster)
                .filter(VehicleIdentityCluster.tpms_sensor_id == vp.sensor_id)
                .first()
            )
            ssids   = json.loads(cl.representative_ssids  or "[]") if cl else []
            bt_v    = json.loads(cl.associated_bt_vendors or "[]") if cl else []
            bundles = cl.bundle_count if cl else 0
            logger.info(
                "  %-40s  sightings=%4d  bundles=%3d  ssids=%s  bt=%s",
                vp.sensor_id, vp.sighting_count, bundles,
                ssids[:3], bt_v[:2],
            )
    finally:
        session.close()

    combined = {
        **backfill,
        **{f"cluster_{k}": v for k, v in cluster.items()},
    }
    logger.info("Presence analysis complete: %s", combined)
    return combined
