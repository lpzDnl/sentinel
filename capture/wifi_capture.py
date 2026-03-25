#!/usr/bin/env python3
"""SENTINEL WiFi Probe Capture Engine.

Passive monitor-mode capture on wlan1mon using scapy.
Extracts probe requests, tracks device arrivals/departures,
resolves OUI vendors, detects randomized MACs, and logs
everything to the SQLite database.

Run standalone:  sudo python3 -m capture.wifi_capture
Run as service:  systemctl start sentinel-wifi
"""

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
    conf,
    sniff,
)

# Ensure project root is on path
sys.path.insert(0, "/opt/sentinel")

import config
from capture.drone_detect import is_drone, rssi_distance_estimate
from database import (
    ArrivalEvent,
    Device,
    DeviceHeartbeat,
    Event,
    ProbeRequest,
    SdrSignal,
    Tag,
    Visit,
    get_or_create_device,
    get_session,
    init_db,
)

logger = logging.getLogger("sentinel.wifi")

# ---------------------------------------------------------------------------
# OUI / MAC utilities
# ---------------------------------------------------------------------------

# Scapy's built-in manufacturer database
_manuf_db = conf.manufdb


def resolve_vendor(mac: str) -> str | None:
    """Resolve MAC to vendor name using scapy's OUI database."""
    try:
        result = _manuf_db.lookup(mac)
        if result and result[0]:
            # scapy returns (short_name, long_name) or similar
            return str(result[1] if len(result) > 1 and result[1] else result[0])
    except Exception:
        pass
    return None


def is_randomized_mac(mac: str) -> bool:
    """Detect locally-administered (randomized) MAC addresses.

    Bit 1 of the first octet is the U/L bit.
    If set (1), the address is locally administered (likely randomized).
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def normalize_mac(mac: str) -> str:
    """Normalize MAC to uppercase colon-separated format."""
    return mac.upper().strip()


# ---------------------------------------------------------------------------
# Channel hopper
# ---------------------------------------------------------------------------

class ChannelHopper:
    """Hops WiFi interface across channels in a background thread."""

    def __init__(self, interface: str, channels: list[int], interval: float):
        self.interface = interface
        self.channels = channels
        self.interval = interval
        self.current_channel = channels[0] if channels else 1
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._hop_loop, daemon=True, name="channel-hopper")
        self._thread.start()
        logger.info("Channel hopper started: channels=%s interval=%.1fs", self.channels, self.interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Channel hopper stopped")

    def _hop_loop(self):
        idx = 0
        while not self._stop.is_set():
            channel = self.channels[idx % len(self.channels)]
            try:
                subprocess.run(
                    ["iwconfig", self.interface, "channel", str(channel)],
                    capture_output=True,
                    timeout=2,
                )
                self.current_channel = channel
            except Exception as e:
                logger.debug("Channel hop to %d failed: %s", channel, e)
            idx += 1
            self._stop.wait(self.interval)


# ---------------------------------------------------------------------------
# Device tracker (arrivals / departures)
# ---------------------------------------------------------------------------

class DeviceTracker:
    """Tracks active devices and detects arrivals/departures."""

    def __init__(self, timeout: int):
        self.timeout = timeout
        self.active: dict[str, float] = {}  # mac -> last_seen timestamp
        self._lock = threading.Lock()

    def touch(self, mac: str) -> bool:
        """Update last-seen time. Returns True if this is a new arrival."""
        now = time.time()
        with self._lock:
            is_new = mac not in self.active
            self.active[mac] = now
            return is_new

    def get_departed(self) -> list[str]:
        """Return and remove MACs that have exceeded the timeout."""
        now = time.time()
        departed = []
        with self._lock:
            for mac, last_seen in list(self.active.items()):
                if now - last_seen > self.timeout:
                    departed.append(mac)
                    del self.active[mac]
        return departed

    @property
    def count(self) -> int:
        with self._lock:
            return len(self.active)


# ---------------------------------------------------------------------------
# Resident heartbeat monitor
# ---------------------------------------------------------------------------

class ResidentHeartbeatMonitor:
    """Monitors resident-tagged devices for presence heartbeats.

    Runs every 15 minutes. For each device tagged 'resident', checks
    last_seen against the expected interval. If missing for 2× the
    expected interval, marks offline and fires a Telegram alert.
    Sends a recovery alert when the device comes back online.
    """

    CHECK_INTERVAL = 15 * 60          # 15 minutes
    DEFAULT_INTERVAL_MINUTES = 60     # expected WiFi heartbeat window
    MISS_MULTIPLIER = 2               # 2× expected = offline threshold

    def __init__(self):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="heartbeat-monitor"
        )
        self._thread.start()
        logger.info("Resident heartbeat monitor started (check every 15m)")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Resident heartbeat monitor stopped")

    def _monitor_loop(self):
        # Small startup delay so wifi capture is fully running first
        self._stop.wait(60)
        while not self._stop.is_set():
            for attempt in range(3):
                try:
                    self._run_check()
                    break
                except Exception as e:
                    if "database is locked" in str(e).lower() and attempt < 2:
                        logger.warning(
                            "Heartbeat monitor: database locked, retrying in 5s (attempt %d/3)",
                            attempt + 1,
                        )
                        self._stop.wait(5)
                    else:
                        logger.error("Heartbeat monitor check failed: %s", e)
                        break
            self._stop.wait(self.CHECK_INTERVAL)

    def _run_check(self):
        from analysis.alerter import get_alerter  # lazy import avoids circular deps

        now = datetime.now(timezone.utc)
        session = get_session()
        try:
            resident_rows = (
                session.query(Device, Tag)
                .join(Tag, Device.id == Tag.device_id)
                .filter(Tag.category == "resident")
                .all()
            )

            if not resident_rows:
                return

            alerter = get_alerter()

            for device, tag in resident_rows:
                # Get or create heartbeat record
                hb = (
                    session.query(DeviceHeartbeat)
                    .filter(DeviceHeartbeat.device_id == device.id)
                    .first()
                )
                if not hb:
                    hb = DeviceHeartbeat(
                        device_id=device.id,
                        last_seen=device.last_seen,
                        expected_interval_minutes=self.DEFAULT_INTERVAL_MINUTES,
                        status="unknown",
                        consecutive_misses=0,
                    )
                    session.add(hb)
                    session.flush()

                # Normalize last_seen to UTC-aware
                device_last = device.last_seen
                if device_last and device_last.tzinfo is None:
                    device_last = device_last.replace(tzinfo=timezone.utc)

                prev_status = hb.status
                name = tag.label or device.alias or device.vendor or device.mac
                threshold_minutes = hb.expected_interval_minutes * self.MISS_MULTIPLIER

                if device_last:
                    minutes_missing = (now - device_last).total_seconds() / 60

                    if minutes_missing <= hb.expected_interval_minutes:
                        # Device is online
                        hb.last_seen = device_last
                        hb.status = "online"
                        hb.consecutive_misses = 0

                        if prev_status == "offline":
                            # Recovery: calculate how long it was offline
                            offline_since = hb.alerted_at
                            if offline_since and offline_since.tzinfo is None:
                                offline_since = offline_since.replace(tzinfo=timezone.utc)
                            offline_minutes = (
                                int((now - offline_since).total_seconds() / 60)
                                if offline_since else 0
                            )
                            msg = (
                                f"\u2705 <b>RESIDENT DEVICE BACK ONLINE</b>\n\n"
                                f"\U0001f4f1 <b>Device:</b> {name}\n"
                                f"\u23f1\ufe0f <b>Was offline for:</b> {offline_minutes} minutes"
                            )
                            alerter.send_raw_message(msg, alert_type="resident_online",
                                                     device=device)
                            logger.info("Resident device recovered: %s (%s)", device.mac, name)

                    elif minutes_missing > threshold_minutes:
                        # Device is offline
                        hb.status = "offline"
                        hb.consecutive_misses += 1

                        # Only alert on the transition to offline
                        if prev_status != "offline":
                            hb.alerted_at = now
                            last_seen_str = (
                                device_last.strftime("%Y-%m-%d %H:%M UTC")
                                if device_last else "unknown"
                            )
                            msg = (
                                f"\U0001f4f4 <b>RESIDENT DEVICE OFFLINE</b>\n\n"
                                f"\U0001f4f1 <b>Device:</b> {name}\n"
                                f"\U0001f552 <b>Last seen:</b> {last_seen_str}\n"
                                f"\u23f1\ufe0f <b>Missing for:</b> {int(minutes_missing)} minutes"
                            )
                            alerter.send_raw_message(msg, alert_type="resident_offline",
                                                     device=device)
                            logger.warning(
                                "Resident device offline: %s (%s) missing %dm",
                                device.mac, name, int(minutes_missing),
                            )
                else:
                    hb.status = "unknown"

            session.commit()
            logger.debug("Heartbeat check complete: %d resident devices", len(resident_rows))
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Capture engine
# ---------------------------------------------------------------------------

class WiFiCaptureEngine:
    """Main WiFi probe capture engine."""

    def __init__(self):
        self.cfg = config.get_section("wifi")
        self.interface = self.cfg["interface"]
        self.hopper: ChannelHopper | None = None
        self.tracker = DeviceTracker(timeout=self.cfg.get("device_timeout", 300))
        self._stop = threading.Event()
        self._departure_thread: threading.Thread | None = None
        self.heartbeat_monitor = ResidentHeartbeatMonitor()

        # Stats
        self.stats = {
            "packets_processed": 0,
            "probes_captured": 0,
            "unique_devices": 0,
            "new_devices": 0,
            "departures": 0,
            "start_time": None,
        }

    def start(self):
        """Start the capture engine."""
        logger.info("WiFi capture engine starting on %s", self.interface)
        self.stats["start_time"] = time.time()

        # Start channel hopper if enabled
        if self.cfg.get("channel_hop", True):
            channels = self.cfg.get("channels", list(range(1, 12)))
            interval = self.cfg.get("hop_interval", 0.5)
            self.hopper = ChannelHopper(self.interface, channels, interval)
            self.hopper.start()

        # Start departure checker
        self._departure_thread = threading.Thread(
            target=self._departure_loop, daemon=True, name="departure-checker"
        )
        self._departure_thread.start()

        # Start resident heartbeat monitor
        self.heartbeat_monitor.start()

        # Build BPF filter for probe requests
        # type 0 subtype 4 = probe request
        bpf_filter = "type mgt subtype probe-req"

        logger.info("Starting packet capture with BPF: %s", bpf_filter)

        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                filter=bpf_filter,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except PermissionError:
            logger.error("Permission denied - run as root or with CAP_NET_RAW")
            raise
        except OSError as e:
            logger.error("Interface error on %s: %s", self.interface, e)
            raise

    def stop(self):
        """Stop the capture engine gracefully."""
        logger.info("WiFi capture engine stopping...")
        self._stop.set()
        if self.hopper:
            self.hopper.stop()
        self.heartbeat_monitor.stop()
        self._flush_departures()
        logger.info(
            "WiFi capture stopped. Stats: %d packets, %d probes, %d devices, %d new, %d departures",
            self.stats["packets_processed"],
            self.stats["probes_captured"],
            self.stats["unique_devices"],
            self.stats["new_devices"],
            self.stats["departures"],
        )

    def _handle_packet(self, pkt):
        """Process a captured packet."""
        self.stats["packets_processed"] += 1

        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]

        # Probe request: source address is addr2
        if pkt.haslayer(Dot11ProbeReq):
            self._handle_probe(pkt, dot11)

    def _handle_probe(self, pkt, dot11):
        """Process a probe request frame."""
        src_mac = normalize_mac(dot11.addr2)

        # Skip broadcast/null MACs
        if not src_mac or src_mac == "FF:FF:FF:FF:FF:FF" or src_mac == "00:00:00:00:00:00":
            return

        self.stats["probes_captured"] += 1

        # Extract SSID from Dot11Elt
        ssid = None
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            if elt.ID == 0 and elt.info:  # SSID element
                try:
                    ssid = elt.info.decode("utf-8", errors="replace").strip()
                    if not ssid or ssid == "\x00" * len(ssid):
                        ssid = None  # broadcast probe
                except Exception:
                    ssid = None

        # Extract signal strength from RadioTap
        rssi = None
        if pkt.haslayer(RadioTap):
            try:
                rssi = int(pkt[RadioTap].dBm_AntSignal)
            except (AttributeError, TypeError):
                pass

        # Channel from hopper
        channel = self.hopper.current_channel if self.hopper else None

        # Resolve vendor
        randomized = is_randomized_mac(src_mac)
        vendor = resolve_vendor(src_mac) if not randomized else None

        # Track arrival
        is_arrival = self.tracker.touch(src_mac)

        if is_arrival:
            self.stats["unique_devices"] = self.tracker.count

        # Write to database
        try:
            self._write_to_db(
                mac=src_mac,
                ssid=ssid,
                rssi=rssi,
                channel=channel,
                vendor=vendor,
                randomized=randomized,
                is_arrival=is_arrival,
            )
        except Exception as e:
            logger.error("DB write failed for %s: %s", src_mac, e)

        # Log notable events
        if is_arrival:
            tag = "randomized" if randomized else (vendor or "unknown")
            if ssid:
                logger.info("NEW DEVICE  %s [%s] probing '%s' rssi=%s ch=%s", src_mac, tag, ssid, rssi, channel)
            else:
                logger.info("NEW DEVICE  %s [%s] broadcast probe rssi=%s ch=%s", src_mac, tag, rssi, channel)
        elif logger.isEnabledFor(logging.DEBUG):
            logger.debug("PROBE  %s -> '%s' rssi=%s ch=%s", src_mac, ssid or "broadcast", rssi, channel)

    def _write_to_db(self, mac: str, ssid: str | None, rssi: int | None,
                     channel: int | None, vendor: str | None,
                     randomized: bool, is_arrival: bool):
        """Persist probe data to database."""
        session = get_session()
        try:
            device, created = get_or_create_device(
                session,
                mac,
                device_type="wifi",
                vendor=vendor,
                is_randomized=randomized,
            )

            if created:
                self.stats["new_devices"] += 1
                logger.info("New device added to DB: %s (%s)", mac, vendor or "unknown vendor")

            # Record probe request
            probe = ProbeRequest(
                device_id=device.id,
                ssid=ssid,
                rssi=rssi,
                channel=channel,
            )
            session.add(probe)

            # Record event
            event = Event(
                device_id=device.id,
                event_type="wifi_probe",
                source=self.interface,
                ssid=ssid,
                rssi=rssi,
                channel=channel,
            )
            session.add(event)

            # Start visit on arrival
            if is_arrival:
                visit = Visit(
                    device_id=device.id,
                    arrived_at=datetime.now(timezone.utc),
                    max_rssi=rssi,
                    event_count=1,
                )
                session.add(visit)

                arrival_event = Event(
                    device_id=device.id,
                    event_type="arrival",
                    source="wifi_tracker",
                    rssi=rssi,
                )
                session.add(arrival_event)

                # Cross-sensor correlation: look for a recent TPMS signal
                self._correlate_tpms(session, device, rssi)
            else:
                # Update current visit event count and max RSSI
                current_visit = (
                    session.query(Visit)
                    .filter(Visit.device_id == device.id, Visit.departed_at.is_(None))
                    .order_by(Visit.arrived_at.desc())
                    .first()
                )
                if current_visit:
                    current_visit.event_count = (current_visit.event_count or 0) + 1
                    if rssi and (current_visit.max_rssi is None or rssi > current_visit.max_rssi):
                        current_visit.max_rssi = rssi

            session.commit()

            # Drone detection: runs after the main commit so failures here
            # never roll back probe/visit data.
            if is_arrival or ssid:
                try:
                    self._check_drone(session, device, mac, ssid, rssi, is_arrival)
                except Exception as e:
                    logger.error("Drone check failed for %s: %s", mac, e)

        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _check_drone(self, session, device, mac: str, ssid: str | None,
                     rssi: int | None, is_arrival: bool):
        """Detect drone via MAC OUI or FAA Remote ID SSID; tag and alert if found."""
        from zoneinfo import ZoneInfo
        from analysis.alerter import get_alerter

        ssids = [ssid] if ssid else []
        detected, vendor, faa_ssid = is_drone(mac, ssids)
        if not detected:
            return

        # Only tag/alert once per device (skip if already tagged drone)
        existing_tag = session.query(Tag).filter(Tag.device_id == device.id).first()
        if existing_tag and existing_tag.category == "drone":
            return

        # Apply drone tag
        if existing_tag:
            existing_tag.category = "drone"
            existing_tag.flagged = True
            existing_tag.label = vendor or "Unknown Drone"
            existing_tag.tagged_by = "auto"
        else:
            tag = Tag(
                device_id=device.id,
                category="drone",
                flagged=True,
                label=vendor or "Unknown Drone",
                tagged_by="auto",
            )
            session.add(tag)
        session.commit()

        # Build and send Telegram alert
        tz_name = config.get().get("general", {}).get("timezone", "UTC")
        try:
            now_local = datetime.now(ZoneInfo(tz_name))
        except Exception:
            now_local = datetime.now()
        time_str = now_local.strftime("%H:%M")
        dist_str = rssi_distance_estimate(rssi)
        rssi_str = f"{rssi} dBm" if rssi is not None else "unknown"

        lines = [
            "\U0001f681 <b>DRONE DETECTED</b>",
            "",
            f"\U0001f3ed <b>Vendor:</b> {vendor or 'Unknown'}",
            f"\U0001f4cd <b>MAC:</b> <code>{mac}</code>",
            f"\U0001f4e1 <b>Signal strength:</b> {rssi_str} \u2014 {dist_str}",
            f"\U0001f552 <b>Time:</b> {time_str}",
        ]
        if faa_ssid:
            lines.append(f"\u26a0\ufe0f <b>FAA Remote ID:</b> {faa_ssid}")

        msg = "\n".join(lines)
        logger.warning("DRONE DETECTED  %s vendor=%s faa=%s rssi=%s", mac, vendor, faa_ssid, rssi)
        get_alerter().send_raw_message(msg, alert_type="drone_detected", device=device)

    def _correlate_tpms(self, session, device, wifi_rssi):
        """Check for a recent TPMS signal and create an ArrivalEvent if found.

        Queries sdr_signals for any TPMS signal in the last 2 minutes.
        Picks the most recent hit. Confidence is 'high' if TPMS RSSI > -70,
        'medium' otherwise. Writes an ArrivalEvent row (within the same session).
        """
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=2)
        tpms_hit = (
            session.query(SdrSignal)
            .filter(
                SdrSignal.signal_class == "tpms",
                SdrSignal.timestamp >= cutoff,
            )
            .order_by(SdrSignal.timestamp.desc())
            .first()
        )
        if tpms_hit is None:
            return

        confidence = "high" if (tpms_hit.rssi is not None and tpms_hit.rssi > -70) else "medium"
        notes = (
            f"WiFi rssi={wifi_rssi} dBm; "
            f"TPMS rssi={tpms_hit.rssi} dBm; "
            f"correlation window=2m"
        )
        arrival = ArrivalEvent(
            wifi_device_id=device.id,
            tpms_sensor_id=tpms_hit.device_uid,
            tpms_model=tpms_hit.model,
            tpms_rssi=tpms_hit.rssi,
            confidence=confidence,
            notes=notes,
        )
        session.add(arrival)
        logger.info(
            "CORRELATED ARRIVAL  wifi=%s tpms=%s model=%s rssi=%.1f conf=%s",
            device.mac,
            tpms_hit.device_uid,
            tpms_hit.model or "?",
            tpms_hit.rssi or 0,
            confidence,
        )

    def _departure_loop(self):
        """Periodically check for departed devices."""
        while not self._stop.is_set():
            self._flush_departures()
            self._stop.wait(30)  # check every 30 seconds

    def _flush_departures(self):
        """Close out visits for departed devices."""
        departed = self.tracker.get_departed()
        if not departed:
            return

        now = datetime.now(timezone.utc)
        session = get_session()
        try:
            for mac in departed:
                self.stats["departures"] += 1
                device = session.query(Device).filter(Device.mac == mac).first()
                if not device:
                    continue

                # Close open visit
                visit = (
                    session.query(Visit)
                    .filter(Visit.device_id == device.id, Visit.departed_at.is_(None))
                    .order_by(Visit.arrived_at.desc())
                    .first()
                )
                if visit:
                    visit.departed_at = now
                    arrived = visit.arrived_at
                    if arrived.tzinfo is None:
                        arrived = arrived.replace(tzinfo=timezone.utc)
                    visit.duration_seconds = int((now - arrived).total_seconds())

                # Log departure event
                dep_event = Event(
                    device_id=device.id,
                    event_type="departure",
                    source="wifi_tracker",
                )
                session.add(dep_event)

                tag = device.vendor or device.mac
                logger.info(
                    "DEPARTED  %s [%s] (visit duration: %s)",
                    device.mac,
                    tag,
                    f"{visit.duration_seconds}s" if visit and visit.duration_seconds else "unknown",
                )

            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("Departure flush failed: %s", e)
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = config.load()
    config.setup_logging()
    init_db()

    wifi_cfg = cfg["wifi"]
    if not wifi_cfg.get("enabled", True):
        logger.warning("WiFi capture disabled in config, exiting")
        sys.exit(0)

    engine = WiFiCaptureEngine()

    def shutdown(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, shutting down...", sig_name)
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("=" * 60)
    logger.info("SENTINEL WiFi Capture Engine")
    logger.info("Interface: %s | Channel hop: %s | Timeout: %ds",
                wifi_cfg["interface"],
                wifi_cfg.get("channel_hop", True),
                wifi_cfg.get("device_timeout", 300))
    logger.info("=" * 60)

    engine.start()


if __name__ == "__main__":
    main()
