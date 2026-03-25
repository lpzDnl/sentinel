#!/usr/bin/env python3
"""SENTINEL OpenDroneID Beacon Capture.

Sniffs WiFi beacon frames on wlan1mon and parses OpenDroneID (ASTM F3411)
messages from vendor-specific Information Elements (IE tag 221).

Supported OUIs:
  FA:0B:BC  — ASTM F3411 standard OpenDroneID
  26:37:12  — DJI proprietary Remote ID (pre-standardization)

Supported message types:
  0x0 — Basic ID   (drone serial number / UA type)
  0x1 — Location   (drone GPS: lat/lon/altitude/speed/heading)
  0x4 — System     (operator/pilot GPS position)

State is accumulated per drone MAC and flushed to DB on each Location message.
A Telegram alert is fired on first GPS fix and every ALERT_COOLDOWN seconds.

Run standalone:  python3 -m capture.droneid_capture
Run as service:  systemctl start sentinel-droneid
"""

import json
import logging
import signal
import struct
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
    sniff,
)

sys.path.insert(0, "/opt/sentinel")

import config
from database import DroneIdEvent, get_session, init_db

logger = logging.getLogger("sentinel.droneid")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ODID_OUI = b"\xfa\x0b\xbc"   # ASTM F3411 standard
DJI_OUI  = b"\x26\x37\x12"   # DJI legacy Remote ID

ODID_OUIS = (ODID_OUI, DJI_OUI)

MSG_BASIC_ID  = 0x0
MSG_LOCATION  = 0x1
MSG_AUTH      = 0x2
MSG_SELFID    = 0x3
MSG_SYSTEM    = 0x4
MSG_OPERATOR  = 0x5
MSG_PACKED    = 0xF

MESSAGE_SIZE = 25          # bytes per ODID message
VENDOR_IE_TAG = 221        # 0xDD

# Cooldown between Telegram alerts per drone MAC (seconds)
ALERT_COOLDOWN = 300

# ---------------------------------------------------------------------------
# ODID message parsers
# ---------------------------------------------------------------------------

def _parse_basic_id(data: bytes) -> dict:
    """Parse Basic ID message (type 0x0).

    Returns dict with: id_type, ua_type, serial_number
    """
    if len(data) < MESSAGE_SIZE:
        return {}
    # Byte 0: (msg_type << 4) | proto_ver  — already stripped by caller
    # Byte 1: (id_type << 4) | ua_type
    id_ua = data[1]
    id_type = (id_ua >> 4) & 0xF
    ua_type = id_ua & 0xF
    # Bytes 2-21: UAS ID (20 bytes, null-terminated ASCII)
    uas_id_raw = data[2:22]
    try:
        serial = uas_id_raw.rstrip(b"\x00").decode("ascii", errors="replace").strip()
    except Exception:
        serial = uas_id_raw.hex()
    return {
        "id_type": id_type,
        "ua_type": ua_type,
        "serial_number": serial or None,
    }


def _parse_location(data: bytes) -> dict:
    """Parse Location/Vector message (type 0x1).

    Returns dict with: drone_lat, drone_lon, drone_alt_meters,
                       speed_ms, heading, vertical_speed_ms
    """
    if len(data) < MESSAGE_SIZE:
        return {}

    status_flags = data[1]

    # Heading: byte 2 encodes 0-179 degrees; E/W segment is LSB of status_flags
    heading_half = data[2]           # 0-179
    ew_segment   = status_flags & 0x01  # 0 = N/E (0-179°), 1 = S/W (180-359°)
    heading = float(heading_half * 2 + ew_segment)   # 0-359 degrees

    # Horizontal speed: byte 3
    # Bit 7 = speed multiplier; bits 6:0 = speed value
    speed_raw  = data[3]
    multiplier = (speed_raw >> 7) & 1
    speed_val  = speed_raw & 0x7F
    if multiplier:
        speed_ms = speed_val * 0.75 + 255 * 0.25
    else:
        speed_ms = speed_val * 0.25

    # Vertical speed: byte 4, signed, 0.5 m/s per unit, offset from -62 m/s
    vert_raw = data[4]
    vert_speed_ms = (vert_raw - 124) * 0.5   # range ≈ -62 to +62 m/s

    # Latitude / Longitude: bytes 5-8, 9-12 (int32 LE, 1e-7 degrees)
    if len(data) >= 13:
        lat_raw, lon_raw = struct.unpack_from("<ii", data, 5)
        lat = lat_raw / 1e7
        lon = lon_raw / 1e7
    else:
        lat = lon = None

    # Geodetic altitude: bytes 15-16 (uint16 LE, 0.5 m/unit, -1000 m offset)
    if len(data) >= 17:
        geo_alt_raw = struct.unpack_from("<H", data, 15)[0]
        alt_m = geo_alt_raw * 0.5 - 1000.0
    else:
        alt_m = None

    # Sanity check: invalid GPS is encoded as 0 (which decodes to lat=0, lon=0)
    if lat == 0.0 and lon == 0.0:
        lat = lon = None
    if alt_m is not None and alt_m <= -999.5:
        alt_m = None

    return {
        "drone_lat": lat,
        "drone_lon": lon,
        "drone_alt_meters": alt_m,
        "speed_ms": round(speed_ms, 2),
        "heading": round(heading, 1),
        "vertical_speed_ms": round(vert_speed_ms, 2),
    }


def _parse_system(data: bytes) -> dict:
    """Parse System message (type 0x4).

    Returns dict with: pilot_lat, pilot_lon, pilot_alt_meters,
                       unix_timestamp
    """
    if len(data) < MESSAGE_SIZE:
        return {}

    # Operator latitude/longitude: bytes 2-5, 6-9 (int32 LE, 1e-7 degrees)
    if len(data) >= 10:
        op_lat_raw, op_lon_raw = struct.unpack_from("<ii", data, 2)
        pilot_lat = op_lat_raw / 1e7
        pilot_lon = op_lon_raw / 1e7
    else:
        pilot_lat = pilot_lon = None

    # Operator altitude: bytes 18-19 (uint16 LE, 0.5 m/unit, -1000 m offset)
    if len(data) >= 20:
        op_alt_raw = struct.unpack_from("<H", data, 18)[0]
        pilot_alt = op_alt_raw * 0.5 - 1000.0
    else:
        pilot_alt = None

    # Unix timestamp: bytes 20-23 (uint32 LE)
    if len(data) >= 24:
        unix_ts = struct.unpack_from("<I", data, 20)[0]
    else:
        unix_ts = None

    if pilot_lat == 0.0 and pilot_lon == 0.0:
        pilot_lat = pilot_lon = None
    if pilot_alt is not None and pilot_alt <= -999.5:
        pilot_alt = None

    return {
        "pilot_lat": pilot_lat,
        "pilot_lon": pilot_lon,
        "pilot_alt_meters": pilot_alt,
        "unix_timestamp": unix_ts,
    }


def parse_odid_messages(payload: bytes) -> list[dict]:
    """Parse a sequence of ODID messages from a vendor-specific IE payload.

    The payload starts after OUI (3 bytes) + subtype (1 byte).
    Messages can be packed (preceded by a count byte) or unpacked (raw sequence).

    Returns list of parsed message dicts with a 'msg_type' key.
    """
    results = []
    if len(payload) < 1:
        return results

    # Some implementations prefix with a message count byte
    # Detect: if first byte looks like a count (1-9) and remaining bytes are
    # a multiple of MESSAGE_SIZE, treat as packed.
    offset = 0
    if payload[0] in range(1, 10) and len(payload) - 1 == payload[0] * MESSAGE_SIZE:
        count = payload[0]
        offset = 1
    else:
        count = len(payload) // MESSAGE_SIZE

    for i in range(count):
        msg_start = offset + i * MESSAGE_SIZE
        if msg_start + MESSAGE_SIZE > len(payload):
            break
        msg = payload[msg_start: msg_start + MESSAGE_SIZE]
        msg_type = (msg[0] >> 4) & 0xF

        if msg_type == MSG_BASIC_ID:
            parsed = _parse_basic_id(msg)
        elif msg_type == MSG_LOCATION:
            parsed = _parse_location(msg)
        elif msg_type == MSG_SYSTEM:
            parsed = _parse_system(msg)
        else:
            continue

        if parsed:
            parsed["msg_type"] = msg_type
            results.append(parsed)

    return results


# ---------------------------------------------------------------------------
# Drone state accumulator (per MAC)
# ---------------------------------------------------------------------------

class DroneState:
    """Accumulated OpenDroneID state for a single drone MAC."""

    __slots__ = (
        "mac", "serial_number", "drone_lat", "drone_lon",
        "drone_alt_meters", "pilot_lat", "pilot_lon",
        "speed_ms", "heading", "last_rssi", "raw_parts",
        "last_alerted",
    )

    def __init__(self, mac: str):
        self.mac = mac
        self.serial_number: str | None = None
        self.drone_lat: float | None = None
        self.drone_lon: float | None = None
        self.drone_alt_meters: float | None = None
        self.pilot_lat: float | None = None
        self.pilot_lon: float | None = None
        self.speed_ms: float | None = None
        self.heading: float | None = None
        self.last_rssi: int | None = None
        self.raw_parts: dict = {}
        self.last_alerted: float = 0.0

    def update(self, messages: list[dict], rssi: int | None):
        if rssi is not None:
            self.last_rssi = rssi
        for m in messages:
            t = m.get("msg_type")
            if t == MSG_BASIC_ID:
                if m.get("serial_number"):
                    self.serial_number = m["serial_number"]
                self.raw_parts["basic_id"] = m
            elif t == MSG_LOCATION:
                if m.get("drone_lat") is not None:
                    self.drone_lat = m["drone_lat"]
                    self.drone_lon = m["drone_lon"]
                if m.get("drone_alt_meters") is not None:
                    self.drone_alt_meters = m["drone_alt_meters"]
                if m.get("speed_ms") is not None:
                    self.speed_ms = m["speed_ms"]
                if m.get("heading") is not None:
                    self.heading = m["heading"]
                self.raw_parts["location"] = m
            elif t == MSG_SYSTEM:
                if m.get("pilot_lat") is not None:
                    self.pilot_lat = m["pilot_lat"]
                    self.pilot_lon = m["pilot_lon"]
                self.raw_parts["system"] = m

    @property
    def has_gps(self) -> bool:
        return self.drone_lat is not None and self.drone_lon is not None


# ---------------------------------------------------------------------------
# DroneID capture engine
# ---------------------------------------------------------------------------

class DroneIdEngine:
    """Sniffs WiFi beacons and extracts OpenDroneID messages."""

    def __init__(self, interface: str = "wlan1mon"):
        self.interface = interface
        self._running = False
        self._states: dict[str, DroneState] = defaultdict(lambda: DroneState(""))
        self._lock = threading.Lock()

    # -- packet handler --

    def _extract_rssi(self, pkt) -> int | None:
        try:
            return -(256 - pkt[RadioTap].dBm_AntSignal)
        except Exception:
            try:
                return pkt[RadioTap].dBm_AntSignal
            except Exception:
                return None

    def _handle_packet(self, pkt):
        try:
            if not pkt.haslayer(Dot11Beacon):
                return
            if not pkt.haslayer(Dot11):
                return

            mac = pkt[Dot11].addr2
            if not mac:
                return
            mac = mac.upper()

            rssi = self._extract_rssi(pkt)

            # Walk information elements
            messages = []
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == VENDOR_IE_TAG:
                    info = bytes(elt.info) if elt.info else b""
                    if len(info) >= 4:
                        oui = info[:3]
                        if oui in ODID_OUIS:
                            # Payload starts after OUI (3) + subtype byte (1)
                            payload = info[4:]
                            parsed = parse_odid_messages(payload)
                            messages.extend(parsed)
                try:
                    elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
                except Exception:
                    break

            if not messages:
                return

            with self._lock:
                state = self._states.get(mac)
                if state is None:
                    state = DroneState(mac)
                    self._states[mac] = state
                state.update(messages, rssi)
                has_loc = any(m.get("msg_type") == MSG_LOCATION for m in messages)

            if has_loc:
                self._persist_and_alert(mac)

        except Exception as e:
            logger.debug("Packet handler error: %s", e)

    # -- persistence and alerting --

    def _persist_and_alert(self, mac: str):
        with self._lock:
            state = self._states.get(mac)
            if state is None:
                return
            # Snapshot current state
            snapshot = {
                "serial_number": state.serial_number,
                "drone_lat": state.drone_lat,
                "drone_lon": state.drone_lon,
                "drone_alt_meters": state.drone_alt_meters,
                "pilot_lat": state.pilot_lat,
                "pilot_lon": state.pilot_lon,
                "speed_ms": state.speed_ms,
                "heading": state.heading,
                "rssi": state.last_rssi,
                "raw_parts": dict(state.raw_parts),
                "should_alert": (time.time() - state.last_alerted) > ALERT_COOLDOWN,
            }
            if snapshot["should_alert"] and state.has_gps:
                state.last_alerted = time.time()

        session = get_session()
        try:
            evt = DroneIdEvent(
                mac=mac,
                serial_number=snapshot["serial_number"],
                drone_lat=snapshot["drone_lat"],
                drone_lon=snapshot["drone_lon"],
                drone_alt_meters=snapshot["drone_alt_meters"],
                pilot_lat=snapshot["pilot_lat"],
                pilot_lon=snapshot["pilot_lon"],
                speed_ms=snapshot["speed_ms"],
                heading=snapshot["heading"],
                rssi=snapshot["rssi"],
                raw_data=json.dumps(snapshot["raw_parts"]),
            )
            session.add(evt)
            session.commit()
            logger.info(
                "DroneID recorded mac=%s serial=%s lat=%s lon=%s alt=%s",
                mac,
                snapshot["serial_number"] or "?",
                snapshot["drone_lat"],
                snapshot["drone_lon"],
                snapshot["drone_alt_meters"],
            )
        except Exception as e:
            session.rollback()
            logger.error("DB write error for %s: %s", mac, e)
        finally:
            session.close()

        if snapshot["should_alert"] and snapshot["drone_lat"] is not None:
            self._send_alert(mac, snapshot)

    def _send_alert(self, mac: str, snap: dict):
        try:
            from analysis.alerter import get_alerter

            serial  = snap["serial_number"] or "UNKNOWN"
            d_lat   = snap["drone_lat"]
            d_lon   = snap["drone_lon"]
            d_alt   = snap["drone_alt_meters"]
            p_lat   = snap["pilot_lat"]
            p_lon   = snap["pilot_lon"]
            speed   = snap["speed_ms"]
            heading = snap["heading"]
            rssi    = snap["rssi"]

            lines = ["\U0001f681 <b>DRONE REMOTE ID DETECTED</b>", ""]
            lines.append(f"\U0001f522 <b>Serial:</b> <code>{serial}</code>")

            if d_lat is not None:
                lines.append(
                    f"\U0001f6f8 <b>Drone position:</b> {d_lat:.6f}, {d_lon:.6f}"
                    + (f" @ {d_alt:.0f}m" if d_alt is not None else "")
                )
            if p_lat is not None:
                lines.append(
                    f"\U0001f9d1\u200d\u2708\ufe0f <b>Pilot position:</b> "
                    f"{p_lat:.6f}, {p_lon:.6f}"
                )

            if speed is not None and heading is not None:
                lines.append(
                    f"\U0001f4a8 <b>Speed:</b> {speed:.1f} m/s "
                    f"| <b>Heading:</b> {heading:.0f}\u00b0"
                )

            lines.append(f"\U0001f4cd <b>MAC:</b> <code>{mac}</code>")
            if rssi is not None:
                lines.append(f"\U0001f4e1 <b>RSSI:</b> {rssi} dBm")

            msg = "\n".join(lines)
            get_alerter().send_raw_message(msg, alert_type="drone_remote_id")
        except Exception as e:
            logger.error("Alert send error: %s", e)

    # -- main loop --

    def run(self):
        self._running = True
        logger.info("DroneID capture starting on %s", self.interface)

        def stop_filter(_pkt):
            return not self._running

        try:
            sniff(
                iface=self.interface,
                filter="type mgt subtype beacon",
                prn=self._handle_packet,
                store=False,
                stop_filter=stop_filter,
            )
        except Exception as e:
            logger.error("Sniff error: %s", e)

    def stop(self):
        self._running = False
        logger.info("DroneID capture stopping")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = config.load()
    config.setup_logging()
    init_db()

    interface = cfg.get("wifi", {}).get("interface", "wlan1mon")
    engine = DroneIdEngine(interface=interface)

    def shutdown(signum, _frame):
        logger.info("Signal %s received, shutting down", signal.Signals(signum).name)
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("=" * 60)
    logger.info("SENTINEL DroneID Capture")
    logger.info("Interface: %s", interface)
    logger.info("=" * 60)

    engine.run()


if __name__ == "__main__":
    main()
