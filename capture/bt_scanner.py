#!/usr/bin/env python3
"""SENTINEL Bluetooth Scanner.

BLE advertisement scanning via bleak and classic BR/EDR discovery
via hcitool. Includes a bluetoothctl subprocess fallback that
catches BLE advertisements bleak/D-Bus misses (Flipper Zero,
certain IoT devices, non-standard advert formats).

Run standalone:  sudo python3 -m capture.bt_scanner
Run as service:  systemctl start sentinel-bt
"""

import asyncio
import json
import logging
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

# Ensure project root is on path
sys.path.insert(0, "/opt/sentinel")

import config
from database import (
    Device,
    Event,
    Visit,
    get_or_create_device,
    get_session,
    init_db,
)

logger = logging.getLogger("sentinel.bluetooth")


# ---------------------------------------------------------------------------
# MAC utilities (shared logic with wifi module)
# ---------------------------------------------------------------------------

def is_randomized_mac(mac: str) -> bool:
    """Detect locally-administered (randomized) MAC addresses."""
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def normalize_mac(mac: str) -> str:
    return mac.upper().strip().replace("-", ":")


# ---------------------------------------------------------------------------
# Device tracker
# ---------------------------------------------------------------------------

class DeviceTracker:
    """Tracks active Bluetooth devices and detects arrivals/departures."""

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
# Classic Bluetooth scanner (hcitool based)
# ---------------------------------------------------------------------------

class ClassicScanner:
    """BR/EDR Bluetooth discovery using hcitool."""

    def __init__(self, adapter: str = "hci0"):
        self.adapter = adapter

    def scan(self, duration: int = 10) -> list[dict]:
        """Run a classic BT inquiry scan.

        Returns list of dicts with keys: mac, name, class.
        """
        devices = []
        try:
            result = subprocess.run(
                ["hcitool", "-i", self.adapter, "scan", "--flush", f"--length={duration}"],
                capture_output=True,
                text=True,
                timeout=duration + 15,
            )
            # Parse hcitool scan output:
            # "	AA:BB:CC:DD:EE:FF	Device Name"
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("Scanning"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 2:
                    mac = normalize_mac(parts[0].strip())
                    name = parts[1].strip() if len(parts) > 1 else None
                    devices.append({"mac": mac, "name": name, "type": "bluetooth_classic"})

        except subprocess.TimeoutExpired:
            logger.warning("Classic BT scan timed out after %ds", duration + 15)
        except FileNotFoundError:
            logger.error("hcitool not found - install bluez-tools")
        except Exception as e:
            logger.error("Classic BT scan failed: %s", e)

        return devices


# ---------------------------------------------------------------------------
# bluetoothctl BLE fallback scanner
# ---------------------------------------------------------------------------

class BluetoothctlScanner:
    """BLE fallback scanner using bluetoothctl subprocess.

    Catches BLE advertisements that bleak/D-Bus discover() misses,
    including Flipper Zero, some IoT devices, and devices using
    non-standard advertisement formats.  Runs continuously in a
    background thread alongside the bleak scan cycles.
    """

    _ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    _NEW_RE = re.compile(
        r'\[NEW\]\s+Device\s+([0-9A-Fa-f:]{17})\s*(.*)')
    _CHG_RSSI_RE = re.compile(
        r'\[CHG\]\s+Device\s+([0-9A-Fa-f:]{17})\s+RSSI:\s+'
        r'(?:\S+\s+\((-?\d+)\)|(-?\d+))')
    _CHG_NAME_RE = re.compile(
        r'\[CHG\]\s+Device\s+([0-9A-Fa-f:]{17})\s+Name:\s*(.*)')

    # Flush pending devices to DB after this many seconds without RSSI
    _FLUSH_DELAY = 2.0

    def __init__(self, engine: "BluetoothScanEngine"):
        self._engine = engine
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # Buffer NEW devices briefly to capture the RSSI that follows
        # mac -> {"name": str|None, "rssi": int|None, "time": float}
        self._pending: dict[str, dict] = {}

    def start(self):
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="bluetoothctl-ble")
        self._thread.start()
        logger.info("bluetoothctl BLE fallback scanner started")

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("bluetoothctl BLE fallback scanner stopped")

    # -- main loop --

    def _run(self):
        """Main loop - (re)starts bluetoothctl scan on failure."""
        while not self._stop.is_set():
            try:
                self._scan_session()
            except Exception as e:
                logger.error("bluetoothctl session error: %s", e)
            if not self._stop.is_set():
                self._stop.wait(5)  # backoff before restart

    def _scan_session(self):
        """Run one continuous bluetoothctl LE scan session."""
        self._proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            time.sleep(0.3)
            # Configure LE-only scan with duplicate reporting so we
            # see RSSI updates for every advertisement frame.
            for cmd in ("menu scan\n", "transport le\n",
                        "duplicate-data on\n", "back\n", "scan on\n"):
                self._proc.stdin.write(cmd)
            self._proc.stdin.flush()

            while not self._stop.is_set():
                # Use select so we can check _stop periodically
                ready, _, _ = select.select(
                    [self._proc.stdout], [], [], 0.5)
                if ready:
                    line = self._proc.stdout.readline()
                    if not line:
                        break  # process exited
                    clean = self._ANSI_RE.sub('', line).strip()
                    if clean:
                        self._parse_line(clean)
                # Flush any pending devices whose RSSI never arrived
                self._flush_stale()

        finally:
            try:
                self._proc.stdin.write("scan off\n")
                self._proc.stdin.write("quit\n")
                self._proc.stdin.flush()
            except (OSError, BrokenPipeError):
                pass
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
            self._flush_all()

    # -- line parser --

    def _parse_line(self, line: str):
        # [NEW] Device AA:BB:CC:DD:EE:FF OptionalName
        m = self._NEW_RE.match(line)
        if m:
            mac = normalize_mac(m.group(1))
            if ":" not in mac or len(mac) != 17:
                return
            name = m.group(2).strip() or None
            # bluetoothctl echoes the MAC in dash form as name when
            # no real name is known -- discard that
            if name and re.fullmatch(r'[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}', name):
                name = None
            is_arrival = self._engine.tracker.touch(mac)
            if is_arrival:
                # Buffer briefly so the RSSI [CHG] line can fill in
                self._pending[mac] = {
                    "name": name, "rssi": None, "time": time.time()}
            return

        # [CHG] Device AA:BB:CC:DD:EE:FF RSSI: 0xffffffcb (-53)  or  RSSI: -53
        m = self._CHG_RSSI_RE.match(line)
        if m:
            mac = normalize_mac(m.group(1))
            if ":" not in mac or len(mac) != 17:
                return
            rssi = int(m.group(2) or m.group(3))
            self._engine.tracker.touch(mac)
            if mac in self._pending:
                # Pair with the buffered NEW entry and flush to DB
                info = self._pending.pop(mac)
                self._commit_device(mac, info["name"], rssi)
            return

        # [CHG] Device AA:BB:CC:DD:EE:FF Name: Flipper deadbeef
        m = self._CHG_NAME_RE.match(line)
        if m:
            mac = normalize_mac(m.group(1))
            if ":" not in mac or len(mac) != 17:
                return
            name = m.group(2).strip()
            self._engine.tracker.touch(mac)
            if mac in self._pending:
                self._pending[mac]["name"] = name
            else:
                # Name resolved after initial commit - update DB
                self._update_device_name(mac, name)
            return

    # -- DB helpers --

    def _commit_device(self, mac: str, name: str | None, rssi: int | None):
        """Write a newly-arrived BLE device from bluetoothctl to DB."""
        self._engine.stats["ble_devices_seen"] += 1
        randomized = is_randomized_mac(mac)
        self._engine._write_to_db(
            mac=mac,
            device_type="bluetooth_le",
            name=name if self._engine.resolve_names else None,
            rssi=rssi,
            randomized=randomized,
            is_arrival=True,
            metadata={"source": "bluetoothctl"},
        )
        label = name or ("randomized" if randomized else "unknown")
        logger.info("NEW BLE (btctl) %s [%s] rssi=%s", mac, label, rssi)

    def _update_device_name(self, mac: str, name: str):
        """Update hostname for a device whose name resolved late."""
        if not self._engine.resolve_names:
            return
        session = get_session()
        try:
            device = (
                session.query(Device)
                .filter(Device.mac == mac.upper())
                .first()
            )
            if device and not device.hostname:
                device.hostname = name
                session.commit()
                logger.debug("btctl name resolved: %s -> %s", mac, name)
        except Exception:
            session.rollback()
        finally:
            session.close()

    # -- flush helpers --

    def _flush_stale(self):
        """Flush pending entries older than _FLUSH_DELAY (RSSI never came)."""
        now = time.time()
        stale = [
            (mac, self._pending.pop(mac))
            for mac in list(self._pending)
            if now - self._pending[mac]["time"] > self._FLUSH_DELAY
        ]
        for mac, info in stale:
            self._commit_device(mac, info["name"], info["rssi"])

    def _flush_all(self):
        """Flush everything remaining (session ending)."""
        remaining = list(self._pending.items())
        self._pending.clear()
        for mac, info in remaining:
            self._commit_device(mac, info["name"], info["rssi"])


# ---------------------------------------------------------------------------
# BLE scanner engine
# ---------------------------------------------------------------------------

class BluetoothScanEngine:
    """Main Bluetooth scanning engine combining BLE and classic discovery."""

    def __init__(self):
        self.cfg = config.get_section("bluetooth")
        self.adapter = self.cfg.get("adapter", "hci0")
        self.scan_interval = self.cfg.get("scan_interval", 30)
        self.scan_duration = self.cfg.get("scan_duration", 10)
        self.do_classic = self.cfg.get("classic_scan", True)
        self.do_ble = self.cfg.get("ble_scan", True)
        self.resolve_names = self.cfg.get("resolve_names", True)
        self.tracker = DeviceTracker(timeout=self.cfg.get("device_timeout", 600))
        self._stop = asyncio.Event()
        self._shutdown = False

        # Stats
        self.stats = {
            "scans_completed": 0,
            "ble_devices_seen": 0,
            "classic_devices_seen": 0,
            "unique_devices": 0,
            "new_devices": 0,
            "departures": 0,
            "start_time": None,
        }

        self.classic_scanner = ClassicScanner(self.adapter) if self.do_classic else None
        self.btctl_scanner = BluetoothctlScanner(self) if self.do_ble else None

    async def start(self):
        """Run the scan loop."""
        logger.info("Bluetooth scan engine starting on %s", self.adapter)
        self.stats["start_time"] = time.time()

        # Start bluetoothctl continuous scanner alongside bleak cycles
        if self.btctl_scanner:
            self.btctl_scanner.start()

        while not self._shutdown:
            scan_start = time.time()

            # Run BLE and classic scans
            if self.do_ble:
                await self._ble_scan()
            if self.do_classic and self.classic_scanner:
                await self._classic_scan()

            self.stats["scans_completed"] += 1
            self.stats["unique_devices"] = self.tracker.count

            # Check departures
            self._flush_departures()

            # Log periodic stats
            if self.stats["scans_completed"] % 10 == 0:
                logger.info(
                    "BT scan stats: %d scans, %d BLE seen, %d classic seen, "
                    "%d active, %d new total, %d departures",
                    self.stats["scans_completed"],
                    self.stats["ble_devices_seen"],
                    self.stats["classic_devices_seen"],
                    self.tracker.count,
                    self.stats["new_devices"],
                    self.stats["departures"],
                )

            # Wait for next scan interval
            elapsed = time.time() - scan_start
            wait_time = max(0, self.scan_interval - elapsed)
            if wait_time > 0 and not self._shutdown:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=wait_time)
                except asyncio.TimeoutError:
                    pass
                if self._stop.is_set():
                    break

        logger.info(
            "Bluetooth scan stopped. Stats: %d scans, %d new devices, %d departures",
            self.stats["scans_completed"],
            self.stats["new_devices"],
            self.stats["departures"],
        )

    def stop(self):
        """Signal the engine to stop."""
        logger.info("Bluetooth scan engine stopping...")
        self._shutdown = True
        self._stop.set()
        if self.btctl_scanner:
            self.btctl_scanner.stop()
        self._flush_departures()

    async def _ble_scan(self):
        """Perform a BLE advertisement scan."""
        try:
            # bleak adapter string format: use adapter path
            adapter = self.adapter
            devices = await BleakScanner.discover(
                timeout=self.scan_duration,
                adapter=adapter,
            )

            for ble_device in devices:
                self._process_ble_device(ble_device)

        except Exception as e:
            logger.error("BLE scan failed: %s", e)

    def _process_ble_device(self, ble_device: BLEDevice):
        """Process a discovered BLE device."""
        mac = normalize_mac(ble_device.address)

        # Skip placeholder addresses (some BLE devices report as UUID)
        if ":" not in mac or len(mac) != 17:
            return

        self.stats["ble_devices_seen"] += 1
        name = ble_device.name if self.resolve_names else None
        randomized = is_randomized_mac(mac)

        # RSSI from device details
        rssi = getattr(ble_device, "rssi", None)

        # Track for arrival/departure
        is_arrival = self.tracker.touch(mac)

        # Build metadata
        metadata = {}
        if ble_device.details:
            try:
                # Extract manufacturer data, service UUIDs, etc.
                props = getattr(ble_device, "metadata", {})
                if props:
                    if "manufacturer_data" in props:
                        # Convert bytes keys to strings for JSON
                        metadata["manufacturer_data"] = {
                            str(k): v.hex() for k, v in props["manufacturer_data"].items()
                        }
                    if "uuids" in props:
                        metadata["service_uuids"] = list(props["uuids"])
            except Exception:
                pass

        self._write_to_db(
            mac=mac,
            device_type="bluetooth_le",
            name=name,
            rssi=rssi,
            randomized=randomized,
            is_arrival=is_arrival,
            metadata=metadata,
        )

        if is_arrival:
            tag = name or ("randomized" if randomized else "unknown")
            logger.info("NEW BLE  %s [%s] rssi=%s", mac, tag, rssi)

    async def _classic_scan(self):
        """Run classic Bluetooth discovery in a thread."""
        try:
            loop = asyncio.get_running_loop()
            devices = await loop.run_in_executor(
                None, self.classic_scanner.scan, self.scan_duration
            )

            for dev_info in devices:
                self.stats["classic_devices_seen"] += 1
                mac = dev_info["mac"]
                name = dev_info.get("name") if self.resolve_names else None
                is_arrival = self.tracker.touch(mac)

                self._write_to_db(
                    mac=mac,
                    device_type="bluetooth_classic",
                    name=name,
                    rssi=None,
                    randomized=is_randomized_mac(mac),
                    is_arrival=is_arrival,
                    metadata={},
                )

                if is_arrival:
                    logger.info("NEW BT CLASSIC  %s [%s]", mac, name or "unknown")

        except Exception as e:
            logger.error("Classic BT scan failed: %s", e)

    def _write_to_db(self, mac: str, device_type: str, name: str | None,
                     rssi: int | None, randomized: bool, is_arrival: bool,
                     metadata: dict):
        """Persist Bluetooth detection to database."""
        session = get_session()
        try:
            kwargs = {
                "device_type": device_type,
                "is_randomized": randomized,
            }
            if name:
                kwargs["hostname"] = name

            device, created = get_or_create_device(session, mac, **kwargs)

            if created:
                self.stats["new_devices"] += 1
                logger.info("New BT device added to DB: %s (%s)", mac, name or "unknown")

            # Record event
            event_type = "bt_ble" if device_type == "bluetooth_le" else "bt_classic"
            raw_data = json.dumps(metadata) if metadata else None

            event = Event(
                device_id=device.id,
                event_type=event_type,
                source=self.adapter,
                rssi=rssi,
                raw_data=raw_data,
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
                    source="bt_tracker",
                    rssi=rssi,
                )
                session.add(arrival_event)
            else:
                # Update current visit
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
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

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

                visit = (
                    session.query(Visit)
                    .filter(Visit.device_id == device.id, Visit.departed_at.is_(None))
                    .order_by(Visit.arrived_at.desc())
                    .first()
                )
                if visit:
                    visit.departed_at = now
                    visit.duration_seconds = int((now - visit.arrived_at).total_seconds())

                dep_event = Event(
                    device_id=device.id,
                    event_type="departure",
                    source="bt_tracker",
                )
                session.add(dep_event)

                tag = device.hostname or device.alias or device.mac
                logger.info(
                    "BT DEPARTED  %s [%s] (visit duration: %s)",
                    device.mac,
                    tag,
                    f"{visit.duration_seconds}s" if visit and visit.duration_seconds else "unknown",
                )

            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("BT departure flush failed: %s", e)
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = config.load()
    config.setup_logging()
    init_db()

    bt_cfg = cfg["bluetooth"]
    if not bt_cfg.get("enabled", True):
        logger.warning("Bluetooth scanning disabled in config, exiting")
        sys.exit(0)

    engine = BluetoothScanEngine()

    def shutdown(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, shutting down...", sig_name)
        engine.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("=" * 60)
    logger.info("SENTINEL Bluetooth Scanner")
    logger.info("Adapter: %s | BLE: %s | Classic: %s | Interval: %ds",
                bt_cfg.get("adapter", "hci0"),
                bt_cfg.get("ble_scan", True),
                bt_cfg.get("classic_scan", True),
                bt_cfg.get("scan_interval", 30))
    if bt_cfg.get("ble_scan", True):
        logger.info("bluetoothctl BLE fallback: enabled (continuous)")
    logger.info("=" * 60)

    asyncio.run(engine.start())


if __name__ == "__main__":
    main()
