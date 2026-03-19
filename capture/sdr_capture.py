#!/usr/bin/env python3
"""SENTINEL SDR Signal Capture.

Uses rtl_433 as a subprocess with JSON output to capture and decode
ISM-band (315/433 MHz) RF transmissions:

  - TPMS (tire-pressure) sensors from passing vehicles
  - Outdoor weather stations, temp/humidity probes
  - Car key fobs and garage door remotes (rolling/fixed code)
  - Security sensors: PIR, door/window contacts
  - Power and energy monitors
  - Any other device rtl_433 can decode

One rtl_433 instance runs continuously.  A second thread drains its
stderr so stdout never blocks.  Each JSON line is parsed, classified,
and written to the sdr_signals table.  The engine auto-restarts rtl_433
on unexpected exit (e.g. USB reset).

Run standalone:  sudo python3 -m capture.sdr_capture
Run as service:  systemctl start sentinel-sdr
"""

import json
import logging
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, "/opt/sentinel")

import config
from database import SdrSignal, get_session, init_db

logger = logging.getLogger("sentinel.sdr")

# ---------------------------------------------------------------------------
# Signal classification
# ---------------------------------------------------------------------------

# Ordered list of (compiled regex, class string).  First match wins.
_CLASS_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(
        r"TPMS|Tire|Tyre|Schrader|Steelmate|Citroen|Kia.*TPMS|BMW.*TPMS|"
        r"Nissan.*TPMS|Audi.*TPMS|GM.*TPMS|EezTire|Carchet|TST-507|"
        r"TyreGuard|TireGuard|GM.Aftermarket",
        re.IGNORECASE,
    ), "tpms"),

    (re.compile(
        r"Key|Remote|Keyless|KeeLoq|Honda.*Key|Doorbell|LightwaveRF|"
        r"KlikAanKlik|Intertechno|Proove|Nexa|X10|Radiohead|HCS[23]\d\d|"
        r"Cardin|Silvercrest|Quhwa|Blyss|Clicker|Brennenstuhl|Elro|"
        r"Globaltronics|Generic.*Remote|SC226",
        re.IGNORECASE,
    ), "keyfob"),

    (re.compile(
        r"PIR|Door|Window|Contact|Security|Motion|Chuango|DSC|Risco|"
        r"Kerui|Watchman|Chamberlain|2Gig|RE208",
        re.IGNORECASE,
    ), "security"),

    (re.compile(
        r"Energy|Power|Current|Voltage|Meter|Monitor|EC3K|Efergy|"
        r"CurrentCost|GEO.*minim|emonTx|Revolt|Voltcraft|Gridstream",
        re.IGNORECASE,
    ), "power"),

    (re.compile(
        r"Weather|Temp|Temperature|Humid|Rain|Wind|Baro|Station|"
        r"Thermo|Hygro|Meteo|Soil|Pool|BBQ|Grill|Meat|Freezer|Fridge|"
        r"Tank|Oil|Sensor|LaCrosse|Acurite|Oregon|Nexus|Fine.Offset|"
        r"Ambient|Bresser|Calibeur|Rubicson|TFA|WH\d|WS\d|WN\d",
        re.IGNORECASE,
    ), "weather"),
]


def classify_model(model: str) -> str:
    """Return a signal class label for a decoded rtl_433 model string."""
    for pattern, cls in _CLASS_RULES:
        if pattern.search(model):
            return cls
    return "other"


def make_device_uid(model: str, decoded: dict) -> str:
    """Build a stable, unique identifier for a physical sensor.

    rtl_433 uses 'id' for most protocols; some also expose 'channel'.
    A few use 'device', 'address', or 'unit' as the primary identifier.
    """
    dev_id = (
        decoded.get("id")
        or decoded.get("device")
        or decoded.get("address")
        or decoded.get("unit")
        or "?"
    )
    ch = decoded.get("channel")
    if ch is not None:
        return f"{model}/{dev_id}/ch{ch}"
    return f"{model}/{dev_id}"


# ---------------------------------------------------------------------------
# Capture engine
# ---------------------------------------------------------------------------

class SdrCaptureEngine:
    """Manages the rtl_433 subprocess and writes decoded signals to DB."""

    # How often (in decoded signals) to emit a stats log line
    _STATS_INTERVAL = 100

    def __init__(self):
        self.cfg = config.get_section("sdr")

        self.device_index  = self.cfg.get("device_index", 0)
        self.gain          = str(self.cfg.get("gain", "auto"))
        self.ppm           = int(self.cfg.get("ppm_error", 0))
        self.frequencies   = self.cfg.get("frequencies") or [433920000]
        self.hop_interval  = int(self.cfg.get("hop_interval", 60))
        self.protocols     = self.cfg.get("protocols") or []
        self.rtl433_path   = self.cfg.get("rtl433_path", "rtl_433")
        self.extra_args    = self.cfg.get("rtl433_extra_args") or []

        self._stop = threading.Event()
        self._proc: subprocess.Popen | None = None

        self.stats = {
            "signals_decoded":  0,
            "signals_tpms":     0,
            "signals_weather":  0,
            "signals_keyfob":   0,
            "signals_security": 0,
            "signals_power":    0,
            "signals_other":    0,
            "db_writes":        0,
            "db_errors":        0,
            "unique_devices":   0,
            "start_time":       None,
        }
        self._seen_uids: set[str] = set()

    # -- public API --

    def start(self):
        """Run the capture loop, restarting rtl_433 on unexpected exit."""
        logger.info(
            "SDR capture engine starting — device=%s  freqs=%s  gain=%s  ppm=%d",
            self.device_index,
            [f"{f/1e6:.3f}MHz" for f in self.frequencies],
            self.gain,
            self.ppm,
        )
        self.stats["start_time"] = time.time()

        while not self._stop.is_set():
            try:
                self._run_session()
            except FileNotFoundError:
                logger.error(
                    "rtl_433 binary not found at '%s'. "
                    "Install with: sudo apt install rtl-433",
                    self.rtl433_path,
                )
                self._stop.wait(60)
            except Exception as e:
                logger.error("rtl_433 session crashed: %s", e)

            if not self._stop.is_set():
                logger.info("rtl_433 exited, restarting in 15s...")
                self._stop.wait(15)

        logger.info(
            "SDR capture stopped — %d signals decoded, %d unique devices",
            self.stats["signals_decoded"],
            self.stats["unique_devices"],
        )

    def stop(self):
        """Signal the engine to shut down cleanly."""
        logger.info("SDR capture engine stopping...")
        self._stop.set()
        proc = self._proc
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            except OSError:
                pass

    # -- subprocess management --

    def _build_cmd(self) -> list[str]:
        cmd = [self.rtl433_path, f"-d{self.device_index}"]

        if self.gain.lower() != "auto":
            cmd += ["-g", self.gain]

        if self.ppm:
            cmd += ["-p", str(self.ppm)]

        for freq in self.frequencies:
            cmd += ["-f", str(freq)]

        if len(self.frequencies) > 1:
            cmd += ["-H", str(self.hop_interval)]

        for proto in self.protocols:
            cmd += ["-R", str(proto)]

        # JSON output; include unix timestamp in UTC, signal level,
        # and protocol number in every decoded record.
        cmd += [
            "-F", "json",
            "-M", "time:unix:utc",
            "-M", "level",
            "-M", "protocol",
        ]

        cmd.extend(str(a) for a in self.extra_args)
        return cmd

    def _run_session(self):
        cmd = self._build_cmd()
        logger.info("Launching rtl_433: %s", " ".join(cmd))

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        # Drain stderr in background — errors go there, not stdout.
        # We log at DEBUG so they don't spam the log but are visible with -v.
        def _drain_stderr():
            for line in self._proc.stderr:
                line = line.strip()
                if not line:
                    continue
                # Demote noisy startup chatter to debug; keep real errors
                if any(kw in line for kw in ("Tuned to", "Allocating", "Sample rate", "Found")):
                    logger.debug("rtl_433: %s", line)
                elif any(kw in line for kw in ("Error", "error", "Failed", "failed", "lost")):
                    logger.warning("rtl_433: %s", line)
                else:
                    logger.debug("rtl_433: %s", line)

        threading.Thread(
            target=_drain_stderr, daemon=True, name="sdr-stderr"
        ).start()

        for raw_line in self._proc.stdout:
            if self._stop.is_set():
                break
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                self._handle_line(raw_line)
            except Exception as e:
                logger.warning(
                    "Line parse error: %s | %.120s", e, raw_line
                )

        self._proc.wait()
        rc = self._proc.returncode
        self._proc = None
        if rc and not self._stop.is_set():
            logger.warning("rtl_433 exited with code %d", rc)

    # -- line handling --

    def _handle_line(self, line: str):
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            return  # non-JSON status/housekeeping lines from rtl_433

        model = decoded.get("model") or ""
        if not model:
            return  # top-level stats/noise report lines have no model

        protocol    = decoded.get("protocol")
        device_uid  = make_device_uid(model, decoded)
        sig_class   = classify_model(model)

        # Signal quality
        rssi  = _float_or_none(decoded.get("rssi"))
        snr   = _float_or_none(decoded.get("snr"))
        noise = _float_or_none(decoded.get("noise"))

        # Battery status — rtl_433 uses various field names
        battery_ok = None
        for key in ("battery_OK", "battery_ok", "battery"):
            val = decoded.get(key)
            if val is not None:
                battery_ok = bool(int(val)) if isinstance(val, (int, float)) else None
                break

        # Frequency — rtl_433 reports "freq" in Hz with -M level
        frequency = _int_or_none(decoded.get("freq")) or (
            self.frequencies[0] if self.frequencies else None
        )

        channel = _int_or_none(decoded.get("channel"))

        # Timestamp — rtl_433 gives unix epoch float with time:unix:utc
        ts = _parse_timestamp(decoded.get("time"))

        # First-seen tracking
        is_new = device_uid not in self._seen_uids
        if is_new:
            self._seen_uids.add(device_uid)
            self.stats["unique_devices"] += 1

        # Stats
        self.stats["signals_decoded"] += 1
        stat_key = f"signals_{sig_class}"
        if stat_key in self.stats:
            self.stats[stat_key] += 1

        # Logging
        if is_new:
            logger.info(
                "NEW %-8s  proto=%-3s  %-50s  rssi=%s",
                sig_class.upper(),
                protocol or "?",
                device_uid,
                f"{rssi:.1f}dBm" if rssi is not None else "?",
            )
            _log_signal_detail(sig_class, decoded)
        else:
            logger.debug(
                "%-8s  proto=%-3s  %-50s  rssi=%s",
                sig_class,
                protocol or "?",
                device_uid,
                f"{rssi:.1f}dBm" if rssi is not None else "?",
            )

        # Periodic stats summary
        if self.stats["signals_decoded"] % self._STATS_INTERVAL == 0:
            self._log_stats()

        # Persist
        self._write_db(
            timestamp   = ts,
            protocol    = protocol,
            model       = model,
            device_uid  = device_uid,
            signal_class= sig_class,
            frequency   = frequency,
            channel     = channel,
            rssi        = rssi,
            snr         = snr,
            noise       = noise,
            battery_ok  = battery_ok,
            raw_json    = line,
        )

    # -- database write --

    def _write_db(self, **kwargs):
        session = get_session()
        try:
            session.add(SdrSignal(**kwargs))
            session.commit()
            self.stats["db_writes"] += 1
        except Exception as e:
            session.rollback()
            self.stats["db_errors"] += 1
            logger.error("DB write failed: %s", e)
        finally:
            session.close()

    # -- stats --

    def _log_stats(self):
        up = time.time() - (self.stats["start_time"] or time.time())
        h, m = divmod(int(up) // 60, 60)
        logger.info(
            "SDR  uptime=%dh%02dm  decoded=%d  unique=%d  "
            "tpms=%d  weather=%d  keyfob=%d  security=%d  power=%d  other=%d  "
            "db_ok=%d  db_err=%d",
            h, m,
            self.stats["signals_decoded"],
            self.stats["unique_devices"],
            self.stats["signals_tpms"],
            self.stats["signals_weather"],
            self.stats["signals_keyfob"],
            self.stats["signals_security"],
            self.stats["signals_power"],
            self.stats["signals_other"],
            self.stats["db_writes"],
            self.stats["db_errors"],
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _float_or_none(val) -> float | None:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _int_or_none(val) -> int | None:
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _parse_timestamp(raw) -> datetime:
    """Parse rtl_433 time field to an aware UTC datetime."""
    try:
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        if isinstance(raw, str):
            # "2024-01-15 10:30:45" or ISO 8601 variant
            return datetime.fromisoformat(
                raw.replace(" ", "T")
            ).replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return datetime.now(timezone.utc)


def _log_signal_detail(sig_class: str, d: dict):
    """Emit a human-readable summary for newly-seen devices."""
    parts = []
    if sig_class == "tpms":
        for key, label, unit in [
            ("pressure_kPa", "pressure", "kPa"),
            ("pressure_bar", "pressure", "bar"),
            ("pressure_PSI", "pressure", "PSI"),
            ("temperature_C", "temp", "°C"),
            ("battery_OK",  "battery", ""),
        ]:
            val = d.get(key)
            if val is not None:
                parts.append(f"{label}={val}{unit}")

    elif sig_class == "weather":
        for key, label, unit in [
            ("temperature_C", "temp", "°C"),
            ("humidity",      "rh",   "%"),
            ("wind_avg_km_h", "wind", "km/h"),
            ("wind_dir_deg",  "dir",  "°"),
            ("rain_mm",       "rain", "mm"),
            ("pressure_hPa",  "baro", "hPa"),
        ]:
            val = d.get(key)
            if val is not None:
                parts.append(f"{label}={val}{unit}")

    elif sig_class == "keyfob":
        for key in ("code", "state", "button", "cmd"):
            val = d.get(key)
            if val is not None:
                parts.append(f"{key}={val}")

    if parts:
        logger.info("          detail: %s", "  ".join(parts))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = config.load()
    config.setup_logging()
    init_db()

    sdr_cfg = cfg.get("sdr", {})
    if not sdr_cfg.get("enabled", True):
        logger.warning("SDR capture disabled in config (sdr.enabled: false)")
        sys.exit(0)

    engine = SdrCaptureEngine()

    def _shutdown(signum, frame):
        logger.info("Received %s, shutting down...", signal.Signals(signum).name)
        engine.stop()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info("=" * 60)
    logger.info("SENTINEL SDR Capture  (rtl_433 %s)", engine.rtl433_path)
    logger.info(
        "Device: %s  |  Gain: %s  |  PPM: %d  |  Frequencies: %s",
        engine.device_index,
        engine.gain,
        engine.ppm,
        ", ".join(f"{f/1e6:.3f}MHz" for f in engine.frequencies),
    )
    if engine.protocols:
        logger.info("Protocol filter: %s", engine.protocols)
    else:
        logger.info("Protocols: all defaults enabled")
    logger.info("=" * 60)

    engine.start()


if __name__ == "__main__":
    main()
