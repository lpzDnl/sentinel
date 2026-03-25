"""SENTINEL database schema and session management.

SQLite with WAL mode. All models use SQLAlchemy ORM.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from config import get as get_config

logger = logging.getLogger("sentinel.database")


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Device(Base):
    """A unique wireless device identified by MAC address."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac = Column(String(17), unique=True, nullable=False, index=True)
    device_type = Column(
        Enum("wifi", "bluetooth_classic", "bluetooth_le", "unknown", name="device_type_enum"),
        default="unknown",
    )
    vendor = Column(String(128))                 # OUI-resolved manufacturer
    hostname = Column(String(255))               # if discovered
    alias = Column(String(255))                  # user-assigned friendly name
    is_randomized = Column(Boolean, default=False)  # randomized MAC flag
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc))
    total_sightings = Column(Integer, default=1)
    notes = Column(Text)

    # Relationships
    tag = relationship("Tag", back_populates="device", uselist=False, cascade="all, delete-orphan")
    events = relationship("Event", back_populates="device", cascade="all, delete-orphan")
    visits = relationship("Visit", back_populates="device", cascade="all, delete-orphan")
    probes = relationship("ProbeRequest", back_populates="device", cascade="all, delete-orphan")
    baseline = relationship("Baseline", back_populates="device", uselist=False, cascade="all, delete-orphan")
    wigle_results = relationship("WigleCache", back_populates="device", cascade="all, delete-orphan")
    heartbeat = relationship("DeviceHeartbeat", back_populates="device", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        label = self.alias or self.vendor or self.mac
        return f"<Device {label} ({self.mac})>"


class Tag(Base):
    """Identity classification for a device."""
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), unique=True, nullable=False)
    category = Column(
        Enum("resident", "neighbor", "delivery", "visitor",
             "unknown", "flagged", "ignore", "drone", name="tag_category_enum"),
        default="unknown",
    )
    label = Column(String(255))                  # e.g. "John's iPhone", "FedEx"
    flagged = Column(Boolean, default=False)
    notes = Column(Text)
    tagged_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tagged_by = Column(String(64), default="auto")  # "auto" or "user"

    device = relationship("Device", back_populates="tag")

    def __repr__(self):
        return f"<Tag {self.category}: {self.label}>"


class Event(Base):
    """A discrete detection event (probe, BT advertisement, Frigate trigger, etc.)."""
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    event_type = Column(
        Enum("wifi_probe", "wifi_data", "bt_classic", "bt_ble",
             "frigate_person", "frigate_car", "frigate_object",
             "arrival", "departure", "anomaly", name="event_type_enum"),
        nullable=False, index=True,
    )
    source = Column(String(64))                  # "wlan1mon", "hci0", "frigate", "correlation"
    ssid = Column(String(64))                    # for probe requests
    rssi = Column(Integer)                       # signal strength dBm
    channel = Column(Integer)
    camera = Column(String(64))                  # Frigate camera name
    frigate_event_id = Column(String(128))       # Frigate event reference
    snapshot_path = Column(String(512))
    confidence = Column(Float)                   # Frigate detection confidence
    raw_data = Column(Text)                      # JSON blob for extra metadata

    device = relationship("Device", back_populates="events")

    __table_args__ = (
        Index("ix_events_device_time", "device_id", "timestamp"),
        Index("ix_events_type_time", "event_type", "timestamp"),
    )

    def __repr__(self):
        return f"<Event {self.event_type} @ {self.timestamp}>"


class Visit(Base):
    """A continuous presence session for a device (arrival to departure)."""
    __tablename__ = "visits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    arrived_at = Column(DateTime, nullable=False, index=True)
    departed_at = Column(DateTime)               # NULL = still present
    duration_seconds = Column(Integer)           # computed on departure
    max_rssi = Column(Integer)                   # strongest signal during visit
    event_count = Column(Integer, default=0)     # how many events during visit
    correlated_frigate_events = Column(Text)     # JSON list of frigate event IDs

    device = relationship("Device", back_populates="visits")

    __table_args__ = (
        Index("ix_visits_device_arrived", "device_id", "arrived_at"),
    )

    def __repr__(self):
        return f"<Visit device={self.device_id} arrived={self.arrived_at}>"


class Baseline(Base):
    """Behavioral baseline for a device - typical visiting patterns."""
    __tablename__ = "baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), unique=True, nullable=False)
    typical_start_hour = Column(Integer)         # e.g. 8 = usually appears after 8am
    typical_end_hour = Column(Integer)           # e.g. 17 = usually gone by 5pm
    typical_days = Column(String(20))            # e.g. "0,1,2,3,4" = weekdays (Monday=0)
    avg_visit_duration = Column(Integer)         # seconds
    avg_visits_per_day = Column(Float)
    total_visits = Column(Integer, default=0)
    last_computed = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    device = relationship("Device", back_populates="baseline")

    def __repr__(self):
        return f"<Baseline device={self.device_id} visits/day={self.avg_visits_per_day}>"


class FrigateEvent(Base):
    """Frigate NVR events received via webhook."""
    __tablename__ = "frigate_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    frigate_event_id = Column(String(128), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    camera = Column(String(64), nullable=False)
    label = Column(String(64))                   # person, car, etc.
    confidence = Column(Float)
    snapshot_path = Column(String(512))
    zones = Column(Text)                         # JSON list of zones
    duration = Column(Float)                     # event duration seconds
    correlated_device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"))
    correlation_confidence = Column(Float)
    raw_json = Column(Text)                      # full Frigate payload

    __table_args__ = (
        Index("ix_frigate_camera_time", "camera", "timestamp"),
    )

    def __repr__(self):
        return f"<FrigateEvent {self.label} on {self.camera} @ {self.timestamp}>"


class ProbeRequest(Base):
    """Individual WiFi probe requests captured."""
    __tablename__ = "probe_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    ssid = Column(String(64), index=True)        # target SSID (NULL = broadcast probe)
    rssi = Column(Integer)
    channel = Column(Integer)

    device = relationship("Device", back_populates="probes")

    __table_args__ = (
        Index("ix_probes_ssid_time", "ssid", "timestamp"),
    )

    def __repr__(self):
        return f"<Probe {self.ssid or 'broadcast'} rssi={self.rssi}>"


class WigleCache(Base):
    """Cached WiGLE API lookups for MAC addresses."""
    __tablename__ = "wigle_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    mac = Column(String(17), index=True)
    ssid = Column(String(64))
    latitude = Column(Float)
    longitude = Column(Float)
    city = Column(String(128))
    region = Column(String(128))
    country = Column(String(64))
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    raw_json = Column(Text)

    device = relationship("Device", back_populates="wigle_results")

    def __repr__(self):
        return f"<WigleCache {self.mac} @ {self.city}>"


class SdrSignal(Base):
    """A signal decoded by rtl_433 from a 315/433 MHz ISM-band device."""
    __tablename__ = "sdr_signals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    protocol  = Column(Integer, index=True)        # rtl_433 protocol number
    model     = Column(String(128), index=True)    # device model string from rtl_433
    device_uid = Column(String(128), index=True)   # "model/id" stable dedup key
    signal_class = Column(
        Enum("tpms", "weather", "keyfob", "security", "power", "other",
             name="sdr_signal_class_enum"),
        default="other", index=True,
    )
    frequency  = Column(Integer)                   # Hz
    channel    = Column(Integer)
    rssi       = Column(Float)                     # dBm
    snr        = Column(Float)
    noise      = Column(Float)
    battery_ok = Column(Boolean)
    raw_json   = Column(Text, nullable=False)      # full decoded JSON line

    __table_args__ = (
        Index("ix_sdr_uid_time",   "device_uid", "timestamp"),
        Index("ix_sdr_class_time", "signal_class", "timestamp"),
    )

    def __repr__(self):
        return f"<SdrSignal {self.signal_class} {self.device_uid} @ {self.timestamp}>"


class SdrDeviceTag(Base):
    """User-assigned label for an SDR device identified by its stable device_uid."""
    __tablename__ = "sdr_device_tags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_uid = Column(String(128), unique=True, nullable=False, index=True)
    category = Column(String(32), default="unknown")  # plain String — no DB enum, avoids migration
    label = Column(String(255))
    flagged = Column(Boolean, default=False)
    notes = Column(Text)
    tagged_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tagged_by = Column(String(64), default="user")

    def __repr__(self):
        return f"<SdrDeviceTag {self.device_uid}: {self.category}>"


class SdrFrigateCorrelation(Base):
    """Link between an SDR TPMS signal and a Frigate car detection."""
    __tablename__ = "sdr_frigate_correlations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    sdr_signal_id = Column(
        Integer, ForeignKey("sdr_signals.id", ondelete="SET NULL"), index=True
    )
    frigate_event_id = Column(
        Integer, ForeignKey("frigate_events.id", ondelete="SET NULL"), index=True
    )
    correlation_window_seconds = Column(Integer)
    confidence = Column(Float)
    notes = Column(Text)

    __table_args__ = (
        Index(
            "ix_sdr_frigate_pair",
            "sdr_signal_id", "frigate_event_id",
            unique=True,
        ),
    )

    def __repr__(self):
        return (
            f"<SdrFrigateCorrelation sdr={self.sdr_signal_id} "
            f"frigate={self.frigate_event_id} conf={self.confidence}>"
        )


class VehicleProfile(Base):
    """Persistent profile for a TPMS-identified vehicle."""
    __tablename__ = "vehicle_profiles"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    sensor_id     = Column(String(128), unique=True, nullable=False, index=True)  # TPMS device_uid
    model         = Column(String(128))           # Toyota/Ford/etc — user-assigned or inferred
    first_seen    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen     = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    sighting_count = Column(Integer, default=0)
    avg_rssi      = Column(Float)
    notes         = Column(Text)
    flagged       = Column(Boolean, default=False)
    flag_reason   = Column(String(64))            # e.g. 'frequent_visitor'

    def __repr__(self):
        return f"<VehicleProfile {self.sensor_id} sightings={self.sighting_count}>"


class DeviceHeartbeat(Base):
    """Heartbeat monitoring record for resident-tagged devices."""
    __tablename__ = "device_heartbeats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), unique=True, nullable=False)
    last_seen = Column(DateTime)
    expected_interval_minutes = Column(Integer, default=60)
    status = Column(
        Enum("online", "offline", "unknown", name="heartbeat_status_enum"),
        default="unknown",
    )
    consecutive_misses = Column(Integer, default=0)
    alerted_at = Column(DateTime)

    device = relationship("Device", back_populates="heartbeat")

    def __repr__(self):
        return f"<DeviceHeartbeat device={self.device_id} status={self.status}>"


class ArrivalEvent(Base):
    """Correlated arrival: WiFi device and TPMS signal seen within 2 minutes."""
    __tablename__ = "arrival_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    wifi_device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    tpms_sensor_id = Column(String(128), index=True)   # SdrSignal.device_uid
    tpms_model = Column(String(128))
    tpms_rssi = Column(Float)
    confidence = Column(
        Enum("high", "medium", "low", name="arrival_confidence_enum"),
        default="medium",
    )
    notes = Column(Text)
    reviewed = Column(Boolean, default=False)

    wifi_device = relationship("Device")

    __table_args__ = (
        Index("ix_arrival_time", "timestamp"),
    )

    def __repr__(self):
        return f"<ArrivalEvent wifi={self.wifi_device_id} tpms={self.tpms_sensor_id} conf={self.confidence}>"


class AlertLog(Base):
    """Record of all alerts sent."""
    __tablename__ = "alert_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    alert_type = Column(String(64), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"))
    frigate_event_id = Column(String(128))
    message = Column(Text, nullable=False)
    channel = Column(String(32), default="telegram")  # telegram, web, tui
    delivered = Column(Boolean, default=False)
    error = Column(Text)

    def __repr__(self):
        return f"<Alert {self.alert_type} delivered={self.delivered}>"


class DroneIdEvent(Base):
    """OpenDroneID beacon event decoded from a WiFi beacon frame."""
    __tablename__ = "droneid_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    mac = Column(String(17), nullable=False, index=True)
    serial_number = Column(String(64))          # from Basic ID message
    drone_lat = Column(Float)                   # degrees
    drone_lon = Column(Float)                   # degrees
    drone_alt_meters = Column(Float)            # geodetic altitude, metres
    pilot_lat = Column(Float)                   # operator GPS from System message
    pilot_lon = Column(Float)
    speed_ms = Column(Float)                    # horizontal speed m/s
    heading = Column(Float)                     # track direction degrees (0=N)
    rssi = Column(Integer)                      # beacon RSSI dBm
    raw_data = Column(Text)                     # JSON of raw parsed message parts

    __table_args__ = (
        Index("ix_droneid_mac_ts", "mac", "timestamp"),
    )

    def __repr__(self):
        return f"<DroneIdEvent mac={self.mac} serial={self.serial_number}>"


# ---------------------------------------------------------------------------
# Engine & Session Management
# ---------------------------------------------------------------------------

_engine = None
_SessionFactory = None


def _set_sqlite_pragmas(dbapi_conn, connection_record):
    """Set SQLite performance pragmas on every new connection."""
    cursor = dbapi_conn.cursor()
    cfg = get_config()
    journal_mode = cfg.get("database", {}).get("journal_mode", "WAL")
    busy_timeout = cfg.get("database", {}).get("busy_timeout", 5000)
    cursor.execute(f"PRAGMA journal_mode={journal_mode}")
    cursor.execute(f"PRAGMA busy_timeout={busy_timeout}")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def get_engine():
    """Get or create the SQLAlchemy engine."""
    global _engine
    if _engine is None:
        cfg = get_config()
        db_path = cfg["database"]["path"]
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,
            pool_pre_ping=True,
            connect_args={"timeout": 30, "check_same_thread": False},
        )
        event.listen(_engine, "connect", _set_sqlite_pragmas)
        logger.info("Database engine created: %s", db_path)
    return _engine


def get_session() -> Session:
    """Get a new database session."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine())
    return _SessionFactory()


def init_db() -> None:
    """Create all tables if they don't exist."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    logger.info("Database initialized - all tables created")


def drop_db() -> None:
    """Drop all tables. Use with caution."""
    engine = get_engine()
    Base.metadata.drop_all(engine)
    logger.warning("All database tables dropped")


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def get_or_create_device(session: Session, mac: str, **kwargs) -> tuple["Device", bool]:
    """Find existing device by MAC or create a new one.

    Returns:
        (device, created) tuple where created is True if new.
    """
    device = session.query(Device).filter(Device.mac == mac.upper()).first()
    if device:
        device.last_seen = datetime.now(timezone.utc)
        device.total_sightings = (device.total_sightings or 0) + 1
        for key, value in kwargs.items():
            if value is not None and hasattr(device, key):
                setattr(device, key, value)
        return device, False

    device = Device(mac=mac.upper(), **kwargs)
    session.add(device)
    session.flush()

    # Auto-create unknown tag
    tag = Tag(device_id=device.id, category="unknown")
    session.add(tag)

    return device, True
