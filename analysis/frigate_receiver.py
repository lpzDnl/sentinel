#!/usr/bin/env python3
"""SENTINEL Frigate Webhook Receiver.

Flask server that receives event webhooks from Frigate NVR,
downloads snapshots, stores events, and triggers the correlation
engine. Also provides a polling fallback that pulls recent events
from the Frigate API.

Run standalone:  python3 -m analysis.frigate_receiver
Run as service:  systemctl start sentinel-frigate
"""

import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, request as flask_request

sys.path.insert(0, "/opt/sentinel")

import config
from database import (
    Event,
    FrigateEvent,
    get_session,
    init_db,
)
from analysis.correlation import run_correlation_for_frigate
from analysis.alerter import ThreatLevel, send_alert

logger = logging.getLogger("sentinel.frigate")

# ---------------------------------------------------------------------------
# Frigate API client
# ---------------------------------------------------------------------------

class FrigateClient:
    """HTTP client for Frigate NVR API."""

    def __init__(self):
        cfg = config.get_section("frigate")
        self.api_url = cfg.get("api_url", "http://192.168.50.182:5000/api")
        self.snapshot_dir = Path(cfg.get("snapshot_dir", "/opt/sentinel/data/snapshots"))
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.watched_labels = set(cfg.get("events", ["person", "car"]))

    def get_events(self, limit: int = 20, after: float | None = None) -> list[dict]:
        """Fetch recent events from Frigate API."""
        params = {"limit": limit, "include_thumbnails": 0}
        if after:
            params["after"] = after
        try:
            resp = requests.get(f"{self.api_url}/events", params=params, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("Frigate API events fetch failed: %s", e)
            return []

    def download_snapshot(self, event_id: str, camera: str) -> str | None:
        """Download event snapshot from Frigate.

        Returns path to saved snapshot file, or None on failure.
        """
        try:
            url = f"{self.api_url}/events/{event_id}/snapshot.jpg"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200 and len(resp.content) > 100:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                filename = f"{camera}_{ts}_{event_id[:8]}.jpg"
                path = self.snapshot_dir / filename
                path.write_bytes(resp.content)
                logger.debug("Snapshot saved: %s (%d bytes)", path, len(resp.content))
                return str(path)
            else:
                logger.debug("No snapshot for event %s (status=%d)", event_id, resp.status_code)
        except Exception as e:
            logger.error("Snapshot download failed for %s: %s", event_id, e)
        return None

    def get_config(self) -> dict:
        """Fetch Frigate configuration."""
        try:
            resp = requests.get(f"{self.api_url}/config", timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("Frigate config fetch failed: %s", e)
            return {}

    def get_stats(self) -> dict:
        """Fetch Frigate stats."""
        try:
            resp = requests.get(f"{self.api_url}/stats", timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("Frigate stats fetch failed: %s", e)
            return {}


# ---------------------------------------------------------------------------
# Event processor
# ---------------------------------------------------------------------------

def process_frigate_event(event_data: dict, client: FrigateClient) -> int | None:
    """Process a single Frigate event and store it in the database.

    Args:
        event_data: Frigate event payload dict.
        client: FrigateClient for snapshot downloads.

    Returns:
        Database ID of the created FrigateEvent, or None.
    """
    frigate_id = event_data.get("id")
    if not frigate_id:
        logger.warning("Frigate event missing id: %s", event_data)
        return None

    label = event_data.get("label", "unknown")
    camera = event_data.get("camera", "unknown")
    score = event_data.get("data", {}).get("score") or event_data.get("score")

    # Check if we care about this label
    if label not in client.watched_labels:
        logger.debug("Ignoring Frigate event: %s (label=%s)", frigate_id, label)
        return None

    session = get_session()
    try:
        # Deduplicate - skip if we already have this event
        existing = (
            session.query(FrigateEvent)
            .filter(FrigateEvent.frigate_event_id == frigate_id)
            .first()
        )
        if existing:
            logger.debug("Duplicate Frigate event skipped: %s", frigate_id)
            return existing.id

        # Parse timestamp
        start_time = event_data.get("start_time")
        if start_time:
            ts = datetime.fromtimestamp(start_time, tz=timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        # Duration
        end_time = event_data.get("end_time")
        duration = None
        if start_time and end_time:
            duration = end_time - start_time

        # Zones
        zones = event_data.get("zones", [])
        zones_json = json.dumps(zones) if zones else None

        # Download snapshot
        snapshot_path = None
        cfg = config.get_section("frigate")
        if cfg.get("snapshot_download", True):
            snapshot_path = client.download_snapshot(frigate_id, camera)

        # Create FrigateEvent record
        fe = FrigateEvent(
            frigate_event_id=frigate_id,
            timestamp=ts,
            camera=camera,
            label=label,
            confidence=score,
            snapshot_path=snapshot_path,
            zones=zones_json,
            duration=duration,
            raw_json=json.dumps(event_data),
        )
        session.add(fe)

        # Also create a generic Event for the unified timeline
        event_type = f"frigate_{label}" if label in ("person", "car") else "frigate_object"
        evt = Event(
            timestamp=ts,
            event_type=event_type,
            source="frigate",
            camera=camera,
            frigate_event_id=frigate_id,
            snapshot_path=snapshot_path,
            confidence=score,
            raw_data=json.dumps({"zones": zones, "label": label}),
        )
        session.add(evt)

        session.commit()
        fe_id = fe.id

        logger.info(
            "Frigate event stored: %s (%s on %s, confidence=%.2f, zones=%s)",
            frigate_id, label, camera, score or 0, zones,
        )

        return fe_id

    except Exception as e:
        session.rollback()
        logger.error("Failed to process Frigate event %s: %s", frigate_id, e)
        return None
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Flask webhook app
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Create the Flask webhook receiver app."""
    app = Flask("sentinel-frigate")
    client = FrigateClient()

    @app.route("/webhook", methods=["POST"])
    def webhook():
        """Receive Frigate webhook POST."""
        data = flask_request.get_json(silent=True)
        if not data:
            return jsonify({"error": "no JSON body"}), 400

        event_type = data.get("type", "unknown")
        logger.debug("Webhook received: type=%s", event_type)

        # Frigate sends different event types: new, update, end
        # Process "new" and "end" events
        if event_type not in ("new", "end"):
            return jsonify({"status": "ignored", "type": event_type}), 200

        after = data.get("after", {})
        if not after:
            return jsonify({"error": "missing 'after' payload"}), 400

        fe_id = process_frigate_event(after, client)
        if fe_id is None:
            return jsonify({"status": "skipped"}), 200

        # Run correlation pipeline in background thread
        threading.Thread(
            target=_run_correlation_safe,
            args=(fe_id,),
            daemon=True,
            name=f"correlate-{fe_id}",
        ).start()

        return jsonify({"status": "processed", "frigate_event_db_id": fe_id}), 200

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        return jsonify({
            "status": "ok",
            "service": "sentinel-frigate",
            "frigate_api": client.api_url,
        }), 200

    @app.route("/stats", methods=["GET"])
    def stats():
        """Return Frigate stats."""
        return jsonify(client.get_stats()), 200

    @app.route("/test", methods=["POST"])
    def test_alert():
        """Send a test RED alert through the full pipeline."""
        send_alert(
            level=ThreatLevel.RED,
            alert_type="night_gate",
            camera="test_camera",
            details={"reason": "Test alert from Frigate receiver",
                     "confidence": 0.99},
        )
        return jsonify({"status": "test RED alert sent"}), 200

    return app


def _run_correlation_safe(fe_id: int):
    """Run correlation with error handling."""
    try:
        result = run_correlation_for_frigate(fe_id)
        logger.info("Correlation result for FE %d: %s", fe_id, result)
    except Exception as e:
        logger.error("Correlation pipeline error for FE %d: %s", fe_id, e)


# ---------------------------------------------------------------------------
# Polling fallback (for Frigate instances without webhook support)
# ---------------------------------------------------------------------------

class FrigatePoller:
    """Polls Frigate API for new events as a webhook fallback."""

    # Keep at most this many IDs in the seen cache; old entries are
    # discarded in FIFO order once the limit is reached.
    _MAX_SEEN = 500

    def __init__(self, client: FrigateClient, poll_interval: int = 30):
        self.client = client
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._last_event_time: float | None = None
        self._seen_event_ids: dict[str, None] = {}  # ordered dict (insertion order)
        self._thread: threading.Thread | None = None

    def start(self):
        """Start polling in a background thread."""
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="frigate-poller")
        self._thread.start()
        logger.info("Frigate poller started (interval=%ds)", self.poll_interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Frigate poller stopped")

    def _poll_loop(self):
        # Seed with current time so we only get new events
        self._last_event_time = time.time()

        while not self._stop.is_set():
            try:
                events = self.client.get_events(limit=10, after=self._last_event_time)
                for event_data in events:
                    frigate_id = event_data.get("id")
                    if not frigate_id:
                        continue

                    # Skip events we've already processed
                    if frigate_id in self._seen_event_ids:
                        continue

                    start_t = event_data.get("start_time", 0)
                    if start_t and start_t > (self._last_event_time or 0):
                        fe_id = process_frigate_event(event_data, self.client)
                        if fe_id:
                            _run_correlation_safe(fe_id)
                        self._last_event_time = start_t

                    # Mark as seen regardless of whether we processed it
                    # (filtered label, duplicate in DB, etc.)
                    self._seen_event_ids[frigate_id] = None
                    if len(self._seen_event_ids) > self._MAX_SEEN:
                        # Evict oldest entry
                        self._seen_event_ids.pop(next(iter(self._seen_event_ids)))

            except Exception as e:
                logger.error("Poller cycle error: %s", e)

            self._stop.wait(self.poll_interval)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = config.load()
    config.setup_logging()
    init_db()

    frigate_cfg = cfg.get("frigate", {})
    if not frigate_cfg.get("enabled", True):
        logger.warning("Frigate integration disabled in config, exiting")
        sys.exit(0)

    port = frigate_cfg.get("webhook_port", 8765)
    client = FrigateClient()

    # Verify Frigate connectivity
    try:
        resp = requests.get(f"{client.api_url}/version", timeout=5)
        logger.info("Frigate connected: version %s", resp.text.strip())
    except Exception as e:
        logger.warning("Cannot reach Frigate at %s: %s (will keep trying)", client.api_url, e)

    # Start the event poller alongside the webhook server
    poller = FrigatePoller(client, poll_interval=30)
    poller.start()

    app = create_app()

    def shutdown(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, shutting down...", sig_name)
        poller.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("=" * 60)
    logger.info("SENTINEL Frigate Webhook Receiver")
    logger.info("Listening on port %d | Frigate API: %s", port, client.api_url)
    logger.info("Watched labels: %s", client.watched_labels)
    logger.info("Poller active (30s interval, watermark seeded to now)")
    logger.info("=" * 60)

    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
