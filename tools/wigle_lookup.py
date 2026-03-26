#!/usr/bin/env python3
"""SENTINEL WiGLE Lookup Tool.

Takes hacker_detector hits (score >= 60) and queries WiGLE API v2
to determine whether any flagged MACs appear in the global wardriving
database — which would indicate a mobile, travelling, or wardriving device.

Auth
────
WiGLE v2 uses HTTP Basic auth:  base64(apiName:apiToken)

Config supports two formats:
  1. Separate fields (preferred):
       wigle.api_name: AIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
       wigle.api_key:  <token>
  2. Pre-encoded credential (WiGLE "Encoded for use" value):
       wigle.api_key:  <base64(name:token)>   # if it decodes to "AID...:..."

Add api_name to /opt/sentinel/config.yaml:
  wigle:
    api_name: AIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx   # from wigle.net → Account → API keys
    api_key: ed2a4b24c5a230ab9f1716d9fe8ba7b6

Usage:
    python3 tools/wigle_lookup.py [--hours N] [--min-score N] [--no-cache]
"""

import argparse
import base64
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/sentinel")

import requests

import config
from database import Device, WigleCache, get_session, init_db
from analysis.hacker_detector import scan_recent_devices

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.wigle_lookup")

WIGLE_DETAIL_URL = "https://api.wigle.net/api/v2/network/detail"
WIGLE_HITS_PATH  = Path("/opt/sentinel/data/wigle_hits.json")

# Polite inter-request delay — WiGLE is a community service
REQUEST_DELAY = 1.2  # seconds


# ---------------------------------------------------------------------------
# Auth builder
# ---------------------------------------------------------------------------

def _build_auth_header(cfg: dict) -> tuple[str, str | None]:
    """Build Authorization header value and return (header_value, error_or_None).

    Supports:
      1. api_name + api_key  → Basic base64(api_name:api_key)
      2. api_key alone (tries to detect if it's already a base64 encoded credential)
    """
    wigle_cfg = cfg.get("wigle", {})
    api_key   = wigle_cfg.get("api_key", "").strip()
    api_name  = wigle_cfg.get("api_name", "").strip()

    if not api_key:
        return "", "wigle.api_key is not set in config.yaml"

    # Case 1: both name and key present — straightforward
    if api_name:
        raw  = f"{api_name}:{api_key}"
        enc  = base64.b64encode(raw.encode()).decode()
        return f"Basic {enc}", None

    # Case 2: api_key only — check if it's already a pre-encoded "name:token" credential
    try:
        decoded = base64.b64decode(api_key + "==").decode("utf-8", errors="strict")
        if ":" in decoded and decoded.split(":", 1)[0].startswith("AID"):
            logger.info("api_key appears to be a pre-encoded WiGLE credential")
            return f"Basic {api_key}", None
    except Exception:
        pass

    # Give a clear error — api_name is required
    return (
        "",
        (
            "wigle.api_name is missing from config.yaml.\n"
            "  Add it under the wigle: section:\n"
            "    api_name: AIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
            "  (Find it at https://wigle.net → Account → API keys)"
        ),
    )


# ---------------------------------------------------------------------------
# WiGLE query
# ---------------------------------------------------------------------------

def _query_wigle(mac: str, auth_header: str, use_cache: bool = True) -> dict:
    """Query WiGLE API v2 for a single MAC.  Returns parsed result dict."""
    # Check DB cache first
    if use_cache:
        session = get_session()
        try:
            cached = (
                session.query(WigleCache)
                .filter(WigleCache.mac == mac.upper())
                .first()
            )
            if cached and cached.raw_json:
                age_h = (
                    datetime.now(timezone.utc) - cached.last_updated.replace(tzinfo=timezone.utc)
                ).total_seconds() / 3600
                if age_h < 24:
                    logger.info("  [cache] %s (%.0fh old)", mac, age_h)
                    return json.loads(cached.raw_json)
        finally:
            session.close()

    headers = {
        "Authorization": auth_header,
        "Accept":        "application/json",
    }
    params = {"netid": mac.upper()}

    try:
        resp = requests.get(WIGLE_DETAIL_URL, headers=headers, params=params, timeout=15)
    except requests.RequestException as e:
        return {"error": str(e), "mac": mac, "http_status": 0}

    if resp.status_code == 401:
        return {"error": "401 Unauthorized — check wigle.api_name in config.yaml",
                "mac": mac, "http_status": 401}
    if resp.status_code == 429:
        return {"error": "429 Rate limited — WiGLE daily quota exhausted; retry after UTC midnight",
                "mac": mac, "http_status": 429, "_rate_limited": True}
    if resp.status_code == 404:
        return {"found": False, "mac": mac, "http_status": 404, "results": []}
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                "mac": mac, "http_status": resp.status_code}

    try:
        data = resp.json()
    except ValueError:
        return {"error": "Invalid JSON response", "mac": mac}

    data["_fetched_at"] = datetime.now(timezone.utc).isoformat()
    data["mac"]         = mac.upper()

    # Cache to DB
    _cache_result(mac, data)

    return data


def _cache_result(mac: str, data: dict) -> None:
    """Persist WiGLE result to wigle_cache table."""
    results = data.get("results", [])
    first   = results[0] if results else {}

    session = get_session()
    try:
        # Find matching device
        device = session.query(Device).filter(Device.mac == mac.upper()).first()
        device_id = device.id if device else None

        existing = (
            session.query(WigleCache)
            .filter(WigleCache.mac == mac.upper())
            .first()
        )
        if existing:
            existing.ssid         = first.get("ssid")
            existing.latitude     = first.get("trilat")
            existing.longitude    = first.get("trilong")
            existing.city         = first.get("city")
            existing.region       = first.get("region")
            existing.country      = first.get("country")
            existing.last_updated = datetime.now(timezone.utc)
            existing.raw_json     = json.dumps(data)
        else:
            row = WigleCache(
                device_id    = device_id,
                mac          = mac.upper(),
                ssid         = first.get("ssid"),
                latitude     = first.get("trilat"),
                longitude    = first.get("trilong"),
                city         = first.get("city"),
                region       = first.get("region"),
                country      = first.get("country"),
                last_updated = datetime.now(timezone.utc),
                raw_json     = json.dumps(data),
            )
            session.add(row)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.warning("Cache write failed for %s: %s", mac, e)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Result parser
# ---------------------------------------------------------------------------

def _parse_result(mac: str, data: dict, hit_meta: dict) -> dict:
    """Parse a WiGLE API response into a clean summary dict."""
    out = {
        "mac":          mac.upper(),
        "score":        hit_meta.get("score", 0),
        "alert_level":  hit_meta.get("alert_level", "?"),
        "vendor":       hit_meta.get("vendor", ""),
        "reasons":      hit_meta.get("reasons", []),
        "wigle_found":  False,
        "wigle_error":  data.get("error"),
        "http_status":  data.get("http_status", 200),
        "results":      [],
        "summary":      {},
    }

    if "error" in data:
        return out

    raw_results = data.get("results", [])
    out["wigle_found"]   = bool(raw_results)
    out["total_results"] = data.get("totalResults", 0)

    cities = set()
    parsed_results = []

    for r in raw_results:
        city    = r.get("city") or ""
        region  = r.get("region") or ""
        country = r.get("country") or ""
        if city:
            cities.add(f"{city}, {country}" if country else city)

        parsed_results.append({
            "ssid":        r.get("ssid"),
            "trilat":      r.get("trilat"),
            "trilong":     r.get("trilong"),
            "firsttime":   r.get("firsttime"),
            "lasttime":    r.get("lasttime"),
            "city":        city,
            "region":      region,
            "country":     country,
            "channel":     r.get("channel"),
            "encryption":  r.get("encryption"),
            "numlinks":    r.get("numlinks", 0),
            "type":        r.get("type"),
        })

    out["results"]       = parsed_results
    out["cities_seen"]   = sorted(cities)
    out["is_mobile"]     = len(cities) > 1

    if parsed_results:
        latest = parsed_results[0]          # WiGLE returns newest first
        out["summary"] = {
            "ssid":          latest["ssid"],
            "last_seen":     latest["lasttime"],
            "first_seen":    latest["firsttime"],
            "last_lat":      latest["trilat"],
            "last_lon":      latest["trilong"],
            "last_location": ", ".join(filter(None, [
                latest["city"], latest["region"], latest["country"]
            ])),
            "trilaterations": latest["numlinks"],
            "cities_seen":   out["cities_seen"],
            "is_mobile":     out["is_mobile"],
        }

    return out


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _bar(width: int = 60) -> str:
    return "─" * width


def _print_result(r: dict) -> None:
    mac   = r["mac"]
    score = r["score"]
    level = r["alert_level"].upper()
    vendor = r["vendor"] or "unknown vendor"

    level_icon = {"RED": "🔴", "YELLOW": "🟡", "LOG": "⬜"}.get(level, "⬜")

    print(f"\n{_bar()}")
    print(f"{level_icon}  {mac}  │  score={score}  │  {vendor}")
    for reason in r["reasons"]:
        print(f"     reason: {reason}")

    if r.get("wigle_error"):
        print(f"     WiGLE:  ERROR — {r['wigle_error']}")
        return

    if not r.get("wigle_found"):
        total = r.get("total_results", 0)
        print(f"     WiGLE:  not found (totalResults={total})")
        return

    s = r["summary"]
    print(f"     WiGLE:  FOUND  ({r['total_results']} result(s))")
    if s.get("ssid"):
        print(f"     Associated SSID:      {s['ssid']}")
    if s.get("first_seen"):
        print(f"     First observed:       {s['first_seen'][:19].replace('T', ' ')}")
    if s.get("last_seen"):
        print(f"     Last seen:            {s['last_seen'][:19].replace('T', ' ')}")
    if s.get("last_location"):
        print(f"     Last location:        {s['last_location']}")
    if s.get("last_lat") is not None:
        print(f"     Coordinates:          {s['last_lat']:.5f}, {s['last_lon']:.5f}")
    if s.get("trilaterations") is not None:
        print(f"     Total trilaterations: {s['trilaterations']}")
    if s.get("cities_seen"):
        print(f"     Cities seen:          {', '.join(s['cities_seen'])}")
    if s.get("is_mobile"):
        print(f"     ⚠️  MOBILE DEVICE — seen in multiple cities")


def _print_summary_table(results: list[dict]) -> None:
    print(f"\n{'═' * 72}")
    print("WIGLE LOOKUP SUMMARY")
    print(f"{'═' * 72}")
    hdr = f"{'MAC':<20} {'Score':>5}  {'Level':<7} {'WiGLE':>7}  {'Location / Note'}"
    print(hdr)
    print(f"{'─' * 20} {'─' * 5}  {'─' * 7} {'─' * 7}  {'─' * 30}")

    for r in results:
        found = "FOUND" if r.get("wigle_found") else (
            "ERROR"  if r.get("wigle_error") else "—"
        )
        location = ""
        if r.get("wigle_found") and r.get("summary"):
            location = r["summary"].get("last_location", "")
            if r["summary"].get("is_mobile"):
                location = "⚠️  MOBILE  " + location
        elif r.get("wigle_error"):
            location = r["wigle_error"][:40]

        level = r["alert_level"].upper()
        print(f"{r['mac']:<20} {r['score']:>5}  {level:<7} {found:>7}  {location}")

    print(f"{'═' * 72}")
    found_count = sum(1 for r in results if r.get("wigle_found"))
    print(f"Total queried: {len(results)}  |  WiGLE hits: {found_count}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SENTINEL WiGLE MAC lookup tool")
    parser.add_argument("--hours",     type=int, default=144,
                        help="Lookback window for hacker_detector scan (default 144h = 6 days)")
    parser.add_argument("--min-score", type=int, default=60,
                        help="Minimum hacker_detector score to include (default 60)")
    parser.add_argument("--no-cache",  action="store_true",
                        help="Bypass DB cache and force fresh WiGLE queries")
    args = parser.parse_args()

    cfg = config.get()
    init_db()

    # ── Auth ──
    auth_header, auth_err = _build_auth_header(cfg)
    if auth_err:
        print(f"\n{'!'*60}")
        print("WIGLE AUTH CONFIGURATION REQUIRED")
        print(f"{'!'*60}")
        print(auth_err)
        print(f"\nThe script will continue and show hacker_detector results,")
        print(f"but WiGLE queries will fail until api_name is configured.\n")
        # Use a sentinel value so queries will get 401s which we handle
        auth_header = "Basic UNCONFIGURED"

    # ── Step 1: hacker_detector scan ──
    print(f"\n{'═'*60}")
    print(f"HACKER DETECTOR SCAN  (last {args.hours}h, score ≥ {args.min_score})")
    print(f"{'═'*60}")
    hits = scan_recent_devices(hours=args.hours)
    candidates = [h for h in hits if h["score"] >= args.min_score]
    print(f"Devices scanned:  {_device_count_in_window(args.hours)}")
    print(f"Total hits:       {len(hits)}")
    print(f"Score ≥ {args.min_score}:       {len(candidates)}")

    if not candidates:
        print("\nNo devices meet the score threshold. Nothing to look up.")

    # ── Step 2: also pull the Pi MAC directly (belt-and-suspenders) ──
    pi_mac = _get_rpi_mac()
    extra_macs = []
    if pi_mac and pi_mac.upper() not in {c["mac"].upper() for c in candidates}:
        logger.info("Adding Raspberry Pi MAC %s from devices table", pi_mac)
        extra_macs.append({
            "device_id": None,
            "mac": pi_mac,
            "vendor": "Raspberry Pi (Trading) Ltd",
            "score": 60,
            "alert_level": "yellow",
            "reasons": ["Vendor: Raspberry Pi (pulled from devices table)"],
            "matched_vendor": "raspberry pi",
            "matched_ssids": [],
        })

    # ESP32/Realtek devices (score 40) — always WiGLE-query these too.
    # An ESP32 with WiGLE history is likely a wardriving rig and should
    # have its score bumped to 90.
    esp_extras = [h for h in hits if h["score"] < args.min_score]

    all_candidates = candidates + extra_macs + esp_extras
    # Deduplicate while preserving the highest-scored entry per MAC
    seen: dict[str, dict] = {}
    for c in all_candidates:
        mac = c["mac"].upper()
        if mac not in seen or c["score"] > seen[mac]["score"]:
            seen[mac] = c
    all_candidates = list(seen.values())

    if esp_extras:
        print(f"\nAlso querying {len(esp_extras)} ESP32/low-score device(s) "
              f"(WiGLE history would bump score to 90)")

    macs_to_query = [c["mac"].upper() for c in all_candidates]

    print(f"\nMACs to query:    {len(macs_to_query)}")
    for mac in macs_to_query:
        meta = next((c for c in all_candidates if c["mac"].upper() == mac), {})
        print(f"  {mac}  score={meta.get('score',0)}  {meta.get('vendor','')}")

    # ── Steps 3–6: query WiGLE ──
    print(f"\n{'─'*60}")
    print("QUERYING WIGLE API v2...")
    print(f"{'─'*60}")

    all_results     = []
    raw_wigle_saves = {}

    for i, mac in enumerate(macs_to_query, 1):
        meta = next((c for c in all_candidates if c["mac"].upper() == mac), {})
        print(f"\n[{i}/{len(macs_to_query)}] {mac}  ({meta.get('vendor','?')})")

        data   = _query_wigle(mac, auth_header, use_cache=not args.no_cache)
        result = _parse_result(mac, data, meta)
        all_results.append(result)
        raw_wigle_saves[mac] = data

        _print_result(result)

        # Stop immediately on rate limit — no point burning remaining quota
        if data.get("_rate_limited"):
            remaining = macs_to_query[i:]
            if remaining:
                print(f"\n  ⏸  Rate limited — skipping remaining {len(remaining)} MAC(s).")
                print(f"     Retry after UTC midnight: python3 tools/wigle_lookup.py --no-cache")
                for skipped_mac in remaining:
                    skipped_meta = next((c for c in all_candidates
                                        if c["mac"].upper() == skipped_mac), {})
                    all_results.append({
                        "mac": skipped_mac, "score": skipped_meta.get("score", 0),
                        "alert_level": skipped_meta.get("alert_level", "log"),
                        "vendor": skipped_meta.get("vendor", ""), "reasons": [],
                        "wigle_found": False, "wigle_error": "skipped (rate limit)",
                        "http_status": 429,
                    })
            break

        if i < len(macs_to_query):
            time.sleep(REQUEST_DELAY)

    # ── Summary table ──
    _print_summary_table(all_results)

    # ── Step 7: save JSON ──
    save_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_hours":   args.hours,
        "min_score":    args.min_score,
        "results":      all_results,
        "raw_wigle":    raw_wigle_saves,
    }
    WIGLE_HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
    WIGLE_HITS_PATH.write_text(json.dumps(save_data, indent=2, default=str))
    print(f"\nFull results saved → {WIGLE_HITS_PATH}")

    # ── Auth fix instructions if needed ──
    if auth_err:
        print(f"\n{'!'*60}")
        print("TO ENABLE LIVE WIGLE QUERIES:")
        print(f"{'!'*60}")
        print("1. Log in at https://wigle.net")
        print("2. Go to Account → API keys")
        print("3. Copy your 'API Name' (starts with AID...)")
        print("4. Add to /opt/sentinel/config.yaml:")
        print("     wigle:")
        print("       api_name: AIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print("       api_key: ed2a4b24c5a230ab9f1716d9fe8ba7b6")
        print("5. Re-run: python3 tools/wigle_lookup.py --no-cache")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _device_count_in_window(hours: int) -> int:
    from datetime import timedelta
    session = get_session()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return session.query(Device).filter(Device.first_seen >= cutoff).count()
    finally:
        session.close()


def _get_rpi_mac() -> str | None:
    """Return the MAC of the first Raspberry Pi device in the devices table."""
    session = get_session()
    try:
        device = (
            session.query(Device)
            .filter(Device.vendor.ilike("%raspberry pi%"))
            .order_by(Device.first_seen)
            .first()
        )
        return device.mac if device else None
    finally:
        session.close()


if __name__ == "__main__":
    main()
