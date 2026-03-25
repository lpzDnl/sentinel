"""SENTINEL Drone Detection Module.

Detects drones via:
  - Known manufacturer OUI (MAC prefix) for DJI, Autel, Skydio
  - FAA Remote ID broadcast SSID pattern (starts with 'FA' + hex)

Usage:
    from capture.drone_detect import is_drone, rssi_distance_estimate

    detected, vendor, faa_ssid = is_drone(mac, ssids=["FAabcdef1234"])
"""

import re

# Known drone manufacturer OUI prefixes (uppercase, colon-separated, 3 octets)
DRONE_VENDORS: dict[str, str] = {
    "60:60:1F": "DJI",
    "34:D2:62": "DJI",
    "48:1C:B9": "DJI",
    "50:1E:2D": "DJI",
    "2C:1B:C5": "DJI",
    "00:0A:F5": "Autel",
    "DC:A6:32": "Skydio",
}

# FAA Remote ID SSID: starts with 'FA' followed by at least one hex character
_FAA_RE = re.compile(r"^FA[0-9A-Fa-f]", re.IGNORECASE)


def check_drone_vendor(mac: str) -> str | None:
    """Return drone vendor name if the MAC OUI matches a known drone prefix, else None."""
    prefix = mac.upper()[:8]  # "XX:XX:XX"
    return DRONE_VENDORS.get(prefix)


def check_faa_remote_id(ssids: list[str]) -> str | None:
    """Return the first SSID that matches the FAA Remote ID pattern, or None."""
    for ssid in ssids:
        if ssid and _FAA_RE.match(ssid):
            return ssid
    return None


def is_drone(mac: str, ssids: list[str] | None = None) -> tuple[bool, str | None, str | None]:
    """Check if a WiFi device is likely a drone.

    Args:
        mac: normalized uppercase MAC address
        ssids: list of SSIDs probed or broadcast by this device

    Returns:
        (detected, vendor, faa_ssid)
          detected  — True if any indicator matched
          vendor    — manufacturer name if OUI matched, else None
          faa_ssid  — matching FAA Remote ID SSID if found, else None
    """
    vendor = check_drone_vendor(mac)
    faa_ssid = check_faa_remote_id(ssids or [])
    return (vendor is not None or faa_ssid is not None), vendor, faa_ssid


def rssi_distance_estimate(rssi: int | None) -> str:
    """Translate RSSI to a human-readable distance estimate."""
    if rssi is None:
        return "unknown distance"
    if rssi >= -50:
        return "very close (<10m)"
    if rssi >= -65:
        return "close (10–30m)"
    if rssi >= -80:
        return "nearby (30–100m)"
    return "distant (>100m)"
