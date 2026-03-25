#!/usr/bin/env python3
"""One-shot fix: re-tag devices incorrectly classified as 'resident' due to
'Unifi 2.4' being in the old _RESIDENT_NETWORKS constant.

Actions:
  1. Find devices tagged auto_probe/resident that probed 'Unifi 2.4' but NOT
     any true resident SSID → re-tag as neighbor.
  2. Override specific MACs per user instruction.
  3. Re-run auto_tag_by_probes on all touched devices to apply fresh logic.
"""

import sys
from datetime import datetime, timezone

sys.path.insert(0, "/opt/sentinel")

import config
config.load()

from database import Device, ProbeRequest, Tag, get_session
from analysis.correlation import auto_tag_by_probes, _RESIDENT_NETWORKS

UNIFI_SSID = "unifi 2.4"
TRUE_RESIDENT_NETS = _RESIDENT_NETWORKS   # {'valenciavalencia', 'valenciavalencia.menudencia'}

# Specific overrides regardless of probe history
SPECIFIC_OVERRIDES = {
    "C4:1C:FF:8B:CB:1E": {"category": "resident", "label": "Vizio TV",   "notes": "Vizio TV"},
    "90:F1:57:E8:9C:6E": {"category": "neighbor",  "label": None,         "notes": "Garmin device - Unifi neighbor"},
    "14:13:0B:13:60:38": {"category": "neighbor",  "label": None,         "notes": "Garmin device - Unifi neighbor"},
}


def main():
    session = get_session()
    affected_device_ids = []

    try:
        # --- Step 1: find incorrectly-tagged residents (auto_probe only) ---
        # A device is a candidate if it probed 'unifi 2.4' and has no true
        # resident SSID in its probe history.
        auto_resident_tags = (
            session.query(Tag, Device)
            .join(Device, Tag.device_id == Device.id)
            .filter(
                Tag.category == "resident",
                Tag.tagged_by == "auto_probe",
            )
            .all()
        )

        print(f"Checking {len(auto_resident_tags)} auto_probe/resident devices...")

        for tag, device in auto_resident_tags:
            # Skip specific overrides — handled in step 2
            if device.mac.upper() in {m.upper() for m in SPECIFIC_OVERRIDES}:
                continue

            ssid_rows = (
                session.query(ProbeRequest.ssid)
                .filter(
                    ProbeRequest.device_id == device.id,
                    ProbeRequest.ssid.isnot(None),
                    ProbeRequest.ssid != "",
                )
                .distinct()
                .all()
            )
            ssids_lower = {row[0].lower() for row in ssid_rows}

            probed_unifi = UNIFI_SSID in ssids_lower
            probed_true_resident = bool(ssids_lower & TRUE_RESIDENT_NETS)

            if probed_unifi and not probed_true_resident:
                print(f"  Re-tagging {device.mac} (probes: {ssids_lower}) → neighbor")
                tag.category = "neighbor"
                tag.notes = "Probes Unifi 2.4 - neighbor network"
                tag.tagged_by = "auto_probe"
                tag.tagged_at = datetime.now(timezone.utc)
                affected_device_ids.append(device.id)

        session.commit()

        # --- Step 2: specific MAC overrides ---
        for mac_upper, overrides in SPECIFIC_OVERRIDES.items():
            device = (
                session.query(Device)
                .filter(Device.mac.ilike(mac_upper))
                .first()
            )
            if not device:
                print(f"  WARN: {mac_upper} not found in DB, skipping")
                continue

            tag = session.query(Tag).filter(Tag.device_id == device.id).first()
            if not tag:
                tag = Tag(device_id=device.id)
                session.add(tag)

            tag.category = overrides["category"]
            if overrides.get("label") is not None:
                tag.label = overrides["label"]
            tag.notes = overrides["notes"]
            tag.tagged_by = "user"
            tag.tagged_at = datetime.now(timezone.utc)
            affected_device_ids.append(device.id)
            print(f"  Override {mac_upper} → {overrides['category']} ({overrides['notes']})")

        session.commit()

    finally:
        session.close()

    # --- Step 3: re-run auto_tag_by_probes on all unknown devices ---
    # (This won't change the devices we just manually fixed since they're no
    # longer 'unknown', but it picks up anything that was stuck.)
    session2 = get_session()
    try:
        all_ids = [row[0] for row in session2.query(Device.id).all()]
    finally:
        session2.close()

    retagged = 0
    for did in all_ids:
        if auto_tag_by_probes(did):
            retagged += 1

    print(f"\nDone.")
    print(f"  Corrected auto_probe/resident → neighbor: devices in step 1")
    print(f"  Specific overrides applied: {len(SPECIFIC_OVERRIDES)}")
    print(f"  auto_tag_by_probes newly tagged (unknowns): {retagged}")


if __name__ == "__main__":
    main()
