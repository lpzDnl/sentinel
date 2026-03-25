#!/usr/bin/env python3
"""SENTINEL Daily Intelligence Digest — sends Telegram summary at 7am El Paso."""
import sqlite3
import httpx
import asyncio
from datetime import datetime, timedelta, timezone

DB = "/opt/sentinel/data/sentinel.db"
TOKEN = "8488678386:AAElrGuQsx6JkpFXAd_-cQgprLhS1FeRbyY"
CHAT_ID = "1200389130"

def get_data():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

    stats = conn.execute("""
        SELECT 
            (SELECT COUNT(*) FROM alert_log WHERE timestamp >= ?) as alerts_24h,
            (SELECT COUNT(*) FROM alert_log WHERE timestamp >= ? AND alert_type LIKE 'red:%') as red_alerts,
            (SELECT COUNT(*) FROM alert_log WHERE timestamp >= ? AND alert_type LIKE 'yellow:%') as yellow_alerts,
            (SELECT COUNT(*) FROM devices WHERE first_seen >= ?) as new_devices,
            (SELECT COUNT(DISTINCT device_id) FROM visits WHERE arrived_at >= ?) as active_devices
    """, (since, since, since, since, since)).fetchone()

    red_alerts = conn.execute("""
        SELECT a.alert_type, a.timestamp, a.message, d.vendor, d.mac
        FROM alert_log a
        LEFT JOIN devices d ON d.id = a.device_id
        WHERE a.timestamp >= ? AND a.alert_type LIKE 'red:%'
        ORDER BY a.timestamp DESC LIMIT 5
    """, (since,)).fetchall()

    yellow_alerts = conn.execute("""
        SELECT a.alert_type, a.timestamp, a.message
        FROM alert_log a
        WHERE a.timestamp >= ? AND a.alert_type LIKE 'yellow:%'
        ORDER BY a.timestamp DESC LIMIT 5
    """, (since,)).fetchall()

    new_devices = conn.execute("""
        SELECT d.mac, d.vendor, d.device_type, d.first_seen
        FROM devices d
        WHERE d.first_seen >= ?
        AND d.vendor IS NOT NULL
        ORDER BY d.first_seen DESC LIMIT 5
    """, (since,)).fetchall()

    # Recurring TPMS vehicles
    vehicles = conn.execute("""
        SELECT model, COUNT(*) as count
        FROM sdr_signals
        WHERE timestamp >= ? AND protocol IN (73,88,186,89,168,82,95,156,60,90,201)
        GROUP BY model
        ORDER BY count DESC LIMIT 5
    """, (since,)).fetchall()

    conn.close()
    return stats, red_alerts, yellow_alerts, new_devices, vehicles

async def send(message):
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10
        )
        print(f"Status: {r.status_code}")

async def main():
    stats, red_alerts, yellow_alerts, new_devices, vehicles = get_data()
    
    lines = ["👁️ <b>SENTINEL DAILY DIGEST</b>"]
    lines.append(f"📅 {datetime.now().strftime('%Y-%m-%d')} · El Paso 07:00\n")
    
    lines.append("📊 <b>OVERVIEW (24h)</b>")
    lines.append(f"Total alerts: {stats['alerts_24h']}")
    lines.append(f"🔴 Red: {stats['red_alerts']} · 🟡 Yellow: {stats['yellow_alerts']}")
    lines.append(f"New devices: {stats['new_devices']}")
    lines.append(f"Active devices: {stats['active_devices']}\n")

    if red_alerts:
        lines.append("🔴 <b>RED ALERTS</b>")
        for a in red_alerts:
            ts = str(a['timestamp'])[:16]
            lines.append(f"• {ts} — {a['alert_type']} {a['vendor'] or a['mac'] or ''}")
        lines.append("")

    if yellow_alerts:
        lines.append("🟡 <b>YELLOW ALERTS</b>")
        for a in list(yellow_alerts)[:3]:
            ts = str(a['timestamp'])[:16]
            lines.append(f"• {ts} — {a['alert_type']}")
        lines.append("")

    if new_devices:
        lines.append("📡 <b>NEW DEVICES</b>")
        for d in new_devices:
            lines.append(f"• {d['vendor']} [{d['device_type']}]")
        lines.append("")

    if vehicles:
        lines.append("🚗 <b>VEHICLES DETECTED</b>")
        for v in vehicles:
            lines.append(f"• {v['model']} ×{v['count']}")

    await send("\n".join(lines))

asyncio.run(main())
