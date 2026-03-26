#!/usr/bin/env python3
"""SENTINEL Terminal TUI.

A full-screen rich terminal dashboard that refreshes every 3 seconds.
Shows the same intelligence as the web ops page: active devices, recent
events, alerts, SDR signals, service health, and threat band.

Usage:
    python3 /opt/sentinel/tools/tui.py
    python3 /opt/sentinel/tools/tui.py --once        # render once and exit
    python3 /opt/sentinel/tools/tui.py --interval 5  # refresh every N seconds
"""

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/opt/sentinel")

import config
import subprocess
from database import (
    AlertLog,
    Device,
    DroneIdEvent,
    Event,
    SdrSignal,
    Tag,
    Visit,
    get_session,
)
from sqlalchemy import func

try:
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.padding import Padding
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("ERROR: rich is required — pip3 install rich")
    sys.exit(1)


import re as _re

# ---------------------------------------------------------------------------
# Colour palette (matches web theme)
# ---------------------------------------------------------------------------
AMBER  = "#e6a817"
GREEN  = "#3fb950"
RED    = "#f85149"
BLUE   = "#58a6ff"
MUTED  = "#6e7681"
TEXT   = "#c9d1d9"
DIM    = "#484f58"
PURPLE = "#bc8cff"


# ---------------------------------------------------------------------------
# Data fetch helpers
# ---------------------------------------------------------------------------

def _tz() -> timezone:
    """Return America/Denver as a fixed-offset timezone (UTC-6 or -7)."""
    try:
        import zoneinfo
        from datetime import datetime as _dt
        zi = zoneinfo.ZoneInfo("America/Denver")
        now_local = _dt.now(zi)
        return now_local.tzinfo
    except Exception:
        return timezone(timedelta(hours=-6))


def fetch_stats() -> dict:
    """Fetch all data needed to render the TUI."""
    session = get_session()
    try:
        now     = datetime.now(timezone.utc)
        cut10   = now - timedelta(minutes=10)
        cut24   = now - timedelta(hours=24)
        cut1h   = now - timedelta(hours=1)
        cut2h   = now - timedelta(hours=2)

        # ── Counters ──
        active   = session.query(func.count(Device.id)).filter(Device.last_seen >= cut10).scalar() or 0
        total    = session.query(func.count(Device.id)).scalar() or 0
        open_v   = session.query(func.count(Visit.id)).filter(Visit.departed_at.is_(None)).scalar() or 0
        alerts24 = session.query(func.count(AlertLog.id)).filter(AlertLog.timestamp >= cut24).scalar() or 0
        red24    = session.query(func.count(AlertLog.id)).filter(
            AlertLog.timestamp >= cut24,
            AlertLog.alert_type.startswith("red:")
        ).scalar() or 0

        # ── Recent events (last 12) ──
        evt_rows = (
            session.query(Event, Device, Tag)
            .outerjoin(Device, Event.device_id == Device.id)
            .outerjoin(Tag, Device.id == Tag.device_id)
            .order_by(Event.id.desc())
            .limit(12)
            .all()
        )
        events = []
        for evt, dev, tag in evt_rows:
            events.append({
                "ts":       evt.timestamp,
                "type":     evt.event_type,
                "mac":      dev.mac if dev else "—",
                "vendor":   (dev.vendor or "")[:22] if dev else "",
                "alias":    (dev.alias or "")[:18] if dev else "",
                "tag_cat":  tag.category if tag else None,
            })

        # ── Recent alerts (last 8) ──
        al_rows = (
            session.query(AlertLog, Device)
            .outerjoin(Device, AlertLog.device_id == Device.id)
            .filter(AlertLog.timestamp >= cut24)
            .order_by(AlertLog.id.desc())
            .limit(8)
            .all()
        )
        alerts = []
        for al, dev in al_rows:
            parts = al.alert_type.split(":", 1) if al.alert_type else ["?", "?"]
            alerts.append({
                "ts":      al.timestamp,
                "level":   parts[0],
                "type":    parts[1] if len(parts) > 1 else parts[0],
                "mac":     dev.mac if dev else "—",
                "msg":     _strip_html(al.message or "")[:60],
            })

        # ── Recent SDR signals (last 8) ──
        sdr_rows = (
            session.query(SdrSignal)
            .order_by(SdrSignal.id.desc())
            .limit(8)
            .all()
        )
        sdr = []
        for s in sdr_rows:
            sdr.append({
                "ts":    s.timestamp,
                "class": s.signal_class,
                "model": (s.model or "")[:24],
                "uid":   (s.device_uid or "")[:22],
                "rssi":  s.rssi,
                "freq":  s.frequency,
            })

        # ── Threat band: RED/YELLOW in last 2h ──
        threat_rows = (
            session.query(AlertLog, Device)
            .outerjoin(Device, AlertLog.device_id == Device.id)
            .filter(
                AlertLog.timestamp >= cut2h,
                (AlertLog.alert_type.startswith("red:"))
                | (AlertLog.alert_type.startswith("yellow:")),
            )
            .order_by(AlertLog.id.desc())
            .limit(6)
            .all()
        )
        threats = []
        for al, dev in threat_rows:
            parts = al.alert_type.split(":", 1) if al.alert_type else ["?", "?"]
            threats.append({
                "ts":    al.timestamp,
                "level": parts[0],
                "type":  parts[1] if len(parts) > 1 else parts[0],
                "mac":   dev.mac if dev else "—",
                "msg":   _strip_html(al.message or "")[:55],
            })

        # ── Recent arrivals (last 6) ──
        arr_rows = (
            session.query(Event, Device, Tag)
            .outerjoin(Device, Event.device_id == Device.id)
            .outerjoin(Tag, Device.id == Tag.device_id)
            .filter(Event.event_type == "arrival")
            .order_by(Event.id.desc())
            .limit(6)
            .all()
        )
        arrivals = []
        for ev, dev, tag in arr_rows:
            arrivals.append({
                "ts":      ev.timestamp,
                "mac":     dev.mac if dev else "—",
                "vendor":  (dev.vendor or "")[:20] if dev else "",
                "alias":   (dev.alias or "")[:16] if dev else "",
                "tag_cat": tag.category if tag else None,
            })

        # ── Hourly pulse (last 24h, grouped to 6 buckets for sparkline) ──
        pulse = []
        for i in range(24):
            h_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23 - i)
            h_end   = h_start + timedelta(hours=1)
            cnt = session.query(func.count(Event.id)).filter(
                Event.timestamp.between(h_start, h_end)
            ).scalar() or 0
            pulse.append(cnt)

        return {
            "now":      now,
            "active":   active,
            "total":    total,
            "open_v":   open_v,
            "alerts24": alerts24,
            "red24":    red24,
            "events":   events,
            "alerts":   alerts,
            "sdr":      sdr,
            "threats":  threats,
            "arrivals": arrivals,
            "pulse":    pulse,
        }
    finally:
        session.close()


def fetch_services() -> dict[str, str]:
    """Return {service_name: active|inactive|failed|unknown}."""
    services = [
        "sentinel-wifi",
        "sentinel-bt",
        "sentinel-sdr",
        "sentinel-frigate",
        "sentinel-droneid",
        "sentinel-web",
        "sentinel-digest",
    ]
    result = {}
    for svc in services:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=3
            )
            result[svc] = r.stdout.strip() or "unknown"
        except Exception:
            result[svc] = "unknown"
    return result


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

_BARS = " ▁▂▃▄▅▆▇█"

def _sparkline(values: list[int], width: int = 24) -> str:
    """Render a Unicode block sparkline from a list of counts."""
    if not values:
        return " " * width
    # Downsample or pad to `width` columns
    if len(values) > width:
        step = len(values) / width
        values = [values[int(i * step)] for i in range(width)]
    elif len(values) < width:
        values = [0] * (width - len(values)) + list(values)

    mx = max(values) or 1
    return "".join(_BARS[min(int(v / mx * 8), 8)] for v in values)


def _strip_html(s: str) -> str:
    """Remove HTML tags, decode entities, strip emoji."""
    s = _re.sub(r"<[^>]+>", "", s)
    s = s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&nbsp;", " ")
    # Strip emoji/non-ASCII symbols that confuse terminal width calculation
    s = _re.sub(r"[^\x00-\x7F]+", "", s)
    return s.strip()


def _ts_local(dt: datetime | None, tz, short: bool = False) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(tz)
    if short:
        return local.strftime("%H:%M")
    return local.strftime("%H:%M:%S")


def _ago(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = (datetime.now(timezone.utc) - dt).total_seconds()
    if diff < 60:
        return f"{int(diff)}s ago"
    if diff < 3600:
        return f"{int(diff/60)}m ago"
    if diff < 86400:
        return f"{int(diff/3600)}h ago"
    return f"{int(diff/86400)}d ago"


def _level_color(level: str) -> str:
    if level == "red":
        return RED
    if level == "yellow":
        return AMBER
    if level == "green":
        return GREEN
    return MUTED


def _evt_color(evt_type: str) -> str:
    if evt_type in ("wifi_arrival", "bt_arrival"):
        return GREEN
    if evt_type in ("wifi_departure", "bt_departure"):
        return RED
    if evt_type == "wifi_probe":
        return BLUE
    return MUTED


def _tag_color(cat: str | None) -> str:
    if cat == "resident":
        return GREEN
    if cat in ("flagged", "threat"):
        return RED
    if cat == "neighbor":
        return BLUE
    return MUTED


def _sdr_class_color(cls: str) -> str:
    if cls == "tpms":
        return BLUE
    if cls == "keyfob":
        return AMBER
    if cls == "weather":
        return GREEN
    if cls == "security":
        return RED
    return MUTED


def _svc_label(state: str) -> Text:
    if state == "active":
        return Text("● ACTIVE", style=f"bold {GREEN}")
    if state in ("inactive", "failed"):
        return Text("● DOWN", style=f"bold {RED}")
    return Text("● ——", style=MUTED)


# ---------------------------------------------------------------------------
# Layout builders
# ---------------------------------------------------------------------------

def build_header(data: dict, tz) -> Panel:
    now_local = data["now"].astimezone(tz)
    time_str  = now_local.strftime("%H:%M:%S")
    date_str  = now_local.strftime("%Y-%m-%d %Z")

    color = RED if data["red24"] > 0 else AMBER if data["alerts24"] > 0 else GREEN

    # Single line: brand + time + key stats
    t = Text(overflow="crop", no_wrap=True)
    t.append("S.E.N.T.I.N.E.L.", style=f"bold {AMBER}")
    t.append(f"  {time_str}", style=f"bold {TEXT}")
    t.append(f"  {date_str}  ", style=MUTED)
    t.append(f"{data['active']} ", style=f"bold {GREEN}")
    t.append("active  ", style=MUTED)
    t.append(f"{data['open_v']} ", style=f"bold {AMBER}")
    t.append("visits  ", style=MUTED)
    t.append(f"{data['alerts24']} ", style=f"bold {color}")
    t.append("alerts  ", style=MUTED)
    t.append(f"{data['red24']} ", style=f"bold {RED}")
    t.append("red  ", style=MUTED)
    t.append(f"{data['total']} ", style=f"bold {TEXT}")
    t.append("total", style=MUTED)

    return Panel(t, style="on #080c10", border_style=AMBER, padding=(0, 1))


def build_services(services: dict[str, str]) -> Panel:
    """Compact single-line services bar."""
    parts: list[Text] = []
    for svc, state in services.items():
        short = svc.replace("sentinel-", "").upper()
        color = GREEN if state == "active" else (RED if state in ("inactive", "failed") else MUTED)
        t = Text()
        t.append("● ", style=color)
        t.append(short, style=f"bold {TEXT}")
        t.append(f" {state}  ", style=color)
        parts.append(t)

    row = Text()
    for p in parts:
        row.append_text(p)

    return Panel(row, title="[bold]SERVICES[/bold]", border_style=DIM, padding=(0, 1))


def build_events(data: dict, tz) -> Panel:
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {MUTED}",
        expand=True,
        padding=(0, 0),
    )
    t.add_column("TIME",   width=6,  style=MUTED, no_wrap=True)
    t.add_column("TYPE",   width=10, no_wrap=True)
    t.add_column("MAC",    width=14, style=MUTED, no_wrap=True)
    t.add_column("AGO",    width=6,  style=MUTED, no_wrap=True)

    for e in data["events"]:
        et   = e["type"] or ""
        col  = _evt_color(et)
        label = e["alias"] if e["alias"] else ""
        type_str = et.replace("_", " ").upper()[:10]
        mac_disp = e["mac"][:14] if e["mac"] else "—"
        t.add_row(
            _ts_local(e["ts"], tz, short=True),
            Text(type_str, style=f"bold {col}"),
            Text(mac_disp, style=MUTED),
            _ago(e["ts"]),
        )

    return Panel(t, title="[bold]RECENT EVENTS[/bold]", border_style=DIM, padding=(0, 0))


def build_alerts(data: dict, tz) -> Panel:
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {MUTED}",
        expand=True,
        padding=(0, 0),
    )
    t.add_column("TIME",    width=6,  style=MUTED, no_wrap=True)
    t.add_column("TYPE",    width=18, no_wrap=True)
    t.add_column("MESSAGE", overflow="fold")

    if not data["alerts"]:
        t.add_row("—", "—", Text("No alerts in last 24h", style=MUTED))
    else:
        for a in data["alerts"]:
            col = _level_color(a["level"])
            # Limit message to first line to avoid multi-line rows
            msg = a["msg"].split("\n")[0][:30]
            t.add_row(
                _ts_local(a["ts"], tz, short=True),
                Text(a["type"][:18], style=f"bold {col}"),
                Text(msg, style=MUTED),
            )

    return Panel(t, title="[bold]ALERTS — LAST 24H[/bold]", border_style=DIM, padding=(0, 0))


def build_sdr(data: dict, tz) -> Panel:
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {MUTED}",
        expand=True,
        padding=(0, 0),
    )
    # Narrow panel (~29 chars content): CLASS + MODEL only
    t.add_column("AGO",    width=6,  style=MUTED, no_wrap=True)
    t.add_column("CLASS",  width=7,  no_wrap=True)
    t.add_column("MODEL",  min_width=12, no_wrap=True)

    if not data["sdr"]:
        t.add_row("—", "—", Text("No SDR signals", style=MUTED))
    else:
        for s in data["sdr"]:
            col = _sdr_class_color(s["class"] or "")
            t.add_row(
                _ago(s["ts"]),
                Text((s["class"] or "—").upper()[:7], style=f"bold {col}"),
                Text(s["model"][:18], style=TEXT),
            )

    return Panel(t, title="[bold]SDR SIGNALS[/bold]", border_style=DIM, padding=(0, 0))


def build_arrivals(data: dict, tz) -> Panel:
    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {MUTED}",
        expand=True,
        padding=(0, 0),
    )
    t.add_column("TIME",    width=6,  style=MUTED, no_wrap=True)
    t.add_column("MAC",     width=13, style=MUTED, no_wrap=True)
    t.add_column("AGO",     width=6,  style=MUTED, no_wrap=True)

    if not data["arrivals"]:
        t.add_row("—", "—", Text("No arrivals yet", style=MUTED))
    else:
        for a in data["arrivals"]:
            t.add_row(
                _ts_local(a["ts"], tz, short=True),
                a["mac"][:13] if a["mac"] else "—",
                _ago(a["ts"]),
            )

    return Panel(t, title="[bold]RECENT ARRIVALS[/bold]", border_style=DIM, padding=(0, 0))


def build_threats(data: dict, tz) -> Panel:
    if not data["threats"]:
        content = Text("  No active threats in the last 2 hours", style=GREEN)
        return Panel(content, title="[bold]THREAT BAND — 2H[/bold]", border_style=GREEN, padding=(0, 1))

    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {MUTED}",
        expand=True,
        padding=(0, 0),
    )
    t.add_column("TIME",  width=6,  style=MUTED, no_wrap=True)
    t.add_column("LVL",   width=5,  no_wrap=True)
    t.add_column("TYPE",  width=18, no_wrap=True)
    t.add_column("MAC",   width=14, style=MUTED, no_wrap=True)
    t.add_column("MESSAGE", min_width=14, overflow="fold")

    for th in data["threats"]:
        col = _level_color(th["level"])
        # First line only, no HTML
        msg = th["msg"].split("\n")[0][:50]
        t.add_row(
            _ts_local(th["ts"], tz, short=True),
            Text(th["level"].upper(), style=f"bold {col}"),
            Text(th["type"][:18], style=col),
            th["mac"][:14] if th["mac"] else "—",
            Text(msg, style=MUTED),
        )

    border = RED if any(th["level"] == "red" for th in data["threats"]) else AMBER
    return Panel(t, title="[bold]THREAT BAND — 2H[/bold]", border_style=border, padding=(0, 0))


def build_pulse(data: dict) -> Panel:
    pulse  = data["pulse"]
    spark  = _sparkline(pulse, width=48)
    mx     = max(pulse) if pulse else 0
    total  = sum(pulse)

    t = Text()
    t.append("  24H ACTIVITY  ", style=f"bold {MUTED}")
    t.append(spark, style=AMBER)
    t.append(f"  peak={mx}  total={total}", style=MUTED)

    return Panel(t, border_style=DIM, padding=(0, 0))


def build_footer(data: dict) -> Text:
    t = Text()
    t.append("  [q] quit", style=MUTED)
    t.append("  [r] refresh now", style=MUTED)
    t.append("  auto-refresh every 3s  ", style=MUTED)
    t.append("web: http://localhost:8080", style=f"{BLUE}")
    t.append("  last update: ", style=MUTED)
    tz = _tz()
    local = data["now"].astimezone(tz)
    t.append(local.strftime("%H:%M:%S %Z"), style=TEXT)
    return t


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------

def render(console: Console, data: dict, services: dict[str, str]) -> Layout:
    tz = _tz()
    term_h = console.size.height

    # Fixed layout: 3+3+6+9+9+3+1 = 34 lines minimum
    # Larger terminals get proportionally more rows in mid/bot
    fixed   = 3 + 3 + 6 + 3 + 1   # = 16 (header+svc+threats+pulse+footer)
    dynamic = max(9, (term_h - fixed) // 2)

    layout = Layout()
    layout.split_column(
        Layout(name="header",  size=3),
        Layout(name="svc",     size=3),
        Layout(name="threats", size=6),
        Layout(name="mid",     size=dynamic),
        Layout(name="bot",     size=dynamic),
        Layout(name="pulse",   size=3),
        Layout(name="footer",  size=1),
    )

    layout["header"].update(build_header(data, tz))
    layout["svc"].update(build_services(services))
    layout["threats"].update(build_threats(data, tz))

    layout["mid"].split_row(
        Layout(name="events",   ratio=3),
        Layout(name="arrivals", ratio=2),
    )
    layout["mid"]["events"].update(build_events(data, tz))
    layout["mid"]["arrivals"].update(build_arrivals(data, tz))

    layout["bot"].split_row(
        Layout(name="alerts", ratio=3),
        Layout(name="sdr",    ratio=2),
    )
    layout["bot"]["alerts"].update(build_alerts(data, tz))
    layout["bot"]["sdr"].update(build_sdr(data, tz))

    layout["pulse"].update(build_pulse(data))
    layout["footer"].update(build_footer(data))

    return layout


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SENTINEL Terminal TUI")
    parser.add_argument("--once",     action="store_true", help="Render once and exit")
    parser.add_argument("--interval", type=float, default=3.0, help="Refresh interval in seconds")
    args = parser.parse_args()

    config.get()

    console = Console()

    if args.once:
        # In --once mode render at unconstrained height for easy inspection
        wide_console = Console(width=120, force_terminal=True)
        data     = fetch_stats()
        services = fetch_services()
        tz = _tz()
        wide_console.print(build_header(data, tz))
        wide_console.print(build_services(services))
        wide_console.print(build_threats(data, tz))
        from rich.columns import Columns as _Columns
        wide_console.print(build_events(data, tz))
        wide_console.print(build_arrivals(data, tz))
        wide_console.print(build_alerts(data, tz))
        wide_console.print(build_sdr(data, tz))
        wide_console.print(build_pulse(data))
        wide_console.print(build_footer(data))
        return

    # Live auto-refresh loop
    try:
        with Live(
            console=console,
            screen=True,
            refresh_per_second=0.5,
            transient=False,
        ) as live:
            last_svc_fetch = 0.0
            services = {}

            while True:
                # Re-fetch services every 15s (slower — subprocess calls)
                now_mono = time.monotonic()
                if now_mono - last_svc_fetch > 15:
                    services = fetch_services()
                    last_svc_fetch = now_mono

                data   = fetch_stats()
                layout = render(console, data, services)
                live.update(layout)

                time.sleep(args.interval)

    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
