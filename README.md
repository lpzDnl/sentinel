# S.E.N.T.I.N.E.L.
### Surveillance Environment Network Threat Intelligence & Evidence Logger

> *"Know your environment before your environment knows you."*

SENTINEL is a modular, self-hosted physical security intelligence platform built on a Raspberry Pi 5. It passively monitors the RF environment, detects and tracks nearby devices via WiFi and Bluetooth, integrates with IP camera systems, correlates signals across sensors, and presents actionable intelligence through a real-time web dashboard — all locally, with no cloud dependencies.

This is not a passive logger. SENTINEL is designed to **detect anomalies**, **correlate events across sensors**, and **alert on suspicious behavior** — the difference between collecting data and understanding your environment.

> *Old neighborhood watch: neighbors with eyes, walkie talkies, a phone tree.*
> *SENTINEL: passive RF sensors, computer vision, behavioral fingerprinting, correlated intelligence, automated alerts.*
> *Same mission. 100 years of technology difference.*

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        SENTINEL                             │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   WiFi   │  │Bluetooth │  │   SDR    │  │ Frigate  │  │
│  │ Capture  │  │ Scanner  │  │ Capture  │  │Receiver  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       └──────────────┴──────────────┴──────────────┘        │
│                              │                               │
│                     ┌────────▼────────┐                     │
│                     │   SQLite DB     │                     │
│                     │  + Correlation  │                     │
│                     │    Engine       │                     │
│                     └────────┬────────┘                     │
│                              │                               │
│                ┌─────────────┴──────────────┐               │
│                │                            │               │
│         ┌──────▼──────┐            ┌────────▼──────┐       │
│         │   Alerter   │            │  Web Dashboard │       │
│         │  (Telegram) │            │  Flask+Socket  │       │
│         └─────────────┘            └───────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

---

## Modules

### WiFi Capture (`capture/wifi_capture.py`)
Passive 802.11 monitor mode capture using a dedicated wireless adapter (Alfa AWUS036ACH). Captures probe requests, beacon frames, and association events. Tracks device MAC addresses, SSID history, signal strength, and first/last seen timestamps. Detects:
- New devices appearing in range
- Known devices returning
- Devices probing for specific networks
- Deauth/disassociation events

### Bluetooth Scanner (`capture/bt_scanner.py`)
Continuous BLE and classic Bluetooth scanning. Tracks device addresses, names, RSSI, and manufacturer data. Identifies device types from manufacturer codes. Detects:
- New Bluetooth devices in range
- AirTags and other tracking devices
- Unusual BLE advertisement patterns

### SDR Capture (`capture/sdr_capture.py`)
RTL-SDR powered RF signal capture using rtl_433 with a discone antenna. Decodes signals on 433MHz, 315MHz, and configurable frequencies. Classifies signals by type:
- **TPMS** — tire pressure sensors (vehicle tracking)
- **Keyfob** — remote entry devices
- **Security** — alarm system sensors
- **Power** — smart meters, power monitors
- **Weather** — environmental sensors
- **Other** — unclassified RF activity

Tracks unique devices by model/ID, logs RSSI/SNR, and flags unusual signal patterns.

### Frigate Receiver (`analysis/frigate_receiver.py`)
Webhook integration with Frigate NVR. Receives real-time object detection events — persons, vehicles, and other tracked objects — from IP cameras. Correlates camera detections with RF/WiFi/BT events for multi-sensor situational awareness.

### Correlation Engine (`analysis/correlation.py`)
The intelligence layer. Cross-references events across all sensors to detect patterns that no single sensor would catch:
- Person detected on camera + new WiFi probe request → probable device association
- Vehicle detected + TPMS signal → vehicle identification
- New BT device + camera event in same time window → physical presence correlation
- Repeated probe requests for specific SSID → targeted surveillance indicator

### Alerter (`analysis/alerter.py`)
Telegram-based alerting with configurable rules and thresholds. Sends structured alerts for:
- New unknown devices detected
- Correlated multi-sensor events
- Anomalies vs. established baselines
- Configurable quiet hours and severity levels

### Web Dashboard (`web/app.py`)
Real-time Flask + SocketIO web interface. Features:
- Live device map and event feed
- Per-sensor device lists with history
- Timeline view of correlated events
- Baseline management (known vs. unknown devices)
- Alert log and acknowledgment
- Mobile-responsive dark theme layout

---

## Hardware

| Component | Purpose |
|-----------|---------|
| Raspberry Pi 5 (16GB) | Primary compute |
| Alfa AWUS036ACH | WiFi monitor mode (802.11 a/b/g/n/ac) |
| RTL-SDR R820T + Discone Antenna | Wideband RF capture (433/315MHz+) |
| Built-in BT adapter | Bluetooth scanning |

---

## Stack

- **Python 3** — all capture and analysis modules
- **SQLAlchemy + SQLite** — local persistent storage
- **Flask + Flask-SocketIO** — web dashboard
- **rtl_433** — RF signal decoding
- **Scapy** — WiFi packet capture
- **BlueZ** — Bluetooth scanning
- **Telegram Bot API** — alerting
- **systemd** — service management

---

## Services

Each module runs as an independent systemd service:

```
sentinel-wifi.service     — WiFi passive capture
sentinel-bt.service       — Bluetooth scanning
sentinel-sdr.service      — SDR/RF capture
sentinel-frigate.service  — Frigate NVR webhook receiver
sentinel-web.service      — Web dashboard
```

Start/stop all:
```bash
sudo /opt/sentinel/start.sh
sudo /opt/sentinel/stop.sh
```

---

## Installation

### Prerequisites
```bash
# System packages
sudo apt install python3-pip rtl-433 aircrack-ng bluez

# Python dependencies
pip3 install flask flask-socketio sqlalchemy scapy telegram
```

### Configuration
```bash
cp config.yaml.example config.yaml
# Edit config.yaml:
# - Set Telegram bot token and chat ID
# - Configure Frigate host/port
# - Set WiFi monitor interface (default: wlan1mon)
# - Set RTL-SDR device index and frequencies
```

### Deploy services
```bash
sudo cp services/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sentinel-wifi sentinel-bt sentinel-sdr sentinel-frigate sentinel-web
sudo /opt/sentinel/start.sh
```

### Access dashboard
```
http://<pi-ip>:8080
```

---

## Security Notes

- All data stays local — no cloud, no external dependencies beyond Telegram alerts
- Web UI has no authentication by default — deploy behind VPN or add auth for production
- WiFi capture requires monitor mode — dedicated adapter strongly recommended to avoid disrupting primary network connection
- SDR capture is passive receive-only — no transmission

---

## Project Context

SENTINEL is part of a broader homelab security stack:

- **B.A.N.S.H.E.E.** — Behavioral Analysis Network for Security & Hostile Entity Examination — SSH honeypot with attacker profiling and MITRE ATT&CK mapping
- **P.E.N.E.L.O.P.E.** — SSH threat intelligence dashboard with Telegram morning briefings
- **W.R.A.I.T.H.** — Wireless Reconnaissance and Intrusion Threat Hunter — TSCM/counter-surveillance RF platform
- **Nightshade** — Blue-light filter for Kali/XFCE on Raspberry Pi

---

## Status

Active development. Core modules operational:
- [x] WiFi capture
- [x] Bluetooth scanning
- [x] SDR/RF capture
- [x] Frigate integration
- [x] Correlation engine
- [x] Telegram alerting
- [x] Web dashboard
- [ ] Authentication layer
- [ ] Baseline auto-learning
- [ ] Mobile app
