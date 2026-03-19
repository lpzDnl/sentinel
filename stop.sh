#!/bin/bash
# SENTINEL - Stop all services
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVICES=(sentinel-wifi sentinel-bt sentinel-sdr sentinel-frigate sentinel-web)

echo -e "${RED}=== SENTINEL Stopping ===${NC}"

# Stop all services
for svc in "${SERVICES[@]}"; do
    echo -n -e "Stopping ${svc}... "
    if systemctl stop "$svc" 2>/dev/null; then
        echo -e "${GREEN}stopped${NC}"
    else
        echo -e "${YELLOW}not running${NC}"
    fi
done

# Optionally stop monitor mode
if [[ "$1" == "--mon-off" ]]; then
    if ip link show wlan1mon &>/dev/null; then
        echo -e "${YELLOW}[..]${NC} Stopping monitor mode..."
        airmon-ng stop wlan1mon
        echo -e "${GREEN}[OK]${NC} Monitor mode disabled"
    else
        echo -e "${YELLOW}[--]${NC} wlan1mon not found, nothing to stop"
    fi
fi

echo ""
echo -e "${GREEN}=== All services stopped ===${NC}"
