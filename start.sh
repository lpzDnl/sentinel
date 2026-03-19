#!/bin/bash
# SENTINEL - Start all services
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVICES=(sentinel-wifi sentinel-bt sentinel-frigate sentinel-web)

echo -e "${GREEN}=== SENTINEL Starting ===${NC}"

# Check/enable monitor mode on wlan1
if ip link show wlan1mon &>/dev/null; then
    echo -e "${GREEN}[OK]${NC} wlan1mon already exists"
else
    echo -e "${YELLOW}[..]${NC} wlan1mon not found, starting monitor mode on wlan1..."
    if ! airmon-ng start wlan1; then
        echo -e "${RED}[FAIL]${NC} Failed to start monitor mode on wlan1"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Monitor mode enabled"
fi

# Start all services
for svc in "${SERVICES[@]}"; do
    echo -n -e "Starting ${svc}... "
    if systemctl start "$svc"; then
        echo -e "${GREEN}started${NC}"
    else
        echo -e "${RED}failed${NC}"
    fi
done

echo ""
echo -e "${GREEN}=== Service Status ===${NC}"
systemctl status --no-pager "${SERVICES[@]}" 2>&1 | grep -E '●|Active:|$'
