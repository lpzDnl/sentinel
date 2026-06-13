#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVICES=(sentinel-wifi sentinel-bt sentinel-sdr sentinel-frigate sentinel-web)

case "$1" in
  start)
    sudo /opt/sentinel/start.sh
    ;;
  stop)
    sudo /opt/sentinel/stop.sh
    ;;
  restart)
    sudo /opt/sentinel/stop.sh
    sleep 2
    sudo /opt/sentinel/start.sh
    ;;
  status)
    echo -e "${GREEN}=== SENTINEL Status ===${NC}"
    for svc in "${SERVICES[@]}"; do
      state=$(systemctl is-active "$svc")
      case "$state" in
        active)   echo -e "${GREEN}[OK]${NC}   $svc" ;;
        failed)   echo -e "${RED}[FAIL]${NC} $svc" ;;
        *)        echo -e "${YELLOW}[??]${NC}  $svc ($state)" ;;
      esac
    done
    ;;
  *)
    echo "Usage: sentinel {start|stop|restart|status}"
    exit 1
    ;;
esac
