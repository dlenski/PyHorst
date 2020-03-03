#!/bin/bash

LOGFILE="${1:-/dev/stdout}"
IFACE="${2:-wlan0}"
shift 2

nmcli dev set $IFACE managed no &&
sudo ifconfig $IFACE down &&
sleep 3 &&
sudo horst -i $IFACE -q -s -o "$LOGFILE" "$@" &&
sudo nmcli d set $IFACE managed yes
