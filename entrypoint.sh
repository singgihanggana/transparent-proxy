#!/bin/sh
set -e
# Exclude: localhost, Docker/private ranges, redirect port, and egress from Gost (mark 100)
iptables -t nat -N GOST 2>/dev/null || iptables -t nat -F GOST
iptables -t nat -A GOST -d 127.0.0.0/8 -j RETURN
iptables -t nat -A GOST -d 172.16.0.0/12 -j RETURN
iptables -t nat -A GOST -d 10.0.0.0/8 -j RETURN
iptables -t nat -A GOST -d 192.168.0.0/16 -j RETURN
iptables -t nat -A GOST -p tcp --dport "${REDIRECT_PORT:-12345}" -j RETURN
iptables -t nat -A GOST -p tcp -m mark --mark 100 -j RETURN
iptables -t nat -A GOST -p tcp -j REDIRECT --to-ports "${REDIRECT_PORT:-12345}"
iptables -t nat -A OUTPUT -p tcp -j GOST
exec /bin/gost -L "red://:${REDIRECT_PORT:-12345}?sniffing=true&so_mark=100" -F "${UPSTREAM_PROXY:-http://proxy:3128}?so_mark=100"
