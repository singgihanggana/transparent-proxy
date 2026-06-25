#!/bin/sh
set -eu

REDIRECT_PORT="${REDIRECT_PORT:-12345}"
UPSTREAM_PROXY="${UPSTREAM_PROXY:-http://proxy:3128}"
DIRECT_DOMAINS="${DIRECT_DOMAINS:-}"
SO_MARK="${SO_MARK:-100}"

if [ "$SO_MARK" = "0" ] || [ "$SO_MARK" = "0x0" ] || [ "$SO_MARK" = "0X0" ]; then
  echo "transparent-proxy: SO_MARK must be non-zero; it is required to keep proxy egress out of the REDIRECT loop" >&2
  exit 1
fi

# Exclude: localhost, Docker/private ranges, redirect port, and marked egress.
# Marked egress is used by GOST and by the embedded router for DIRECT sockets so
# router traffic does not loop back into this transparent REDIRECT chain.
iptables -t nat -N GOST 2>/dev/null || iptables -t nat -F GOST
iptables -t nat -A GOST -d 127.0.0.0/8 -j RETURN
iptables -t nat -A GOST -d 172.16.0.0/12 -j RETURN
iptables -t nat -A GOST -d 10.0.0.0/8 -j RETURN
iptables -t nat -A GOST -d 192.168.0.0/16 -j RETURN
iptables -t nat -A GOST -p tcp --dport "$REDIRECT_PORT" -j RETURN
iptables -t nat -A GOST -p tcp -m mark --mark "$SO_MARK" -j RETURN
iptables -t nat -A GOST -p tcp -j REDIRECT --to-ports "$REDIRECT_PORT"
iptables -t nat -A OUTPUT -p tcp -j GOST

if [ -n "$DIRECT_DOMAINS" ]; then
  echo "transparent-proxy: domain routing enabled; direct domains=$DIRECT_DOMAINS" >&2
  export UPSTREAM_PROXY DIRECT_DOMAINS REDIRECT_PORT SO_MARK
  # The embedded router is the transparent listener in routing mode. It reads
  # SO_ORIGINAL_DST, sniffs TLS SNI/HTTP Host, and then chooses DIRECT or
  # UPSTREAM_PROXY. This avoids GOST's red listener losing the hostname before
  # policy routing.
  exec python3 /router_proxy.py
fi

# Backward-compatible path: no routing rules configured, behave exactly like the
# original transparent-proxy image.
echo "transparent-proxy: domain routing disabled; forwarding all traffic to UPSTREAM_PROXY" >&2
exec /bin/gost -L "red://:${REDIRECT_PORT}?sniffing=true&so_mark=${SO_MARK}" -F "${UPSTREAM_PROXY}?so_mark=${SO_MARK}"
