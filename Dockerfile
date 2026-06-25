# Transparent proxy: redirect TCP to Gost, optionally route selected domains direct.
# Containers that use network_mode: service:proxy-transparent need no proxy config.
FROM gogost/gost:latest
USER root
RUN apk add --no-cache iptables python3 ca-certificates
COPY entrypoint.sh /entrypoint.sh
COPY router_proxy.py /router_proxy.py
RUN chmod +x /entrypoint.sh /router_proxy.py
ENV REDIRECT_PORT=12345
ENV UPSTREAM_PROXY=http://proxy:3128
ENV DIRECT_DOMAINS=""
ENV SO_MARK=100
ENTRYPOINT ["/entrypoint.sh"]
