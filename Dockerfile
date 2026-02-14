# Transparent proxy: redirect TCP to Gost, forward to upstream HTTP proxy.
# Containers that use network_mode: service:proxy-transparent need no proxy config.
FROM gogost/gost:latest
USER root
RUN apk add --no-cache iptables
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV REDIRECT_PORT=12345
ENV UPSTREAM_PROXY=http://proxy:3128
ENTRYPOINT ["/entrypoint.sh"]
