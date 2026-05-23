# Build WireGuard custom image for GHCR deployment
FROM lscr.io/linuxserver/wireguard:latest

# This ensures we use the official LinuxServer WireGuard base, but can
# extend it later with custom scripts, health-checks, or routing tables.
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"
LABEL org.opencontainers.image.description="Gaming Optimized WireGuard VPN"

# 1. Install dependencies (Python 3, Flask, and tcpdump)
RUN apk add --no-cache python3 py3-flask tcpdump

# 2. Copy the web monitoring application
COPY strategies/monitor_web.py /app/monitor_web.py

# 3. Hook the monitoring tool as a custom background service managed by s6-overlay
RUN mkdir -p /custom-services.d/vpn-monitor && \
    printf '#!/usr/bin/with-contenv sh\nexec python3 /app/monitor_web.py\n' > /custom-services.d/vpn-monitor/run && \
    chmod +x /custom-services.d/vpn-monitor/run

