# Build WireGuard custom image for GHCR deployment
FROM lscr.io/linuxserver/wireguard:latest

LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"
LABEL org.opencontainers.image.description="Gaming Optimized WireGuard VPN with Multi-Account Management"

# 1. Install dependencies (Python 3, Flask, SQLite3, gunicorn, qrencode, tcpdump)
RUN apk add --no-cache python3 py3-flask py3-gunicorn py3-sqlite3 qrencode tcpdump

# 2. Copy the VPN management engine, CLI, and web monitoring application
COPY strategies/vpn_manager.py /app/vpn_manager.py
COPY strategies/manage_vpn.py /app/manage_vpn.py
COPY strategies/monitor_web.py /app/monitor_web.py

# 3. Hook the monitoring tool as a custom background service managed by s6-overlay
COPY vpn-monitor.sh /custom-services.d/vpn-monitor
RUN chmod +x /custom-services.d/vpn-monitor
