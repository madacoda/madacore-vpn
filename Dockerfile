# Build WireGuard custom image for GHCR deployment
FROM lscr.io/linuxserver/wireguard:latest

# This ensures we use the official LinuxServer WireGuard base, but can
# extend it later with custom scripts, health-checks, or routing tables.
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"
LABEL org.opencontainers.image.description="Gaming Optimized WireGuard VPN"
