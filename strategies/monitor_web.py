#!/usr/bin/env python3
"""
MadaCore VPN - Containerized Web Traffic & Quality Monitor
Author: Professional Network Engineer

This script runs inside a sidecar Docker container, communicates with the host
Docker socket, and exposes a beautiful web-based dashboard on port 8080.
"""

import os
import re
import time
import socket
import docker
from flask import Flask, jsonify, render_template_string
from collections import defaultdict

app = Flask(__name__)

# Environment variable configurations
CONTAINER_NAME = os.getenv("WG_CONTAINER_NAME", "gaming-wireguard")
INTERFACE = os.getenv("WG_INTERFACE", "wg0")
PORT = int(os.getenv("MONITOR_PORT", "8080"))

# DNS Resolution Cache
dns_cache = {}

# Metrics Cache to limit Docker exec CPU overhead (limits updates to once every 2 seconds)
metrics_cache = {
    "data": None,
    "last_updated": 0
}

def get_hostname(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        # Resolve target IP address with a strict 0.5s timeout
        socket.setdefaulttimeout(0.5)
        hostname, _, _ = socket.gethostbyaddr(ip)
        dns_cache[ip] = hostname
        return hostname
    except Exception:
        dns_cache[ip] = ip
        return ip

def get_docker_client():
    try:
        # Connects to Docker daemon via mounted /var/run/docker.sock
        return docker.from_env()
    except Exception as e:
        app.logger.error(f"Failed to connect to Docker socket: {e}")
        return None

def ensure_tcpdump(container):
    """
    Checks if tcpdump is available inside the WireGuard container,
    and installs it if missing.
    """
    try:
        exit_code, _ = container.exec_run("which tcpdump")
        if exit_code != 0:
            app.logger.info("tcpdump not found in WireGuard container. Installing...")
            # Try Alpine's apk
            exit_code, _ = container.exec_run("apk add --no-cache tcpdump")
            if exit_code != 0:
                # Try Ubuntu's apt-get
                container.exec_run("apt-get update")
                container.exec_run("apt-get install -y tcpdump")
    except Exception as e:
        app.logger.error(f"Error ensuring tcpdump: {e}")

def fetch_metrics():
    client = get_docker_client()
    if not client:
        return {
            "status": "error",
            "message": "Cannot connect to the host Docker daemon. Ensure '/var/run/docker.sock' is mounted into the monitor container."
        }
    
    try:
        container = client.containers.get(CONTAINER_NAME)
    except Exception:
        return {
            "status": "error",
            "message": f"WireGuard container '{CONTAINER_NAME}' is not running or could not be found."
        }
        
    ensure_tcpdump(container)
    
    # 1. Query WireGuard Interface stats
    exit_code, wg_out = container.exec_run(f"wg show {INTERFACE} dump")
    if exit_code != 0:
        return {
            "status": "error",
            "message": f"Failed to execute 'wg show'. Check if WireGuard interface '{INTERFACE}' exists."
        }
        
    wg_out = wg_out.decode("utf-8", errors="ignore").strip()
    lines = wg_out.split("\n")
    if len(lines) <= 1:
        return {
            "status": "ok",
            "peers": []
        }
        
    peers = []
    # Index 0 is interface info, peers start at index 1
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) >= 8:
            peers.append({
                "pubkey": parts[0],
                "endpoint": parts[2],
                "allowed_ips": parts[3],
                "handshake": int(parts[4]),
                "rx": int(parts[5]),
                "tx": int(parts[6])
            })
            
    # 2. Run tcpdump for 1.5 seconds to calculate current speeds & targets
    capture_duration = 1.5
    exit_code, tcpdump_out = container.exec_run(f"timeout {capture_duration} tcpdump -i {INTERFACE} -n -t -q")
    tcpdump_out = tcpdump_out.decode("utf-8", errors="ignore")
    
    # Map peer traffic: peer_ip -> { target_ip: { 'port': port, 'rx_bytes': X, 'tx_bytes': Y } }
    flows = defaultdict(lambda: defaultdict(lambda: {"port": "", "rx_bytes": 0, "tx_bytes": 0}))
    peer_speeds = defaultdict(lambda: {"rx_bytes": 0, "tx_bytes": 0})
    
    for line in tcpdump_out.split("\n"):
        match = re.search(r"IP\s+([\d\.]+)\.(\d+)\s+>\s+([\d\.]+)\.(\d+):.*length\s+(\d+)", line)
        if match:
            src_ip = match.group(1)
            src_port = match.group(2)
            dst_ip = match.group(3)
            dst_port = match.group(4)
            length = int(match.group(5))
            
            # Check upload (Tx) or download (Rx) from the peer's perspective
            if src_ip.startswith("10.0.0."):
                peer_ip = src_ip
                flows[peer_ip][dst_ip]["tx_bytes"] += length
                flows[peer_ip][dst_ip]["port"] = dst_port
                peer_speeds[peer_ip]["tx_bytes"] += length
            elif dst_ip.startswith("10.0.0."):
                peer_ip = dst_ip
                flows[peer_ip][src_ip]["rx_bytes"] += length
                flows[peer_ip][src_ip]["port"] = src_port
                peer_speeds[peer_ip]["rx_bytes"] += length

    # 3. Assemble complete metrics (including latency ping back to the client)
    peer_data = []
    for peer in peers:
        peer_ip = peer["allowed_ips"].split("/")[0]
        
        # Measure latency to client via container ICMP
        ping_avg = -1
        ping_jitter = -1
        exit_code, ping_out = container.exec_run(f"ping -c 3 -i 0.2 -W 1 {peer_ip}")
        if exit_code == 0:
            ping_out = ping_out.decode("utf-8", errors="ignore")
            match = re.search(r"rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms", ping_out)
            if match:
                ping_avg = float(match.group(2))
                ping_jitter = float(match.group(4))
                
        # Speed rates in Kbps
        rx_rate = (peer_speeds[peer_ip]["rx_bytes"] * 8) / (capture_duration * 1024)
        tx_rate = (peer_speeds[peer_ip]["tx_bytes"] * 8) / (capture_duration * 1024)
        
        # Structure active routing endpoints
        active_flows = []
        for target_ip, stats in flows[peer_ip].items():
            flow_rx = (stats["rx_bytes"] * 8) / (capture_duration * 1024)
            flow_tx = (stats["tx_bytes"] * 8) / (capture_duration * 1024)
            if flow_rx > 0.05 or flow_tx > 0.05:
                active_flows.append({
                    "target_ip": target_ip,
                    "resolved_host": get_hostname(target_ip),
                    "port": stats["port"],
                    "rx_rate": round(flow_rx, 1),
                    "tx_rate": round(flow_tx, 1)
                })
        
        # Sort targets by throughput (highest first) and limit to top 8
        active_flows = sorted(active_flows, key=lambda x: x["rx_rate"] + x["tx_rate"], reverse=True)[:8]
        
        peer_data.append({
            "pubkey": peer["pubkey"],
            "ip": peer_ip,
            "endpoint": peer["endpoint"],
            "handshake": peer["handshake"],
            "rx_total_mb": round(peer["rx"] / (1024 * 1024), 2),
            "tx_total_mb": round(peer["tx"] / (1024 * 1024), 2),
            "rx_rate_kbps": round(rx_rate, 1),
            "tx_rate_kbps": round(tx_rate, 1),
            "ping_ms": round(ping_avg, 1) if ping_avg >= 0 else None,
            "jitter_ms": round(ping_jitter, 1) if ping_jitter >= 0 else None,
            "flows": active_flows
        })
        
    return {
        "status": "ok",
        "timestamp": int(time.time()),
        "peers": peer_data
    }

def get_cached_metrics():
    now = time.time()
    # Cache metrics for 2.0s to protect CPU cycles from multiple web browsers
    if metrics_cache["data"] is None or (now - metrics_cache["last_updated"]) >= 2.0:
        metrics_cache["data"] = fetch_metrics()
        metrics_cache["last_updated"] = now
    return metrics_cache["data"]


# HTML / CSS / JS Single Page Application Dashboard template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MadaCore VPN Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: rgba(17, 24, 39, 0.7);
            --border-card: rgba(255, 255, 255, 0.07);
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-orange: #f59e0b;
            --accent-red: #ef4444;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem;
            background-image: radial-gradient(circle at 10% 15%, rgba(59, 130, 246, 0.07) 0%, transparent 40%),
                              radial-gradient(circle at 90% 85%, rgba(16, 185, 129, 0.05) 0%, transparent 40%);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-card);
        }
        
        .logo-section h1 {
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #3b82f6, #10b981);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .logo-section p {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }
        
        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-green);
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 500;
            border: 1px solid rgba(16, 185, 129, 0.2);
            transition: all 0.3s ease;
        }
        
        .status-badge.error {
            background: rgba(239, 68, 68, 0.1);
            color: var(--accent-red);
            border-color: rgba(239, 68, 68, 0.2);
        }
        
        .pulse-dot {
            width: 8px;
            height: 8px;
            background-color: currentColor;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(0.95); opacity: 0.5; }
            50% { transform: scale(1.15); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.5; }
        }
        
        .peer-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            padding: 1.75rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        .peer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .peer-info h2 {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--text-main);
        }
        
        .peer-info p {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
            font-family: monospace;
        }
        
        .peer-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.75rem;
        }
        
        .stat-box {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        
        .stat-box:hover {
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.08);
        }
        
        .stat-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 600;
        }
        
        .stat-value {
            font-size: 1.35rem;
            font-weight: 700;
            color: var(--text-main);
        }
        
        .stat-value.latency {
            color: var(--accent-blue);
        }
        
        .stat-value.speed {
            color: var(--accent-green);
        }
        
        .flows-section h3 {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .table-container {
            overflow-x: auto;
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.04);
            background: rgba(0, 0, 0, 0.15);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.875rem;
        }
        
        th {
            padding: 0.85rem 1.25rem;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            background: rgba(255, 255, 255, 0.01);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        
        td {
            padding: 0.85rem 1.25rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            color: #cbd5e1;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
            color: var(--text-main);
        }
        
        .speed-tag {
            font-family: monospace;
            font-weight: 600;
        }
        
        .speed-tag.down {
            color: var(--accent-green);
        }
        
        .speed-tag.up {
            color: var(--accent-orange);
        }
        
        .error-message {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #fca5a5;
            padding: 1.25rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            font-size: 0.95rem;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-section">
                <h1>MadaCore VPN Monitor</h1>
                <p>Gaming-Optimized Tunnel Telemetry</p>
            </div>
            <div id="connection-status" class="status-badge">
                <span class="pulse-dot"></span>
                <span id="status-text">Connecting...</span>
            </div>
        </header>

        <div id="error-container" style="display: none;"></div>
        <div id="peers-container"></div>
    </div>

    <script>
        async function updateData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                
                const statusBadge = document.getElementById('connection-status');
                const statusText = document.getElementById('status-text');
                const errorContainer = document.getElementById('error-container');
                const peersContainer = document.getElementById('peers-container');
                
                if (data.status === 'error') {
                    statusBadge.className = 'status-badge error';
                    statusText.textContent = 'Error';
                    errorContainer.style.display = 'block';
                    errorContainer.innerHTML = `<div class="error-message"><strong>System Error:</strong> ${data.message}</div>`;
                    peersContainer.innerHTML = '';
                    return;
                }
                
                statusBadge.className = 'status-badge';
                statusText.textContent = 'Active';
                errorContainer.style.display = 'none';
                
                if (!data.peers || data.peers.length === 0) {
                    peersContainer.innerHTML = '<div class="peer-card"><p style="text-align: center; color: var(--text-muted);">No active peers detected.</p></div>';
                    return;
                }
                
                let html = '';
                data.peers.forEach(peer => {
                    const handshakeStr = peer.handshake > 0 
                        ? Math.round((Date.now() / 1000) - peer.handshake) + 's ago'
                        : 'Never';
                        
                    const pingStr = peer.ping_ms !== null ? peer.ping_ms + ' ms' : 'ICMP Blocked';
                    const jitterStr = peer.jitter_ms !== null ? peer.jitter_ms + ' ms' : 'N/A';
                    
                    let tableRows = '';
                    if (peer.flows && peer.flows.length > 0) {
                        peer.flows.forEach(flow => {
                            tableRows += `
                                <tr>
                                    <td>${flow.resolved_host}</td>
                                    <td>${flow.port}</td>
                                    <td class="speed-tag down">${flow.rx_rate} Kbps</td>
                                    <td class="speed-tag up">${flow.tx_rate} Kbps</td>
                                </tr>
                            `;
                        });
                    } else {
                        tableRows = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">No active traffic detected in this interval.</td></tr>`;
                    }
                    
                    html += `
                        <div class="peer-card">
                            <div class="peer-header">
                                <div class="peer-info">
                                    <h2>Client IP: ${peer.ip}</h2>
                                    <p>Endpoint: ${peer.endpoint} | Handshake: ${handshakeStr}</p>
                                </div>
                            </div>
                            
                            <div class="peer-stats-grid">
                                <div class="stat-box">
                                    <span class="stat-label">Tunnel Latency</span>
                                    <span class="stat-value latency">${pingStr}</span>
                                </div>
                                <div class="stat-box">
                                    <span class="stat-label">Jitter</span>
                                    <span class="stat-value latency">${jitterStr}</span>
                                </div>
                                <div class="stat-box">
                                    <span class="stat-label">Real-time Down</span>
                                    <span class="stat-value speed">${peer.rx_rate_kbps} Kbps</span>
                                </div>
                                <div class="stat-box">
                                    <span class="stat-label">Real-time Up</span>
                                    <span class="stat-value speed" style="color: var(--accent-orange);">${peer.tx_rate_kbps} Kbps</span>
                                </div>
                                <div class="stat-box">
                                    <span class="stat-label">Cumulative Data</span>
                                    <span class="stat-value" style="font-size: 1rem; margin-top: 0.25rem;">
                                        Rx: ${peer.rx_total_mb} MB<br>Tx: ${peer.tx_total_mb} MB
                                    </span>
                                </div>
                            </div>
                            
                            <div class="flows-section">
                                <h3>🎯 Active Target Host Routing</h3>
                                <div class="table-container">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Target Destination (Reverse DNS / IP)</th>
                                                <th>Port</th>
                                                <th>Speed Down</th>
                                                <th>Speed Up</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${tableRows}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    `;
                });
                peersContainer.innerHTML = html;
                
            } catch (err) {
                console.error('Update error:', err);
                const statusBadge = document.getElementById('connection-status');
                const statusText = document.getElementById('status-text');
                statusBadge.className = 'status-badge error';
                statusText.textContent = 'Offline';
            }
        }
        
        // Initial load
        updateData();
        // Update every 2 seconds
        setInterval(updateData, 2000);
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/data")
def api_data():
    return jsonify(get_cached_metrics())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
