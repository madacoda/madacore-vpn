#!/usr/bin/env python3
"""
MadaCore VPN - Web Traffic Monitor & Account Manager
Author: Professional Network Engineer

This service runs natively inside the WireGuard container, starts a Flask server,
and serves a high-performance, real-time dashboard and administration portal at port 10000.
Features:
1. Real-time gaming traffic, RTT latency, and jitter monitoring.
2. Complete Account & Peer management (Email unique identifier, max 2 devices per user).
3. Live bandwidth tracking and automatic quota enforcement (Free 2GB/day, Pro 200GB/month).
4. Direct client configuration download and in-browser QR code generation for mobile.
5. In-game ping benchmark diagnostics.
"""

import os
import re
import time
import socket
import threading
import subprocess
from pathlib import Path
from collections import defaultdict
from flask import Flask, jsonify, render_template_string, request, Response

# Import VPNManager engine
try:
    from vpn_manager import VPNManager
except ImportError:
    try:
        from strategies.vpn_manager import VPNManager
    except ImportError:
        VPNManager = None

app = Flask(__name__)

# Configurable interface and port
INTERFACE = os.getenv("WG_INTERFACE", "wg0")
PORT = int(os.getenv("MONITOR_PORT", "10000"))

# Initialize VPN Manager
manager = VPNManager(interface=INTERFACE) if VPNManager else None

# Background Quota Enforcement Poller (Runs every 30 seconds with ~0% CPU)
def background_poller():
    while True:
        try:
            if manager:
                manager.poll_and_enforce_quotas()
        except Exception as e:
            pass
        time.sleep(30)

if manager:
    poller_thread = threading.Thread(target=background_poller, daemon=True)
    poller_thread.start()

# DNS Resolution Cache
dns_cache = {}

# Metrics Cache to limit CPU overhead from multiple HTTP requests
metrics_cache = {
    "data": None,
    "last_updated": 0
}

def format_bytes_helper(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"

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

def fetch_metrics():
    # 1. Query WireGuard Interface stats locally
    try:
        res = subprocess.run(
            ["wg", "show", INTERFACE, "dump"],
            capture_output=True, text=True, check=True
        )
        wg_out = res.stdout.strip()
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to execute 'wg show' on interface '{INTERFACE}'. Error: {e}"
        }
        
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
            
    # 2. Run tcpdump for 1.5 seconds locally to calculate current speeds & targets
    capture_duration = 1.5
    try:
        res = subprocess.run(
            ["timeout", str(capture_duration), "tcpdump", "-i", INTERFACE, "-n", "-t", "-q"],
            capture_output=True, text=True
        )
        tcpdump_out = res.stdout
    except Exception:
        tcpdump_out = ""
        
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

    # 3. Assemble complete metrics (including latency ping back to the client & Account Metadata)
    peer_data = []
    for peer in peers:
        peer_ip = peer["allowed_ips"].split("/")[0]
        
        # Measure latency to client via local ICMP ping
        ping_avg = -1
        ping_jitter = -1
        try:
            res = subprocess.run(
                ["ping", "-c", "3", "-i", "0.2", "-W", "1", peer_ip],
                capture_output=True, text=True
            )
            if res.returncode == 0:
                match = re.search(r"rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms", res.stdout)
                if match:
                    ping_avg = float(match.group(2))
                    ping_jitter = float(match.group(4))
        except Exception:
            pass
                
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
        
        # Correlate with Account in DB
        account_email = None
        device_name = None
        account_tier = None
        account_status = "active"
        if manager:
            try:
                with manager.get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                    SELECT d.device_name, a.email, a.tier, a.status
                    FROM devices d
                    JOIN accounts a ON d.account_email = a.email
                    WHERE d.public_key = ?
                    """, (peer["pubkey"],))
                    row = cursor.fetchone()
                    if row:
                        device_name = row["device_name"]
                        account_email = row["email"]
                        account_tier = row["tier"]
                        account_status = row["status"]
            except Exception:
                pass

        peer_data.append({
            "pubkey": peer["pubkey"],
            "ip": peer_ip,
            "device_name": device_name,
            "account_email": account_email,
            "account_tier": account_tier,
            "account_status": account_status,
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
    <title>MadaCore VPN Portal & Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: rgba(17, 24, 39, 0.7);
            --border-card: rgba(255, 255, 255, 0.08);
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-orange: #f59e0b;
            --accent-red: #ef4444;
            --accent-purple: #8b5cf6;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem;
            background-image: radial-gradient(circle at 10% 15%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
                              radial-gradient(circle at 90% 85%, rgba(16, 185, 129, 0.06) 0%, transparent 40%);
        }
        
        .container { max-width: 1200px; margin: 0 auto; }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-card);
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .logo-section h1 {
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #3b82f6, #10b981);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .logo-section p { font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem; }
        
        /* Navigation Tabs */
        .nav-tabs {
            display: flex;
            gap: 0.5rem;
            background: rgba(17, 24, 39, 0.8);
            padding: 0.35rem;
            border-radius: 12px;
            border: 1px solid var(--border-card);
        }
        
        .nav-tab {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 0.5rem 1.25rem;
            border-radius: 8px;
            font-size: 0.88rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .nav-tab:hover { color: var(--text-main); background: rgba(255, 255, 255, 0.05); }
        
        .nav-tab.active {
            background: var(--accent-blue);
            color: #ffffff;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .tab-pane { display: none; }
        .tab-pane.active { display: block; }
        
        /* Badges & Buttons */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            padding: 0.25rem 0.65rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-quota { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-free { background: rgba(59, 130, 246, 0.15); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.3); }
        .badge-pro { background: rgba(139, 92, 246, 0.15); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.3); }
        .badge-adaw { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--accent-blue), #2563eb);
            color: white;
            border: none;
            padding: 0.55rem 1.1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
        }
        .btn-primary:hover { opacity: 0.95; transform: translateY(-1px); }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-main);
            border: 1px solid var(--border-card);
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-secondary:hover { background: rgba(255, 255, 255, 0.12); }
        
        .btn-danger {
            background: rgba(239, 68, 68, 0.12);
            color: var(--accent-red);
            border: 1px solid rgba(239, 68, 68, 0.25);
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-danger:hover { background: rgba(239, 68, 68, 0.25); }

        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }
        .summary-card .label { font-size: 0.8rem; color: var(--text-muted); font-weight: 500; }
        .summary-card .value { font-size: 1.5rem; font-weight: 700; color: var(--text-main); }
        
        /* Account Cards */
        .account-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: 14px;
            padding: 1.5rem;
            margin-bottom: 1.25rem;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.25);
            transition: transform 0.2s;
        }
        
        .account-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-bottom: 1.25rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .account-title {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .account-email { font-size: 1.15rem; font-weight: 600; color: var(--text-main); }
        
        .quota-bar-container {
            margin-bottom: 1.25rem;
        }
        .quota-labels {
            display: flex;
            justify-content: space-between;
            font-size: 0.82rem;
            color: var(--text-muted);
            margin-bottom: 0.4rem;
        }
        .progress-track {
            height: 8px;
            background: rgba(255, 255, 255, 0.08);
            border-radius: 999px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            border-radius: 999px;
            transition: width 0.3s ease;
        }
        
        /* Devices Section */
        .devices-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 0.75rem;
        }
        
        .device-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 0.75rem;
        }
        
        .device-box {
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .device-info h4 { font-size: 0.95rem; font-weight: 600; color: #fff; margin-bottom: 0.2rem; }
        .device-info p { font-size: 0.8rem; color: var(--text-muted); font-family: monospace; }
        .device-actions { display: flex; gap: 0.4rem; }
        
        /* Peer Card (Monitor Tab) */
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
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .peer-ip-info h2 { font-size: 1.3rem; font-weight: 700; color: var(--accent-green); }
        .peer-ip-info span { font-size: 0.85rem; color: var(--text-muted); font-family: monospace; }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .metric-box {
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 1rem;
        }
        .metric-box .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem; }
        .metric-box .value { font-size: 1.25rem; font-weight: 600; }
        
        /* Tables */
        table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
        th { text-align: left; padding: 0.75rem 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border-card); }
        td { padding: 0.75rem 1rem; border-bottom: 1px solid rgba(255, 255, 255, 0.03); }
        
        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(6px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .modal {
            background: #111827;
            border: 1px solid var(--border-card);
            border-radius: 16px;
            width: 90%;
            max-width: 480px;
            padding: 2rem;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }
        .modal h3 { font-size: 1.25rem; margin-bottom: 1rem; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.35rem; }
        .form-group input, .form-group select {
            width: 100%;
            padding: 0.65rem 0.85rem;
            background: rgba(0, 0, 0, 0.35);
            border: 1px solid var(--border-card);
            border-radius: 8px;
            color: #fff;
            font-size: 0.9rem;
            outline: none;
        }
        .form-group input:focus, .form-group select:focus { border-color: var(--accent-blue); }
        .modal-buttons { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem; }
        
        .pulse-dot { width: 8px; height: 8px; background: currentColor; border-radius: 50%; display: inline-block; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-section">
                <h1>MadaCore Gaming VPN</h1>
                <p>Ultra-Low Latency Kernel WireGuard &bull; Multi-Peer Management</p>
            </div>
            
            <nav class="nav-tabs">
                <button class="nav-tab active" id="tab-btn-monitor" onclick="switchTab('monitor')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                    Live Traffic Monitor
                </button>
                <button class="nav-tab" id="tab-btn-accounts" onclick="switchTab('accounts')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
                    Accounts & Quotas
                </button>
            </nav>
        </header>

        <!-- TAB 1: ACCOUNTS & QUOTAS -->
        <div id="tab-accounts" class="tab-pane">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <div>
                    <h2 style="font-size: 1.3rem; font-weight: 700;">Account & Device Management</h2>
                    <p style="font-size: 0.85rem; color: var(--text-muted);">Unique email auth &bull; Strict 2-device limit per account &bull; Automated quota enforcement</p>
                </div>
                <button class="btn-primary" onclick="openCreateModal()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    New Account
                </button>
            </div>

            <div class="summary-grid" id="accounts-summary">
                <div class="summary-card">
                    <span class="label">Total Accounts</span>
                    <span class="value" id="stat-total-accounts">0</span>
                </div>
                <div class="summary-card">
                    <span class="label">Total Registered Devices</span>
                    <span class="value" id="stat-total-devices">0</span>
                </div>
                <div class="summary-card">
                    <span class="label">Free Tier Accounts</span>
                    <span class="value" id="stat-free-accounts" style="color: var(--accent-blue);">0</span>
                </div>
                <div class="summary-card">
                    <span class="label">Pro Tier Accounts</span>
                    <span class="value" id="stat-pro-accounts" style="color: var(--accent-purple);">0</span>
                </div>
                <div class="summary-card">
                    <span class="label">Adaw Tier (Unlimited)</span>
                    <span class="value" id="stat-adaw-accounts" style="color: #f59e0b;">0</span>
                </div>
            </div>

            <div id="accounts-container">
                <!-- Rendered dynamically -->
            </div>
        </div>

        <!-- TAB 2: LIVE TRAFFIC MONITOR -->
        <div id="tab-monitor" class="tab-pane active">
            <div id="peers-container">
                <p style="color: var(--text-muted); text-align: center; padding: 2rem;">Connecting to WireGuard kernel interface...</p>
            </div>
        </div>
    </div>

    <!-- MODAL: CREATE ACCOUNT -->
    <div class="modal-overlay" id="modal-create">
        <div class="modal">
            <h3>Create VPN Account</h3>
            <form onsubmit="handleCreateAccount(event)">
                <div class="form-group">
                    <label>Unique Email Address</label>
                    <input type="email" id="create-email" required placeholder="player1@gmail.com">
                </div>
                <div class="form-group">
                    <label>Subscription Tier</label>
                    <select id="create-tier">
                        <option value="free">Free Tier (2 GB / Day - Reset midnight UTC)</option>
                        <option value="pro">Pro Tier (200 GB / Month - Reset 1st of month)</option>
                        <option value="adaw">Adaw Tier (Unlimited Bandwidth - No Cap)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Initial Devices (Max 2 simultaneous devices)</label>
                    <div style="display: flex; gap: 1rem; margin-top: 0.5rem; font-size: 0.88rem;">
                        <label style="display: flex; align-items: center; gap: 0.4rem; cursor: pointer;">
                            <input type="checkbox" id="create-dev-pc" checked style="width: auto;"> PC / Laptop
                        </label>
                        <label style="display: flex; align-items: center; gap: 0.4rem; cursor: pointer;">
                            <input type="checkbox" id="create-dev-phone" checked style="width: auto;"> Mobile / Phone
                        </label>
                    </div>
                </div>
                <div class="modal-buttons">
                    <button type="button" class="btn-secondary" onclick="closeModal('modal-create')">Cancel</button>
                    <button type="submit" class="btn-primary">Create Account</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: ADD DEVICE -->
    <div class="modal-overlay" id="modal-device">
        <div class="modal">
            <h3>Add Device</h3>
            <form onsubmit="handleAddDevice(event)">
                <input type="hidden" id="device-email">
                <div class="form-group">
                    <label>Account</label>
                    <input type="text" id="device-email-display" disabled style="opacity: 0.7;">
                </div>
                <div class="form-group">
                    <label>Device Name (e.g. laptop, mobile, work_pc)</label>
                    <input type="text" id="device-name" required placeholder="laptop">
                </div>
                <div class="modal-buttons">
                    <button type="button" class="btn-secondary" onclick="closeModal('modal-device')">Cancel</button>
                    <button type="submit" class="btn-primary">Provision Device</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: QR CODE -->
    <div class="modal-overlay" id="modal-qr">
        <div class="modal" style="text-align: center;">
            <h3 id="qr-modal-title">WireGuard Tunnel QR Code</h3>
            <p id="qr-modal-sub" style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;"></p>
            <div id="qrcode" style="display: inline-block; background: white; padding: 12px; border-radius: 8px; margin-bottom: 1rem;"></div>
            <div class="modal-buttons" style="justify-content: center;">
                <button type="button" class="btn-secondary" onclick="closeModal('modal-qr')">Close</button>
                <button type="button" class="btn-primary" id="btn-qr-download">Download .conf</button>
            </div>
        </div>
    </div>

    <script>
        let currentTab = 'monitor';
        let currentDownloadUrl = '';

        function switchTab(tab) {
            currentTab = tab;
            document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            
            document.getElementById(`tab-btn-${tab}`).classList.add('active');
            document.getElementById(`tab-${tab}`).classList.add('active');
            
            if (tab === 'accounts') {
                loadAccounts();
            }
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // =====================================================
        // ACCOUNTS MANAGEMENT
        // =====================================================
        async function loadAccounts() {
            try {
                const res = await fetch('/api/accounts');
                const data = await res.json();
                if (data.status !== 'ok') return;

                const accounts = data.accounts;
                document.getElementById('stat-total-accounts').innerText = accounts.length;
                let totalDevices = 0;
                let freeCount = 0;
                let proCount = 0;
                let adawCount = 0;

                accounts.forEach(a => {
                    totalDevices += a.device_count;
                    if (a.tier === 'free') freeCount++;
                    else if (a.tier === 'pro') proCount++;
                    else if (a.tier === 'adaw') adawCount++;
                });

                document.getElementById('stat-total-devices').innerText = totalDevices;
                document.getElementById('stat-free-accounts').innerText = freeCount;
                document.getElementById('stat-pro-accounts').innerText = proCount;
                const adawStat = document.getElementById('stat-adaw-accounts');
                if (adawStat) adawStat.innerText = adawCount;

                const container = document.getElementById('accounts-container');
                if (accounts.length === 0) {
                    container.innerHTML = `
                        <div class="account-card" style="text-align: center; color: var(--text-muted); padding: 3rem;">
                            No accounts created yet. Click <strong>New Account</strong> above to provision your first user.
                        </div>
                    `;
                    return;
                }

                container.innerHTML = accounts.map(a => {
                    const statusBadge = a.status === 'active' 
                        ? `<span class="badge badge-active"><span class="pulse-dot"></span> Active</span>`
                        : `<span class="badge badge-quota">Quota Exceeded</span>`;

                    let tierBadge = '';
                    if (a.tier === 'free') {
                        tierBadge = `<span class="badge badge-free">Free (2GB/Day)</span>`;
                    } else if (a.tier === 'pro') {
                        tierBadge = `<span class="badge badge-pro">Pro (200GB/Month)</span>`;
                    } else {
                        tierBadge = `<span class="badge badge-adaw">Adaw (Unlimited)</span>`;
                    }

                    let quotaBarHtml = '';
                    if (a.tier === 'adaw') {
                        quotaBarHtml = `
                            <div class="quota-bar-container">
                                <div class="quota-labels">
                                    <span>Adaw Unlimited Bandwidth (No Quota Cap)</span>
                                    <span><strong>${formatBytes(a.today_usage_bytes)}</strong> today &bull; <strong>${formatBytes(a.month_usage_bytes)}</strong> this month</span>
                                </div>
                                <div class="progress-track">
                                    <div class="progress-fill" style="width: 100%; background: linear-gradient(90deg, #f59e0b, #10b981);"></div>
                                </div>
                            </div>
                        `;
                    } else {
                        const isFree = a.tier === 'free';
                        const used = isFree ? a.today_usage_bytes : a.month_usage_bytes;
                        const limit = isFree ? a.daily_limit_bytes : a.monthly_limit_bytes;
                        const percent = a.quota_percent || 0;
                        
                        let fillColor = 'var(--accent-green)';
                        if (percent > 85) fillColor = 'var(--accent-red)';
                        else if (percent > 65) fillColor = 'var(--accent-orange)';

                        quotaBarHtml = `
                            <div class="quota-bar-container">
                                <div class="quota-labels">
                                    <span>${isFree ? "Today's Consumption (24h Window)" : "Monthly Consumption"}</span>
                                    <span><strong>${formatBytes(used)}</strong> / ${formatBytes(limit)} (${percent}%)</span>
                                </div>
                                <div class="progress-track">
                                    <div class="progress-fill" style="width: ${percent}%; background: ${fillColor};"></div>
                                </div>
                            </div>
                        `;
                    }

                    const deviceBoxes = a.devices.map(d => `
                        <div class="device-box">
                            <div class="device-info">
                                <h4>📱 ${d.device_name}</h4>
                                <p>IP: <strong>${d.internal_ip}</strong></p>
                            </div>
                            <div class="device-actions">
                                <a href="/api/accounts/${encodeURIComponent(a.email)}/devices/${encodeURIComponent(d.device_name)}/config" class="btn-secondary" download>📥 .conf</a>
                                <button class="btn-secondary" onclick="showQR('${a.email}', '${d.device_name}', '${d.internal_ip}')">📱 QR</button>
                                <button class="btn-danger" onclick="deleteDevice('${a.email}', '${d.device_name}')">🗑️</button>
                            </div>
                        </div>
                    `).join('');

                    const addDeviceBtn = a.device_count < 2
                        ? `<button class="btn-secondary" onclick="openAddDeviceModal('${a.email}')">+ Add Device (${a.device_count}/2)</button>`
                        : `<span style="font-size: 0.8rem; color: var(--accent-orange); font-weight: 500;">✓ Max 2 devices allocated</span>`;

                    return `
                        <div class="account-card">
                            <div class="account-header">
                                <div class="account-title">
                                    <span class="account-email">${a.email}</span>
                                    ${tierBadge}
                                    ${statusBadge}
                                </div>
                                <div style="display: flex; gap: 0.5rem; align-items: center;">
                                    <select class="btn-secondary" style="background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255,255,255,0.15); color: #fff; padding: 0.35rem 0.6rem; border-radius: 6px; font-size: 0.8rem; cursor: pointer;" onchange="toggleTier('${a.email}', this.value)">
                                        <option value="free" ${a.tier === 'free' ? 'selected' : ''}>Tier: Free (2GB/d)</option>
                                        <option value="pro" ${a.tier === 'pro' ? 'selected' : ''}>Tier: Pro (200GB/m)</option>
                                        <option value="adaw" ${a.tier === 'adaw' ? 'selected' : ''}>Tier: Adaw (Unlimited)</option>
                                    </select>
                                    <button class="btn-secondary" onclick="resetQuota('${a.email}')">🔄 Reset Quota</button>
                                    <button class="btn-danger" onclick="deleteAccount('${a.email}')">Delete</button>
                                </div>
                            </div>

                            ${quotaBarHtml}

                            <div class="devices-header">
                                <span>ASSIGNED DEVICES</span>
                                ${addDeviceBtn}
                            </div>
                            <div class="device-grid">
                                ${deviceBoxes || '<p style="font-size: 0.85rem; color: var(--text-muted);">No devices configured yet.</p>'}
                            </div>
                        </div>
                    `;
                }).join('');

            } catch (err) {
                console.error(err);
            }
        }

        function openCreateModal() {
            document.getElementById('modal-create').style.display = 'flex';
            document.getElementById('create-email').focus();
        }

        function openAddDeviceModal(email) {
            document.getElementById('device-email').value = email;
            document.getElementById('device-email-display').value = email;
            document.getElementById('modal-device').style.display = 'flex';
            document.getElementById('device-name').focus();
        }

        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }

        async function handleCreateAccount(e) {
            e.preventDefault();
            const email = document.getElementById('create-email').value.trim();
            const tier = document.getElementById('create-tier').value;
            const devices = [];
            if (document.getElementById('create-dev-pc').checked) devices.push('pc');
            if (document.getElementById('create-dev-phone').checked) devices.push('phone');

            try {
                const res = await fetch('/api/accounts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, tier, devices })
                });
                const data = await res.json();
                if (data.status === 'ok') {
                    closeModal('modal-create');
                    loadAccounts();
                } else {
                    alert('Error: ' + data.message);
                }
            } catch (err) {
                alert('Failed to connect to backend.');
            }
        }

        async function handleAddDevice(e) {
            e.preventDefault();
            const email = document.getElementById('device-email').value;
            const device_name = document.getElementById('device-name').value.trim();

            try {
                const res = await fetch(`/api/accounts/${encodeURIComponent(email)}/devices`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ device_name })
                });
                const data = await res.json();
                if (data.status === 'ok') {
                    closeModal('modal-device');
                    loadAccounts();
                } else {
                    alert('Error: ' + data.message);
                }
            } catch (err) {
                alert('Failed to connect to backend.');
            }
        }

        async function deleteDevice(email, deviceName) {
            if (!confirm(`Delete device '${deviceName}' for ${email}?`)) return;
            try {
                await fetch(`/api/accounts/${encodeURIComponent(email)}/devices/${encodeURIComponent(deviceName)}`, { method: 'DELETE' });
                loadAccounts();
            } catch (err) { alert('Delete failed'); }
        }

        async function deleteAccount(email) {
            if (!confirm(`Permanently delete account ${email} and all its devices?`)) return;
            try {
                await fetch(`/api/accounts/${encodeURIComponent(email)}`, { method: 'DELETE' });
                loadAccounts();
            } catch (err) { alert('Delete failed'); }
        }

        async function resetQuota(email) {
            try {
                await fetch(`/api/accounts/${encodeURIComponent(email)}/reset-quota`, { method: 'POST' });
                loadAccounts();
            } catch (err) { alert('Reset quota failed'); }
        }

        async function toggleTier(email, newTier) {
            try {
                await fetch(`/api/accounts/${encodeURIComponent(email)}/tier`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tier: newTier })
                });
                loadAccounts();
            } catch (err) { alert('Tier update failed'); }
        }

        async function showQR(email, deviceName, ip) {
            try {
                const configUrl = `/api/accounts/${encodeURIComponent(email)}/devices/${encodeURIComponent(deviceName)}/config`;
                const res = await fetch(configUrl);
                const configText = await res.text();

                document.getElementById('qr-modal-title').innerText = `${deviceName} (${ip})`;
                document.getElementById('qr-modal-sub').innerText = email;

                const qrContainer = document.getElementById('qrcode');
                qrContainer.innerHTML = '';
                new QRCode(qrContainer, {
                    text: configText,
                    width: 256,
                    height: 256,
                    correctLevel: QRCode.CorrectLevel.M
                });

                document.getElementById('btn-qr-download').onclick = () => {
                    window.location.href = configUrl;
                };

                document.getElementById('modal-qr').style.display = 'flex';
            } catch (err) {
                alert('Failed to generate QR code.');
            }
        }

        // =====================================================
        // LIVE TRAFFIC MONITOR
        // =====================================================
        async function updateMonitorData() {
            if (currentTab !== 'monitor') return;
            try {
                const res = await fetch('/api/data');
                const data = await res.json();
                if (data.status !== 'ok') return;

                const peers = data.peers || [];
                const container = document.getElementById('peers-container');

                if (peers.length === 0) {
                    container.innerHTML = `
                        <div class="peer-card" style="text-align: center; color: var(--text-muted); padding: 3rem;">
                            No active peers currently connected to interface <strong>${INTERFACE}</strong>.
                        </div>
                    `;
                    return;
                }

                container.innerHTML = peers.map(p => {
                    const handshakeAgo = p.handshake > 0 ? (Math.floor(Date.now() / 1000) - p.handshake) + 's ago' : 'Never';
                    const pingText = p.ping_ms ? `${p.ping_ms} ms (Jitter: ${p.jitter_ms} ms)` : 'ICMP Blocked';
                    const userLabel = p.account_email ? `${p.account_email} [${p.device_name}]` : 'Guest / Standalone Peer';

                    return `
                        <div class="peer-card">
                            <div class="peer-header">
                                <div class="peer-ip-info">
                                    <h2>🟢 ${p.ip}</h2>
                                    <span>${userLabel} &bull; ${p.pubkey.substring(0, 12)}...</span>
                                </div>
                                <span class="badge badge-active"><span class="pulse-dot"></span> Tunnel Connected</span>
                            </div>

                            <div class="metrics-grid">
                                <div class="metric-box">
                                    <div class="label">Download Speed</div>
                                    <div class="value" style="color: var(--accent-green);">${p.rx_rate_kbps} Kbps</div>
                                </div>
                                <div class="metric-box">
                                    <div class="label">Upload Speed</div>
                                    <div class="value" style="color: var(--accent-blue);">${p.tx_rate_kbps} Kbps</div>
                                </div>
                                <div class="metric-box">
                                    <div class="label">Direct Latency</div>
                                    <div class="value">${pingText}</div>
                                </div>
                                <div class="metric-box">
                                    <div class="label">Cumulative Data</div>
                                    <div class="value">${p.rx_total_mb} MB &darr; / ${p.tx_total_mb} MB &uarr;</div>
                                </div>
                            </div>

                            <h4 style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">ACTIVE ROUTED DESTINATIONS</h4>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Target Host / Game Server</th>
                                        <th>Port</th>
                                        <th>Speed Down</th>
                                        <th>Speed Up</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${p.flows.map(f => `
                                        <tr>
                                            <td><strong>${f.resolved_host}</strong> <span style="color: var(--text-muted); font-size: 0.8rem;">(${f.target_ip})</span></td>
                                            <td>${f.port}</td>
                                            <td style="color: var(--accent-green);">${f.rx_rate} Kbps</td>
                                            <td style="color: var(--accent-blue);">${f.tx_rate} Kbps</td>
                                        </tr>
                                    `).join('') || '<tr><td colspan="4" style="color: var(--text-muted); text-align: center;">No active routed targets in current capture window</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    `;
                }).join('');

            } catch (err) {
                console.error(err);
            }
        }

        // Periodic updates
        setInterval(updateMonitorData, 2000);
        updateMonitorData();
    </script>
</body>
</html>
"""

def get_client_ip():
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    cf_connecting_ip = request.headers.get("CF-Connecting-IP")
    if cf_connecting_ip:
        return cf_connecting_ip.strip()
    return request.remote_addr

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/data")
def api_data():
    all_metrics = get_cached_metrics()
    if all_metrics.get("status") == "error":
        return jsonify(all_metrics)
        
    client_ip = get_client_ip()
    is_local = client_ip in ("127.0.0.1", "::1", "localhost")
    
    filtered_peers = []
    client_connected = False
    
    if is_local:
        filtered_peers = all_metrics.get("peers", [])
        client_connected = True
    else:
        for peer in all_metrics.get("peers", []):
            peer_internal_ip = peer.get("ip", "")
            peer_endpoint_ip = ""
            endpoint = peer.get("endpoint", "")
            if endpoint and endpoint != "(none)":
                endpoint_part = endpoint.rsplit(":", 1)[0]
                peer_endpoint_ip = endpoint_part.strip("[]")
                
            if client_ip == peer_internal_ip or (peer_endpoint_ip and client_ip == peer_endpoint_ip):
                filtered_peers.append(peer)
                client_connected = True
                
        # If accessing via public IP or web proxy, show all peers
        if not filtered_peers:
            filtered_peers = all_metrics.get("peers", [])
            client_connected = True
                
    return jsonify({
        "status": "ok",
        "timestamp": all_metrics.get("timestamp", int(time.time())),
        "peers": filtered_peers,
        "client_connected": client_connected
    })

# =====================================================
# REST API: ACCOUNTS & DEVICE MANAGEMENT
# =====================================================
@app.route("/api/accounts", methods=["GET"])
def api_list_accounts():
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    return jsonify({"status": "ok", "accounts": manager.list_accounts()})

@app.route("/api/accounts", methods=["POST"])
def api_create_account():
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    data = request.get_json() or {}
    email = data.get("email")
    tier = data.get("tier", "free")
    devices = data.get("devices", [])
    
    if not email:
        return jsonify({"status": "error", "message": "Email is required"}), 400
        
    try:
        acc = manager.create_account(email, tier=tier)
        for dev_name in devices[:2]:
            manager.add_device(email, dev_name)
        return jsonify({"status": "ok", "account": manager.get_account(email)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/accounts/<email>/devices", methods=["POST"])
def api_add_device(email):
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    data = request.get_json() or {}
    device_name = data.get("device_name", "pc")
    public_key = data.get("public_key")
    psk = data.get("psk")
    try:
        dev = manager.add_device(email, device_name, public_key=public_key, preshared_key=psk)
        return jsonify({"status": "ok", "device": dev})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/keys", methods=["GET"])
def api_list_keys():
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    return jsonify({"status": "ok", "keys": manager.list_keys()})

@app.route("/api/keys/<path:public_key>", methods=["DELETE"])
def api_delete_key(public_key):
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    try:
        if manager.delete_key(public_key):
            return jsonify({"status": "ok", "message": f"Key '{public_key}' deleted"})
        return jsonify({"status": "error", "message": "Key not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/accounts/<email>/devices/<device_name>", methods=["DELETE"])
def api_delete_device(email, device_name):
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    try:
        if manager.remove_device(email, device_name):
            return jsonify({"status": "ok", "message": f"Device '{device_name}' removed"})
        return jsonify({"status": "error", "message": "Device not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/accounts/<email>", methods=["DELETE"])
def api_delete_account(email):
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    try:
        if manager.delete_account(email):
            return jsonify({"status": "ok", "message": f"Account '{email}' deleted"})
        return jsonify({"status": "error", "message": "Account not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/accounts/<email>/reset-quota", methods=["POST"])
def api_reset_quota(email):
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    try:
        acc = manager.reset_quota(email)
        return jsonify({"status": "ok", "account": acc})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/accounts/<email>/tier", methods=["POST"])
def api_update_tier(email):
    if not manager:
        return jsonify({"status": "error", "message": "VPN Manager not initialized"}), 500
    data = request.get_json() or {}
    tier = data.get("tier", "free")
    try:
        acc = manager.update_tier(email, tier)
        return jsonify({"status": "ok", "account": acc})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/accounts/<email>/devices/<device_name>/config", methods=["GET"])
def api_download_config(email, device_name):
    if not manager:
        return "VPN Manager not initialized", 500
    cfg = manager.get_device_config(email, device_name)
    if not cfg:
        return "Config not found", 404
    return Response(
        cfg,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename={email}_{device_name}.conf"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
