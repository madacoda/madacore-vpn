#!/usr/bin/env python3
"""
MadaCore VPN - Real-Time Traffic & Quality Monitor
Author: Professional Network Engineer

This script runs on the host VPS to provide a comprehensive, real-time dashboard
of your WireGuard VPN network performance. It tracks:
1. Client IP & Public Endpoint
2. Real-time Latency (Ping RTT) and Jitter back to the client
3. Current upload/download speeds (Rx/Tx)
4. Active destination hosts (Targets) and their resolved domain names

Requirements:
- Python 3.x (Standard on Linux hosts)
- Docker running the 'gaming-wireguard' container
- 'tcpdump' (Auto-installed inside the container by this script if missing)
"""

import os
import sys
import re
import subprocess
import time
import socket
from collections import defaultdict

# DNS resolution cache to prevent lag during loops
dns_cache = {}

def check_dependencies():
    # 1. Check if Docker is available
    res = subprocess.run(["which", "docker"], capture_output=True)
    if res.returncode != 0:
        print("[-] Error: Docker is not installed on this host VPS.")
        sys.exit(1)
    
    # 2. Check if the gaming-wireguard container is running
    res = subprocess.run(
        ["docker", "ps", "-q", "-f", "name=gaming-wireguard"],
        capture_output=True, text=True
    )
    if not res.stdout.strip():
        print("[-] Error: The 'gaming-wireguard' container is not running.")
        print("    Please start your VPN stack using: docker compose up -d")
        sys.exit(1)

    # 3. Check if tcpdump is installed inside the WireGuard container
    res = subprocess.run(
        ["docker", "exec", "gaming-wireguard", "which", "tcpdump"],
        capture_output=True
    )
    if res.returncode != 0:
        print("[*] tcpdump not found in container. Attempting automated installation...")
        # Try Alpine packager (apk)
        install_res = subprocess.run(
            ["docker", "exec", "gaming-wireguard", "apk", "add", "--no-cache", "tcpdump"],
            capture_output=True
        )
        if install_res.returncode != 0:
            # Fallback to Debian/Ubuntu packager (apt)
            subprocess.run(["docker", "exec", "gaming-wireguard", "apt-get", "update"], capture_output=True)
            install_res = subprocess.run(
                ["docker", "exec", "gaming-wireguard", "apt-get", "install", "-y", "tcpdump"],
                capture_output=True
            )
        
        # Verify installation success
        res = subprocess.run(
            ["docker", "exec", "gaming-wireguard", "which", "tcpdump"],
            capture_output=True
        )
        if res.returncode != 0:
            print("[-] Error: Could not install tcpdump inside the container automatically.")
            print("    Please execute: docker exec -it gaming-wireguard apk add --no-cache tcpdump")
            sys.exit(1)
        else:
            print("[+] tcpdump successfully installed inside container.")

def get_hostname(ip):
    # Return from cache if resolved previously
    if ip in dns_cache:
        return dns_cache[ip]
    
    try:
        # Perform reverse DNS lookup with a short timeout
        socket.setdefaulttimeout(0.8)
        hostname, _, _ = socket.gethostbyaddr(ip)
        dns_cache[ip] = hostname
        return hostname
    except Exception:
        dns_cache[ip] = ip
        return ip

def parse_wg_dump():
    """
    Executes 'wg show wg0 dump' and parses active peer parameters.
    """
    try:
        res = subprocess.run(
            ["docker", "exec", "gaming-wireguard", "wg", "show", "wg0", "dump"],
            capture_output=True, text=True, check=True
        )
        lines = res.stdout.strip().split("\n")
        if len(lines) <= 1:
            return []
        
        peers = []
        # Index 0 is the server interface information, peers start at index 1
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
        return peers
    except Exception as e:
        print(f"[-] Error querying WireGuard status: {e}")
        return []

def ping_peer(vpn_ip):
    """
    Pings the client's VPN tunnel IP from inside the container namespace
    to measure direct latency and jitter.
    """
    try:
        res = subprocess.run(
            ["docker", "exec", "gaming-wireguard", "ping", "-c", "3", "-i", "0.2", "-W", "1", vpn_ip],
            capture_output=True, text=True
        )
        if res.returncode == 0:
            # Extract standard ping summary output: rtt min/avg/max/mdev = 12.345/15.678/18.901/1.234 ms
            match = re.search(r"rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms", res.stdout)
            if match:
                return {
                    "min": float(match.group(1)),
                    "avg": float(match.group(2)),
                    "max": float(match.group(3)),
                    "jitter": float(match.group(4))
                }
    except Exception:
        pass
    return None

def capture_traffic(duration=1.5):
    """
    Runs tcpdump on wg0 inside the container for a specified duration
    and returns raw packet capture log lines.
    """
    cmd = ["docker", "exec", "gaming-wireguard", "timeout", str(duration), "tcpdump", "-i", "wg0", "-n", "-t", "-q"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(duration)
        proc.terminate()
        stdout, _ = proc.communicate(timeout=1.0)
        return stdout
    except Exception:
        return ""

def main():
    check_dependencies()
    print("[+] Dependencies verified. Initializing dashboard...")
    time.sleep(1)
    
    capture_duration = 1.5
    
    try:
        while True:
            # Clear terminal screen
            print("\033[H\033[J", end="")
            
            print("=" * 85)
            print("   MADACORE VPN - REAL-TIME TRAFFIC & ROUTE MONITOR")
            print(f"   Time: {time.strftime('%Y-%m-%d %H:%M:%S')} | Capture Interval: {capture_duration}s | Ctrl+C to Stop")
            print("=" * 85)
            
            peers = parse_wg_dump()
            if not peers:
                print("\n   [-] No active peers configured or connected on interface wg0.")
                time.sleep(2)
                continue
                
            # Perform packet capture to isolate speeds and targets
            traffic_data = capture_traffic(capture_duration)
            
            # Map peer traffic: peer_ip -> { target_ip: { 'port': port, 'rx_bytes': X, 'tx_bytes': Y } }
            flows = defaultdict(lambda: defaultdict(lambda: {"port": "", "rx_bytes": 0, "tx_bytes": 0}))
            peer_current_speed = defaultdict(lambda: {"rx_bytes": 0, "tx_bytes": 0})
            
            for line in traffic_data.split("\n"):
                # Matches: IP source_ip.port > dest_ip.port: ... length packet_size
                match = re.search(r"IP\s+([\d\.]+)\.(\d+)\s+>\s+([\d\.]+)\.(\d+):.*length\s+(\d+)", line)
                if match:
                    src_ip = match.group(1)
                    src_port = match.group(2)
                    dst_ip = match.group(3)
                    dst_port = match.group(4)
                    length = int(match.group(5))
                    
                    # Distinguish upload/download from client perspective
                    # If packet source is on VPN internal subnet, it's outbound traffic (Client Tx)
                    if src_ip.startswith("10.0.0."):
                        peer_ip = src_ip
                        target_ip = dst_ip
                        flows[peer_ip][target_ip]["tx_bytes"] += length
                        flows[peer_ip][target_ip]["port"] = dst_port
                        peer_current_speed[peer_ip]["tx_bytes"] += length
                    # If packet destination is on VPN internal subnet, it's inbound traffic (Client Rx)
                    elif dst_ip.startswith("10.0.0."):
                        peer_ip = dst_ip
                        target_ip = src_ip
                        flows[peer_ip][target_ip]["rx_bytes"] += length
                        flows[peer_ip][target_ip]["port"] = src_port
                        peer_current_speed[peer_ip]["rx_bytes"] += length

            # Output statistics per peer
            for peer in peers:
                peer_ip = peer["allowed_ips"].split("/")[0]
                
                # Check latency
                lat = ping_peer(peer_ip)
                if lat:
                    latency_str = f"Avg: {lat['avg']:.1f}ms | Jitter: {lat['jitter']:.1f}ms (Min: {lat['min']:.1f}ms / Max: {lat['max']:.1f}ms)"
                else:
                    # Ping timed out (could be client firewall blocking ICMP)
                    latency_str = "ICMP Blocked / Peer Host Offline"
                
                # Handshake age calculation
                if peer["handshake"] > 0:
                    handshake_ago = int(time.time() - peer["handshake"])
                    handshake_str = f"{handshake_ago}s ago"
                else:
                    handshake_str = "Never"
                
                # Calculate real-time speed rates in Kilobits per second (Kbps)
                rx_rate = (peer_current_speed[peer_ip]["rx_bytes"] * 8) / (capture_duration * 1024)
                tx_rate = (peer_current_speed[peer_ip]["tx_bytes"] * 8) / (capture_duration * 1024)
                
                # Total usage metrics (MB)
                total_rx_mb = peer["rx"] / (1024 * 1024)
                total_tx_mb = peer["tx"] / (1024 * 1024)
                
                # Truncate client public key for clean representation
                short_key = peer["pubkey"][:12] + "..." + peer["pubkey"][-8:]
                
                # Print peer card
                print(f"\n🟢 CLIENT: {peer_ip} ({short_key})")
                print(f"   └─ Public Endpoint : {peer['endpoint']}")
                print(f"   └─ Last Handshake  : {handshake_str}")
                print(f"   └─ Tunnel Latency  : {latency_str}")
                print(f"   └─ Cumulative Data : Received: {total_rx_mb:.2f} MB | Transmitted: {total_tx_mb:.2f} MB")
                print(f"   └─ Real-Time Speed : Down: {rx_rate:.2f} Kbps | Up: {tx_rate:.2f} Kbps")
                print("-" * 85)
                
                # Show active target routes
                peer_flows = flows[peer_ip]
                if not peer_flows:
                    print("   [i] No active routing detected on this capture window.")
                else:
                    print(f"   {'ACTIVE TARGET HOST (REVERSE DNS / IP)':<48} {'PORT':<8} {'SPEED DOWN':<13} {'SPEED UP':<13}")
                    
                    # Sort active routes by cumulative bandwidth
                    sorted_flows = sorted(
                        peer_flows.items(),
                        key=lambda x: x[1]["rx_bytes"] + x[1]["tx_bytes"],
                        reverse=True
                    )
                    
                    # Limit output to top 8 targets to fit terminal neatly
                    for target_ip, stats in sorted_flows[:8]:
                        target_rx_rate = (stats["rx_bytes"] * 8) / (capture_duration * 1024)
                        target_tx_rate = (stats["tx_bytes"] * 8) / (capture_duration * 1024)
                        
                        resolved_host = get_hostname(target_ip)
                        if len(resolved_host) > 45:
                            resolved_host = resolved_host[:42] + "..."
                        
                        # Format speeds
                        rx_speed_str = f"{target_rx_rate:.1f} Kbps" if target_rx_rate >= 0.1 else "0.0 Kbps"
                        tx_speed_str = f"{target_tx_rate:.1f} Kbps" if target_tx_rate >= 0.1 else "0.0 Kbps"
                        
                        print(f"   {resolved_host:<48} {stats['port']:<8} {rx_speed_str:<13} {tx_speed_str:<13}")
                        
            print("=" * 85)
            
            # Short sleep to complete a ~2.0 second cycle
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped. Exiting monitoring process.")
        sys.exit(0)

if __name__ == "__main__":
    main()
