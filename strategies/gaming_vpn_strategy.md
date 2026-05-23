# Gaming VPN Implementation Strategy
**Author:** Professional Network Engineer  
**Target Games:** Dota 2, Counter-Strike 2 (CS2), Valorant  
**Goal:** Minimize latency, eliminate packet loss/jitter, and prevent ping spikes using a self-hosted Virtual Private Server (VPS).

> [!NOTE]
> For direct installation and execution instructions, please refer directly to the [Step-by-Step Setup Guide](file:///c:/laragon/www/madacore-vpn/strategies/user_setup_guide.md).

---

## 1. Executive Summary & Architecture

To achieve a stable gaming connection over a VPS, standard VPN configurations (like default OpenVPN or general-purpose WireGuard setups) are insufficient. They often route all system traffic, leading to bufferbloat, packet overhead, and routing inefficiencies. 

Our strategy uses a **Split-Tunnel kernel-space WireGuard VPN** combined with **Linux Kernel Network Stack Tuning** and **MTU Optimization**. This ensures that only game traffic is routed through the VPS, leaving browser traffic, voice chats (Discord), and system updates to run on your local internet connection.

### Architectural Diagram

```mermaid
graph TD
    subgraph Client System (Windows)
        AppDota[Dota 2 / Steam] -->|Game Traffic| WGClient[WireGuard Client]
        AppCS2[CS2 / Steam] -->|Game Traffic| WGClient
        AppVal[Valorant / Riot] -->|Game Traffic| WGClient
        AppDiscord[Discord / Web Browser] -->|Non-Game Traffic| LocalISP[Local ISP Gateway]
    end

    subgraph Tunnel
        WGClient -->|Encapsulated UDP / MTU 1420| WGServer[WireGuard Server]
    end

    subgraph VPS (Debian/Ubuntu Linux)
        WGServer -->|IP Forwarding / iptables NAT| KernelTuning[Kernel Stack Optimizations]
        KernelTuning -->|Optimized Routing| Internet[Transit Providers / IXPs]
    end

    Internet -->|Direct Peering| Valve[Valve Servers (Dota2/CS2)]
    Internet -->|Direct Peering| Riot[Riot Games (Valorant)]
    LocalISP -->|General Route| InternetPublic[Public Web]
```

---

## 2. Phase 1: VPS Provider & Location Selection

Choosing the right VPS host is the most critical decision. If your VPS has bad routing to your home ISP or the game servers, the VPN will increase your ping instead of lowering it.

### Selection Criteria
1. **Physical Location**: 
   - Identify where the game servers are located (e.g., Singapore, Tokyo, Frankfurt, Chicago).
   - Rent a VPS located in the **same city** as the game servers, or at a major **network hub/transit point** between you and the game servers.
2. **Network Peerings**:
   - Choose providers with premium network transit (e.g., Tier 1 providers like GTT, Level3, Cogent) and direct peering with your ISP.
   - Excellent VPS hosts for gaming routes include: **Vultr (High Frequency)**, **Linode/Akamai**, **DigitalOcean**, or game-route specialized providers like **G-Core** or **OVH Cloud** (highly optimized anti-DDoS).
3. **Virtualization Type**:
   - Ensure the VPS uses **KVM (Kernel-based Virtual Machine)** virtualization. Avoid OpenVZ, as it prevents modifying custom kernel parameters and loading custom WireGuard kernel modules.

### Pre-Deployment Verification
Before purchasing, run a traceroute and ping test from your home connection to the VPS provider's looking-glass IP.
```powershell
# Windows PowerShell command to test latency jitter and route
Test-NetConnection -ComputerName <VPS_LOOKING_GLASS_IP> -TraceRoute
```
Look for:
- Stable round-trip time (RTT).
- Zero packet loss.
- Minimal hops (< 12 hops is ideal).

---

## 3. Phase 2: VPS Server Optimization (Linux OS)

Once your VPS (running **Ubuntu 24.04 LTS** or **Debian 12**) is online, apply these low-level network stack modifications to optimize for real-time UDP packet delivery.

### 3.1 Kernel Network Tuning (`/etc/sysctl.conf`)
By default, Linux network queues are optimized for high-throughput TCP (like web servers) rather than low-latency, small-packet UDP (gaming). Add the following parameters:

```ini
# Enable IP Forwarding for NAT
net.ipv4.ip_forward = 1

# Increase max OS receive/send buffer sizes for UDP packets
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# Adjust max backlog queue sizes to avoid packet drops under load
net.core.netdev_max_backlog = 10000

# Enable BBR Congestion Control (highly effective at managing packet loss)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

Apply these settings:
```bash
sudo sysctl -p
```

### 3.2 Network Interface Queue Optimization
Increase the transmit queue length (`txqueuelen`) of your VPS physical ethernet interface (e.g., `eth0`) to prevent packet buffer overflows.
```bash
# Check current configuration
ip link show eth0

# Temporarily set queue length to 10000 (add to /etc/rc.local for persistence)
sudo ip link set dev eth0 txqueuelen 10000
```

---

## 4. Phase 3: WireGuard VPN Configuration & Deployment

You can deploy the WireGuard server either **Natively** or via **Docker**. For modern server maintenance and automated setup, the **Docker method is highly recommended**.

* **Recommended Option**: Proceed to our [Docker Deployment Strategy](file:///c:/laragon/www/madacore-vpn/strategies/docker_deployment.md) for a containerized stack setup and deployment script.
* **Alternative Option**: Proceed below for a native host-based installation.

### 4.1 Native Host-Based Installation (Alternative)
Install WireGuard:
```bash
sudo apt update && sudo apt install -y wireguard
```

Generate server keys:
```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

Create the WireGuard configuration file `/etc/wireguard/wg0.conf`:
```ini
[Interface]
PrivateKey = <INSERT_SERVER_PRIVATE_KEY>
Address = 10.0.0.1/24
ListenPort = 51820

# NAT Forwarding Rules (adjust 'eth0' to match your VPS interface name)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Client Configuration
PublicKey = <INSERT_CLIENT_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
```

Enable and start the WireGuard service:
```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```

---

## 5. Phase 4: Client Configuration & Split Tunneling

To ensure that only your games route through the VPS, we must configure **Split Tunneling** on the client.

### 5.1 WireGuard Client Config (`gaming-vpn.conf`)
Download the official WireGuard client for Windows. Create your configuration as follows:

```ini
[Interface]
PrivateKey = <INSERT_CLIENT_PRIVATE_KEY>
Address = 10.0.0.2/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = <INSERT_SERVER_PUBLIC_KEY>
Endpoint = <YOUR_VPS_PUBLIC_IP>:51820
# Only route game server IPs through the tunnel
AllowedIPs = <GAME_SERVER_IP_RANGES>
```

### 5.2 Finding Game Server IP Ranges
Do **NOT** use `0.0.0.0/0` in `AllowedIPs` as it will route all PC traffic through the VPN. Instead, input the specific subnet ranges for your gaming regions:

| Game | Region | Typical Server IP Subnets (AllowedIPs) |
| :--- | :--- | :--- |
| **Dota 2 / CS2** | Southeast Asia (Singapore) | `103.28.54.0/24`, `103.10.124.0/23`, `45.121.184.0/23` |
| **Dota 2 / CS2** | Europe (Luxembourg/Vienna) | `146.66.152.0/21`, `185.25.180.0/22`, `162.254.192.0/21` |
| **Valorant** | AP South / Singapore | `16.228.0.0/15`, `15.177.0.0/16`, `99.83.128.0/17` |
| **Valorant** | NA East | `192.207.0.0/16`, `54.239.0.0/16`, `52.94.0.0/15` |

> [!TIP]
> **How to capture your exact game server IP:**
> 1. Launch the game and connect to a match.
> 2. Open PowerShell as Administrator and run:
>    `Get-NetUDPEndpoint -OwningProcess (Get-Process | Where-Object {$_.Name -eq "dota2" -or $_.Name -eq "cs2" -or $_.Name -eq "VALORANT"}).Id | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort`
> 3. Identify the server IP and add its subnet (usually `/24`) to your WireGuard client's `AllowedIPs` list.

---

## 6. Phase 5: Crucial Optimization & Troubleshooting Tuning

### 6.1 MTU Clamping (Addressing Packet Fragmentation)
Real-time games send very high packet frequencies. If a packet is larger than the network's Maximum Transmission Unit (MTU), it gets fragmented. Fragmentation causes packet buffering, resulting in severe ping spikes and rubber-banding.

1. Find your local internet interface MTU (usually `1500` or `1492`).
2. Set the WireGuard MTU to account for the encapsulation overhead:
   - For **IPv4**: `Local MTU - 60 bytes` (e.g., `1500 - 60 = 1440` or safer: `1420`).
   - For **IPv6**: `Local MTU - 80 bytes` (e.g., `1400` or `1360`).
3. Add MTU clamping rules on the VPS iptables firewall to force TCP/UDP segments to comply:
   ```bash
   sudo iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
   ```

### 6.2 Packet Loss Mitigation with Forward Error Correction (FEC) (Optional - Advanced)
If your underlying local ISP connection is prone to packet loss, even a direct VPN route will suffer. You can run **UDPSpeeder** on top of WireGuard.
* **What it does**: It duplicates UDP packets at a ratio (e.g., `1:1.5` or `1:2`). If your ISP drops 5% of packets, UDPSpeeder reconstructs the lost packets using the redundant duplicates, reducing virtual packet loss to `0%` at the expense of extra bandwidth.
* **Flow**: Game Client $\rightarrow$ Local UDPSpeeder (Client) $\rightarrow$ WireGuard $\rightarrow$ VPS UDPSpeeder (Server) $\rightarrow$ Game Server.

---

## 7. Action Plan Checklist

- [ ] **Step 1:** Run Looking Glass / Ping tests to potential VPS providers to find the lowest-latency node.
- [ ] **Step 2:** Purchase KVM-based VPS near the game server region.
- [ ] **Step 3:** Apply the sysctl kernel optimization parameters.
- [ ] **Step 4:** Install and configure WireGuard server.
- [ ] **Step 5:** Configure WireGuard Windows client with game-specific `AllowedIPs` (Split-Tunneling).
- [ ] **Step 6:** Fine-tune client MTU (start with `1420` and adjust down if packet drops occur).
- [ ] **Step 7:** Run in-game diagnostics (e.g., CS2 network graph, Valorant network stats overlay) to verify the RTT and packet loss.
