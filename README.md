# MadaCore VPN - Gaming Optimized WireGuard & Multi-Peer Management
A self-hosted, containerized, and kernel-optimized WireGuard VPN solution tailored specifically to eliminate ping spikes, reduce jitter, and stabilize routes for multiplayer online games like **Dota 2**, **Counter-Strike 2 (CS2)**, and **Valorant** — now with built-in **Multi-Account & Peer Management**, strict 2-device limits, and automated bandwidth quota enforcement.

---

## 🚀 Key Features

* **Gaming-Grade Low Latency:** Configured natively in Linux kernel space (via Docker host bindings) to bypass user-space latency overhead.
* **Email-Based Account Management:** Unique account identification with strict enforcement of **maximum 2 simultaneous devices per user**.
* **Zero-Downtime Hot Reloading:** Instant peer provisioning and deletion in kernel memory (`wg set`) with **0ms downtime** and zero container restarts.
* **Resource-Efficient Quota Tracking:** Embedded SQLite (`vpn.db`) with zero external daemon overhead (< 15 MB RAM total), auto-enforcing **Free Tier (2 GB/day)**, **Pro Tier (200 GB/month)**, and **Adaw Tier (Unlimited)** bandwidth policies.
* **Integrated Web Dashboard & REST API:** Real-time throughput speeds, direct ping RTT/jitter, active gaming routes, in-browser QR code scanner, and one-click `.conf` downloads at port `10000`.
* **Host CLI Tool (`./vpn-admin`):** Full administrator command-line suite for managing users, exporting profiles, and scanning terminal QR codes directly on your VPS.
* **Linux Kernel Tuning:** Automatically adjusts system parameters (`sysctl` network buffers, transmit queue lengths `txqueuelen`, and TCP BBR) on the host VPS.
* **Smart Split-Tunneling:** Routes only the target game servers through the low-ping VPS pathway, keeping regular web browsing, downloads, and Discord direct via your local ISP.

---

## 📂 Project Structure

```text
├── .github/workflows/
│   └── deploy.yml               # GitHub Actions CI/CD deployment pipeline
├── strategies/
│   ├── account_management_guide.md # Multi-account, CLI reference & quota enforcement
│   ├── gaming_vpn_strategy.md   # Core network architecture & UDP optimizations
│   ├── docker_deployment.md     # Containerization, GHCR, & host-kernel bindings
│   ├── user_setup_guide.md      # Step-by-step VPS & Windows setup guide
│   ├── vpn_manager.py           # Core SQLite & WireGuard kernel controller engine
│   ├── manage_vpn.py            # Administrative CLI tool
│   └── monitor_web.py           # Real-time traffic monitor & management portal (:10000)
├── tests/
│   ├── test_vpn_manager.py      # Unit tests for account lifecycle & quotas
│   └── test_api.py              # Unit tests for Web REST API
├── Dockerfile                   # Custom WireGuard + Python + SQLite image
├── docker-compose.prod.yml      # Production stack configuration
├── manage_vpn.py                # Root CLI shortcut
├── vpn-admin                    # VPS host wrapper script (Linux bash)
├── vpn-admin.ps1                # Windows / PowerShell wrapper script
├── .env.example                 # Environment variables template
└── .gitignore                   # Protects configuration files and private keys
```

---

## 🛠️ Quick Start

### 1. Read the Detailed Strategies & Guides
For complete technical implementation details and instructions, review:
* 👥 [Account & Multi-Peer Management Guide](file:///c:/laragon/www/madacore-vpn/strategies/account_management_guide.md) — How to create accounts, manage devices, and enforce quotas.
* 📖 [Gaming VPN Network Strategy](file:///c:/laragon/www/madacore-vpn/strategies/gaming_vpn_strategy.md) — Network architecture and kernel optimization concepts.
* 📦 [Docker & CI/CD Strategy](file:///c:/laragon/www/madacore-vpn/strategies/docker_deployment.md) — Containerization, GitHub Actions integration, and security.
* 🎮 [Step-by-Step Setup Guide](file:///c:/laragon/www/madacore-vpn/strategies/user_setup_guide.md) — Step-by-step instructions for your VPS and Windows system.

### 2. Managing Users & Devices via CLI
On your VPS, execute the `./vpn-admin` helper:

```bash
# Provision a user with PC and Phone configs in 1 command:
./vpn-admin create-user player1@gmail.com --tier free --devices pc,phone

# List all users, device counts, live bandwidth, and quota progress:
./vpn-admin list-users

# Print mobile QR code in terminal:
./vpn-admin show-qr player1@gmail.com phone

# Reset daily quota or upgrade tier (free/pro/adaw):
./vpn-admin reset-quota player1@gmail.com
./vpn-admin upgrade-user player1@gmail.com --tier adaw
```

### 3. Web Management Portal
Navigate to `http://<YOUR_VPS_IP>:10000` (or via SSH tunnel `ssh -L 10000:localhost:10000 root@<YOUR_VPS_IP>`):
* **Live Traffic Tab:** View current throughput, ping latency, jitter, and active gaming server targets.
* **Accounts Tab:** Add users, download `.conf` profiles, scan QR codes on mobile, and manage quotas.

### 4. Deploy via GitHub Actions
Add repository secrets (`SERVER_HOST`, `SERVER_USER`, `SSH_PRIVATE_KEY`, `GHCR_PAT`) and push to main:
```bash
git add .
git commit -m "feat: complete multi-account management with 2-device limit and quotas"
git push origin main
```
