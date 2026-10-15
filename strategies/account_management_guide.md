# Account & Multi-Peer Management Guide
**Author:** Professional Network Engineer  
**Scope:** Email-based account provisioning, multi-device management, live bandwidth accounting, and automatic quota enforcement.

---

## 1. System Architecture & Resource Efficiency

To run effectively on low-cost VPS instances (e.g., 1 vCPU, 512MB–1GB RAM), this project completely avoids heavy third-party panels (Node.js/Electron, PostgreSQL, Redis) which waste 300MB–600MB RAM.

Instead, it uses an **Ultra-Lean Native Kernel Architecture**:
* **Storage:** Embedded SQLite (`/config/vpn.db`) with Write-Ahead Logging (WAL) & zero background memory footprint.
* **Key Engine:** Native Curve25519 cryptographic key generation (`wg genkey` / `x25519`).
* **Hot-Reload:** Live interface modification via kernel Netlink (`wg set wg0 peer ...`) with **0ms downtime** and no container restarts.
* **Usage Accounting:** Reads kernel hardware counters directly via `wg show wg0 dump` (< 1ms execution, < 0.05% CPU).

```
+--------------------------------------------------------------------------+
| Linux Host VPS (Kernel: WireGuard wg0, FQ Queue, TCP BBR)                |
+--------------------------------------------------------------------------+
                                    ▲
                   (wg set Netlink commands: <1ms)
                                    ▼
+--------------------------------------------------------------------------+
| Container: gaming-wireguard                                              |
|                                                                          |
|  1. /config/vpn.db (SQLite3, 0MB daemon overhead)                        |
|     - Accounts: email (unique PK), tier (free/pro), daily/monthly limits |
|     - Devices: max 2 peers per account, static 10.0.0.X IP, pubkey       |
|     - Usage: persistent daily & monthly byte accumulation                |
|                                                                          |
|  2. CLI Engine (manage_vpn.py / ./vpn-admin)                             |
|                                                                          |
|  3. Web Management Portal & Quota Daemon (:10000)                        |
+--------------------------------------------------------------------------+
```

---

## 2. Cryptographic Rule: 1 Account $\rightarrow$ Max 2 Distinct Peers

In WireGuard's Cryptographic Key Routing:
* Every active device **must have its own unique private key and internal IP** (e.g., `10.0.0.2` and `10.0.0.3`).
* Sharing the same config across 2 simultaneous devices causes endpoint hijacking, packet loss, and disconnects.
* Therefore, MadaCore VPN manages **1 Email Account $\rightarrow$ up to 2 distinct Devices** (e.g. `pc` and `phone`). Attempting to add a 3rd device is blocked automatically.

---

## 3. Administrator CLI Quick Reference (`./vpn-admin`)

On your VPS host, you can manage everything directly using `./vpn-admin`:

### Create Account & Devices in 1 Command
```bash
./vpn-admin create-user gamer1@gmail.com --tier free --devices pc,phone
```
* Generates keys and allocates consecutive IPs (`10.0.0.2`, `10.0.0.3`).
* Injects peers live into the running WireGuard interface.
* Saves `.conf` profiles to `/config/clients/gamer1@gmail.com/`.

### List All Users & Live Usage
```bash
./vpn-admin list-users
```
Outputs a clean table with emails, tiers, device count, today's usage, quota progress bar, and status (`ACTIVE` or `QUOTA_EXCEEDED`).

### Display Client Config (.conf)
```bash
./vpn-admin show-config gamer1@gmail.com pc
```

### Display Terminal QR Code for Mobile App
```bash
./vpn-admin show-qr gamer1@gmail.com phone
```

### Add a Device to an Existing Account
```bash
./vpn-admin add-device gamer1@gmail.com laptop
```
*(Fails automatically if the account already has 2 devices).*

### Reset Usage Quota (Restore Access)
```bash
./vpn-admin reset-quota gamer1@gmail.com
```

### Upgrade Tier (Free $\leftrightarrow$ Pro)
```bash
./vpn-admin upgrade-user gamer1@gmail.com --tier pro
```

### Delete Device or Account
```bash
./vpn-admin delete-device gamer1@gmail.com phone
./vpn-admin delete-user gamer1@gmail.com
```

---

## 4. Web Dashboard & Management Portal

The container serves an integrated dashboard at port `10000`:
* **Live Traffic Monitor:** Real-time download/upload speeds, direct ping RTT latency, jitter, and active gaming route destinations.
* **Accounts & Quotas Tab:**
  * Add accounts with 1 click.
  * Download `.conf` files directly from the browser.
  * Instant QR code modal for scanning on mobile phones.
  * Live quota progress bars (e.g. `650 MB / 2,048 MB`).
  * Instant Quota Reset and Tier Upgrade buttons.

### Accessing the Web Dashboard
* **Via SSH Tunnel (Most Secure):**
  ```bash
  ssh -L 10000:localhost:10000 root@<YOUR_VPS_IP>
  ```
  Then open `http://localhost:10000` in your web browser.
* **Direct Public Access:**
  In `.env`, set `MONITOR_BIND=0.0.0.0` and open port `10000` in your VPS firewall.

---

## 5. Tier Quota Specifications

| Tier | Data Allowance | Reset Schedule | Intended Usage |
| :--- | :--- | :--- | :--- |
| **Free** | **2 GB / Day** | Midnight UTC (Every 24 hours) | Unlimited gaming (CS2, Dota 2, Valorant use ~50-100 MB/hr) while blocking video/torrent abuse. |
| **Pro** | **200 GB / Month** | 1st day of every month | Heavy gaming, full-tunnel routing, Discord voice, and game updates. |

When an account hits their quota, the background daemon automatically drops the peer from the live WireGuard interface. The moment the reset window arrives (midnight UTC) or an admin clicks "Reset Quota", access is automatically restored.
