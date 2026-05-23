# MadaCore VPN - Gaming Optimized WireGuard
A self-hosted, containerized, and kernel-optimized WireGuard VPN solution tailored specifically to eliminate ping spikes, reduce jitter, and stabilize routes for multiplayer online games like **Dota 2**, **Counter-Strike 2 (CS2)**, and **Valorant**.

---

## 🚀 Key Features

* **Gaming-Grade Low Latency:** Configured natively in Linux kernel space (via Docker host bindings) to bypass user-space latency overhead.
* **Linux Kernel Tuning:** Automatically adjusts system parameters (`sysctl` network buffers, transmit queue lengths `txqueuelen`, and TCP BBR) on the host VPS.
* **Smart Split-Tunneling:** Routes only the target game servers through the low-ping VPS pathway, keeping regular web browsing, downloads, and Discord direct via your local ISP.
* **MTU Clamping & FEC:** Minimizes packet fragmentation and manages packet-loss recovery using Forward Error Correction (FEC) strategies.
* **Strategic CI/CD Deployment:** Employs the `madacore-go` GitHub Actions workflow pattern, compiling your custom container registry setup via GitHub Packages (GHCR) and pushing updates automatically.

---

## 📂 Project Structure

```text
├── .github/workflows/
│   └── deploy.yml          # GitHub Actions CI/CD deployment pipeline
├── strategies/
│   ├── gaming_vpn_strategy.md   # Core network architecture & UDP optimizations
│   ├── docker_deployment.md     # Containerization, GHCR, & host-kernel bindings
│   └── user_setup_guide.md      # Step-by-step VPS & Windows setup guide
├── Dockerfile              # GHCR deployment container config
├── docker-compose.prod.yml # Production Docker-Compose stack config
├── .env.example            # Environment variables template
└── .gitignore              # Protects configuration files and private keys
```

---

## 🛠️ Quick Start

### 1. Read the Detailed Strategies & Guides
For complete technical implementation details and instructions, review:
* 📖 [Gaming VPN Network Strategy](file:///c:/laragon/www/madacore-vpn/strategies/gaming_vpn_strategy.md) — Network architecture and kernel optimization concepts.
* 📦 [Docker & CI/CD Strategy](file:///c:/laragon/www/madacore-vpn/strategies/docker_deployment.md) — Containerization, GitHub Actions integration, and security.
* 🎮 [Step-by-Step Setup Guide](file:///c:/laragon/www/madacore-vpn/strategies/user_setup_guide.md) — Step-by-step instructions for your VPS and Windows system.

### 2. Configure GitHub CD Secrets
Go to your repository **Settings** $\rightarrow$ **Secrets and variables** $\rightarrow$ **Actions** and add the following repository secrets to activate automated deployments on every `git push`:
* `SERVER_HOST` - Your VPS public IP.
* `SERVER_USER` - The SSH username (e.g. `root`).
* `SSH_PRIVATE_KEY` - The SSH private key allowed on the server.
* `GHCR_PAT` - A Personal Access Token (classic) with package read/write permissions.

### 3. Deploy
Commit your files and push to your remote GitHub repository:
```bash
git add .
git commit -m "feat: initial gaming vpn stack"
git branch -M main
git push -u origin main
```

### 4. Import & Go
Once deployed, retrieve the Windows client configuration file (`peer1.conf`) from your VPS, import it into the Windows [WireGuard Client](https://www.wireguard.com/install/), update your `AllowedIPs` for game routes, and turn it on!
