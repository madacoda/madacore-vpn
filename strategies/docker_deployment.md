# Docker Deployment Strategy for Gaming VPN
**Author:** Professional Network Engineer  
**Architecture:** Containerized WireGuard with Host-Kernel Integration  
**Goal:** Achieve rapid, repeatable, and clean deployment of our gaming VPN on any KVM VPS while maintaining bare-metal networking speeds.

> [!NOTE]
> Looking for step-by-step deployment and configuration instructions? See the [Step-by-Step Setup Guide](file:///c:/laragon/www/madacore-vpn/strategies/user_setup_guide.md).

---

## 1. Containerization & Networking Strategy

Deploying WireGuard inside Docker is highly strategic because it isolates the VPN software, configuration, and client keys from the host operating system, making migrations, updates, and backups trivial.

However, to avoid adding latency or CPU overhead, we must adhere to the following networking principles:

1. **Host Kernel Integration**: The Docker container must use the host kernel's native WireGuard module rather than a user-space fallback (`wireguard-go`). This is achieved by mounting `/lib/modules` from the host.
2. **Network Administration Capabilities**: The container requires the `NET_ADMIN` capability to manipulate the host network interfaces and routing tables (`iptables`).
3. **Port Forwarding**: Bind the WireGuard UDP port directly to the host IP to minimize Docker bridge network latency.

---

## 2. Docker Compose Configuration (`docker-compose.yml`)

We will use the highly optimized `linuxserver/wireguard` image, which automatically builds kernel modules if missing and provides easy environment configurations.

```yaml
version: '3.8'

services:
  wireguard:
    image: lscr.io/linuxserver/wireguard:latest
    container_name: gaming-wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE # Allow container to load WireGuard kernel module if needed
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Etc/UTC             # Change to your VPS timezone
      - SERVERURL=auto         # Will auto-detect VPS public IP, or replace with your VPS IP
      - SERVERPORT=51820       # WireGuard Port
      - PEERS=1                # Number of clients to generate (e.g., your gaming PC)
      - PEERDNS=1.1.1.1,8.8.8.8
      - INTERNAL_SUBNET=10.0.0.0
      - ALLOWEDIPS=0.0.0.0/0   # Configured on server-side; client-side split-tunneling is handled in client config
    ports:
      - 51820:51820/udp        # Bind directly to host network interface
    volumes:
      - ./config:/config       # Persist configs, client configurations, and keys
      - /lib/modules:/lib/modules:ro # Mount host kernel modules for kernel-space performance
    sysctls:
      # Enable packet forwarding inside the container namespace
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv4.ip_forward=1
    restart: unless-stopped
```

---

## 3. Automated Strategic Deployment Script (`deploy.sh`)

This script automates the entire setup of the host, including sysctl optimizations (from our main strategy), installing Docker, and starting the WireGuard container.

```bash
#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "========================================="
echo "   Gaming VPN - Strategic Docker Deploy  "
echo "========================================="

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# 2. Apply Host Kernel Optimizations (Crucial for Low Latency)
echo "[*] Optimizing Host Kernel Network Stack..."
cat <<EOF > /etc/sysctl.d/99-gaming-vpn.conf
# Increase max OS receive/send buffer sizes for UDP
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 10000

# Enable BBR TCP Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
EOF

sysctl --system

# Set transmit queue length on host ethernet adapter
DEFAULT_INTERFACE=$(ip route show default | awk '/default/ {print $5}')
if [ -n "$DEFAULT_INTERFACE" ]; then
  echo "[*] Tuning transmit queue length on interface: $DEFAULT_INTERFACE"
  ip link set dev "$DEFAULT_INTERFACE" txqueuelen 10000
else
  echo "[!] Warning: Could not detect default network interface to set txqueuelen"
fi

# 3. Install Docker & Docker Compose if not present
if ! [ -x "$(command -v docker)" ]; then
  echo "[*] Installing Docker..."
  curl -fsSL https://get.docker.com -o get-docker.sh
  sh get-docker.sh
  rm get-docker.sh
else
  echo "[+] Docker is already installed."
fi

# 4. Spin up the VPN Container Stack
echo "[*] Starting WireGuard container..."
docker compose up -d

echo "========================================="
echo "   Deployment Complete!                  "
echo "========================================="
echo "To display the QR code for your gaming client, run:"
echo "  docker exec -it gaming-wireguard /app/show-peer 1"
echo ""
echo "Your client config file is located at:"
echo "  $(pwd)/config/peer1/peer1.conf"
echo "========================================="
```

---

## 4. Managing Client Profiles & Custom Routing

Once deployed, the `linuxserver/wireguard` container auto-generates client configuration profiles inside the `./config/` directory.

### Retrieving Client Configs
1. **Text File**: Download `./config/peer1/peer1.conf` using SFTP or SCP to your Windows gaming machine.
2. **QR Code**: If you want to connect a mobile device or scan it quickly:
   ```bash
   docker exec -it gaming-wireguard /app/show-peer 1
   ```

### Custom Client Setup (Applying the Split Tunnel)
Open the generated `./config/peer1/peer1.conf` and modify the `AllowedIPs` line under `[Peer]` to include only your targeted game subnets (e.g. Valve/Riot) as detailed in [gaming_vpn_strategy.md](file:///c:/laragon/www/madacore-vpn/strategies/gaming_vpn_strategy.md#L143-L177):

```ini
# Edit on your Windows Machine client:
[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <VPS_IP>:51820
AllowedIPs = 103.28.54.0/24, 103.10.124.0/23, 45.121.184.0/23, 16.228.0.0/15, 15.177.0.0/16
```

---

## 5. Strategic Benefits of Docker Deployment
* **Zero Host Contamination**: Deleting the VPN is as simple as `docker compose down -v`. Your VPS remains clean.
* **Easy Scaling**: To add players (e.g. squadmates sharing the route), increase `PEERS=3` in `docker-compose.yml` and run `docker compose up -d`.
* **Automatic Recovery**: Docker's `restart: unless-stopped` automatically restarts WireGuard if the VPS crashes or reboots.

---

## 6. GitHub Actions & GHCR Deployment Pipeline

To align with the deployment pattern used in `madacore-go`, we deploy the VPN using GitHub Container Registry (GHCR) and GitHub Actions.

### Deployment Flow
1. **GitHub Push**: When code is pushed to `main`, a GitHub Actions workflow is triggered.
2. **GHCR Build & Push**: A custom Docker image is built from the [Dockerfile](file:///c:/laragon/www/madacore-vpn/Dockerfile) and pushed to `ghcr.io`.
3. **Automated SCP**: The deployment environment copies [docker-compose.prod.yml](file:///c:/laragon/www/madacore-vpn/docker-compose.prod.yml) to the target folder (`/var/www/madacore-vpn`) on the VPS.
4. **SSH Optimization & Launch**:
   - The workflow SSHs into the VPS host, writes/applies kernel optimizations (`sysctl`), sets network queues (`txqueuelen`), logs into GHCR, pulls the new image, and runs `docker compose -f docker-compose.prod.yml up -d`.

The workflow is fully defined in [.github/workflows/deploy.yml](file:///c:/laragon/www/madacore-vpn/.github/workflows/deploy.yml).

---

## 7. Credential & Secret Management

> [!WARNING]
> **DO NOT commit raw credentials (SSH Keys, Host IPs, or Passwords) to Git.**
> Committing secrets to a public or private repository is a high security vulnerability.

### Where to Store Credentials?
1. **VPS SSH Access (GitHub Side)**: 
   Go to your GitHub Repository $\rightarrow$ **Settings** $\rightarrow$ **Secrets and variables** $\rightarrow$ **Actions** $\rightarrow$ **New repository secret**. Define:
   * `SERVER_HOST`: The public IP address of your VPS.
   * `SERVER_USER`: The username used to SSH (e.g., `root` or a dedicated deployment user).
   * `SSH_PRIVATE_KEY`: Your SSH private key (ensure the public key is in `/root/.ssh/authorized_keys` on the VPS).
   * `SSH_PASSPHRASE`: (Optional) If your SSH key is passphrase protected.
   * `GHCR_PAT`: A GitHub Personal Access Token with `write:packages` and `read:packages` scopes (used for registry authentication).

2. **VPN Environment Configuration (Server Side)**:
   * Keep `.env` listed in [.gitignore](file:///c:/laragon/www/madacore-vpn/.gitignore) so it is never pushed to GitHub.
   * A local template is provided in [.env.example](file:///c:/laragon/www/madacore-vpn/.env.example).
   * During the first deployment, the GitHub Actions script will auto-generate a `.env` file on the VPS containing default configurations if it is not present. You can edit this directly on the VPS `/var/www/madacore-vpn/.env` to customize settings like the listen port or number of peers.

---

## 8. Post-Deployment Manual Actions Checklist

While the deployment is fully automated, there are three items that must be handled manually after the pipeline runs successfully:

### 1. Provider-Level Firewall / Security Groups (Crucial)
Most VPS providers (DigitalOcean, AWS, Vultr, Linode) block all ports by default.
* **Action Required**: Log in to your VPS provider dashboard. Under the Networking/Firewall settings for your VPS instance, add an **Inbound Rule** allowing:
  * **Protocol**: `UDP`
  * **Port Range**: `51820` (or whatever `WG_PORT` is set to in your `.env`)
  * **Source**: `0.0.0.0/0` (Anywhere)

### 2. Retrieve Client WireGuard Profile
Because client configuration files are generated dynamically inside the container's volume for security, you must extract them from the VPS:
* **Option A (Secure Copy via SCP)**:
  Use a client like WinSCP, FileZilla, or terminal command to download the config file:
  ```bash
  scp root@<YOUR_VPS_IP>:/var/www/madacore-vpn/config/peer1/peer1.conf ./
  ```
* **Option B (Scan QR Code via Terminal)**:
  SSH into the VPS and execute the helper script inside the container to display the QR code directly:
  ```bash
  docker exec -it gaming-wireguard /app/show-peer 1
  ```

### 3. Verification of Kernel Modifications
Confirm that the optimization rules were applied successfully on the VPS host:
```bash
# Check if BBR is active
sysctl net.ipv4.tcp_congestion_control
# Should output: net.ipv4.tcp_congestion_control = bbr

# Check if interface queue length is updated
ip link show | grep txqueuelen
# Look for 'txqueuelen 10000' on your default interface (e.g. eth0)
```

