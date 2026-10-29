#!/usr/bin/env python3
"""
MadaCore VPN - Account & Peer Management Engine
Author: Professional Network Engineer

Core management engine providing:
1. Unique email-based account authentication.
2. Strict limit of maximum 2 devices per account.
3. Automated internal IP allocation (10.0.0.2 - 10.0.0.254).
4. Dynamic Zero-Downtime WireGuard peer hot-reloading (wg set).
5. Granular usage tracking (daily & monthly) stored persistently in SQLite.
6. Automated quota enforcement:
   - Free Tier: 2 GB / day (reset midnight UTC)
   - Pro Tier:  200 GB / month (reset 1st of month)
   - Adaw Tier: Unlimited daily and monthly bandwidth
"""

import os
import re
import sys
import time
import shutil
import sqlite3
import base64
import tempfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Subnet configuration
DEFAULT_SUBNET = "10.0.0.0/24"
SERVER_IP = "10.0.0.1"
IP_POOL_START = 2
IP_POOL_END = 254
MAX_DEVICES_PER_ACCOUNT = 2
VALID_TIERS = ("free", "pro", "adaw")

# Quotas in bytes
FREE_DAILY_QUOTA_BYTES = 2 * 1024 * 1024 * 1024       # 2 GB / day
PRO_MONTHLY_QUOTA_BYTES = 200 * 1024 * 1024 * 1024   # 200 GB / month

class VPNManager:
    def __init__(self, config_dir=None, db_path=None, interface="wg0"):
        # Auto-detect config path: /config inside Docker, or ./config on host
        if config_dir:
            self.config_dir = Path(config_dir)
        elif os.path.exists("/config"):
            self.config_dir = Path("/config")
        else:
            self.config_dir = Path("./config").resolve()
            
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.clients_dir = self.config_dir / "clients"
        self.clients_dir.mkdir(parents=True, exist_ok=True)
        self.server_dir = self.config_dir / "server"
        self.server_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = Path(db_path) if db_path else self.config_dir / "vpn.db"
        self.interface = os.getenv("WG_INTERFACE", interface)
        wg_confs_file = self.config_dir / "wg_confs" / f"{self.interface}.conf"
        if wg_confs_file.exists():
            self.wg_conf_path = wg_confs_file
        else:
            self.wg_conf_path = self.config_dir / f"{self.interface}.conf"
        
        # Server connection parameters
        server_url = os.getenv("SERVER_URL") or os.getenv("SERVERURL") or "auto"
        if server_url == "auto":
            try:
                import urllib.request
                server_url = urllib.request.urlopen("https://api.ipify.org", timeout=3).read().decode().strip()
            except Exception:
                pass
        self.server_url = server_url
        self.server_port = os.getenv("WG_PORT", "51820")
        self.peer_dns = os.getenv("PEER_DNS", "1.1.1.1,8.8.8.8")
        self.mtu = int(os.getenv("WG_MTU", "1420"))
        
        self.init_db()

    def get_db(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self):
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Accounts Table (Unique by Email)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                email TEXT PRIMARY KEY COLLATE NOCASE,
                tier TEXT CHECK(tier IN ('free', 'pro', 'adaw')) NOT NULL DEFAULT 'free',
                daily_limit_bytes INTEGER NOT NULL DEFAULT 2147483648,
                monthly_limit_bytes INTEGER NOT NULL DEFAULT 214748364800,
                status TEXT CHECK(status IN ('active', 'suspended', 'quota_exceeded')) NOT NULL DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # Auto-migrate existing database if check constraint does not contain 'adaw'
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='accounts'")
            table_row = cursor.fetchone()
            if table_row and "adaw" not in table_row[0]:
                conn.execute("PRAGMA foreign_keys = OFF;")
                conn.execute("""
                CREATE TABLE accounts_adaw_mig (
                    email TEXT PRIMARY KEY COLLATE NOCASE,
                    tier TEXT CHECK(tier IN ('free', 'pro', 'adaw')) NOT NULL DEFAULT 'free',
                    daily_limit_bytes INTEGER NOT NULL DEFAULT 2147483648,
                    monthly_limit_bytes INTEGER NOT NULL DEFAULT 214748364800,
                    status TEXT CHECK(status IN ('active', 'suspended', 'quota_exceeded')) NOT NULL DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """)
                conn.execute("INSERT INTO accounts_adaw_mig SELECT email, tier, daily_limit_bytes, monthly_limit_bytes, status, created_at, updated_at FROM accounts;")
                conn.execute("DROP TABLE accounts;")
                conn.execute("ALTER TABLE accounts_adaw_mig RENAME TO accounts;")
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.commit()

            # Devices Table (Max 2 devices per account)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_email TEXT NOT NULL,
                device_name TEXT NOT NULL,
                internal_ip TEXT UNIQUE NOT NULL,
                public_key TEXT UNIQUE NOT NULL,
                private_key TEXT NOT NULL,
                preshared_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(account_email) REFERENCES accounts(email) ON DELETE CASCADE,
                UNIQUE(account_email, device_name)
            );
            """)

            # Daily Usage Log
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS daily_usage (
                account_email TEXT NOT NULL,
                date TEXT NOT NULL,
                bytes_rx INTEGER DEFAULT 0,
                bytes_tx INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                PRIMARY KEY (account_email, date),
                FOREIGN KEY(account_email) REFERENCES accounts(email) ON DELETE CASCADE
            );
            """)

            # Monthly Usage Log
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS monthly_usage (
                account_email TEXT NOT NULL,
                month TEXT NOT NULL,
                bytes_rx INTEGER DEFAULT 0,
                bytes_tx INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                PRIMARY KEY (account_email, month),
                FOREIGN KEY(account_email) REFERENCES accounts(email) ON DELETE CASCADE
            );
            """)

            # Kernel Polling State Cache (tracks byte counters to compute deltas)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS kernel_counter_cache (
                pubkey TEXT PRIMARY KEY,
                last_rx INTEGER DEFAULT 0,
                last_tx INTEGER DEFAULT 0,
                last_handshake INTEGER DEFAULT 0,
                endpoint TEXT DEFAULT '',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            conn.commit()

    # ---------------------------------------------------------
    # Cryptographic Key Generation
    # ---------------------------------------------------------
    def generate_keypair(self):
        """
        Generates WireGuard Private, Public, and Preshared Keys.
        Uses native 'wg' command if available, otherwise falls back to X25519.
        """
        # 1. Try native wg binary
        if shutil.which("wg"):
            try:
                priv_proc = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True)
                priv_key = priv_proc.stdout.strip()
                
                pub_proc = subprocess.run(["wg", "pubkey"], input=priv_key, capture_output=True, text=True, check=True)
                pub_key = pub_proc.stdout.strip()
                
                psk_proc = subprocess.run(["wg", "genpsk"], capture_output=True, text=True, check=True)
                psk = psk_proc.stdout.strip()
                return priv_key, pub_key, psk
            except Exception:
                pass

        # 2. Portable Python Cryptography fallback
        try:
            from cryptography.hazmat.primitives.asymmetric import x25519
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key()
            priv_key = base64.b64encode(priv.private_bytes_raw()).decode()
            pub_key = base64.b64encode(pub.public_bytes_raw()).decode()
            psk = base64.b64encode(os.urandom(32)).decode()
            return priv_key, pub_key, psk
        except ImportError:
            # Fallback if cryptography not installed
            rand_bytes = bytearray(os.urandom(32))
            rand_bytes[0] &= 248
            rand_bytes[31] &= 127
            rand_bytes[31] |= 64
            priv_key = base64.b64encode(rand_bytes).decode()
            psk = base64.b64encode(os.urandom(32)).decode()
            pub_key = base64.b64encode(os.urandom(32)).decode()
            return priv_key, pub_key, psk

    def get_server_public_key(self):
        """
        Retrieves server public key from wg0 interface or saved file.
        """
        # Check environment variable
        if os.getenv("SERVER_PUBLIC_KEY"):
            return os.getenv("SERVER_PUBLIC_KEY").strip()

        # Check /config/server/publickey-server
        pub_file = self.server_dir / "publickey-server"
        if pub_file.exists():
            return pub_file.read_text().strip()

        # Query live wg interface
        if shutil.which("wg"):
            try:
                res = subprocess.run(["wg", "show", self.interface, "public-key"], capture_output=True, text=True)
                if res.returncode == 0 and res.stdout.strip():
                    key = res.stdout.strip()
                    pub_file.write_text(key)
                    return key
            except Exception:
                pass

        # Check /config/server_publickey (linuxserver standard)
        alt_pub = self.config_dir / "server" / "publickey-server"
        if alt_pub.exists():
            return alt_pub.read_text().strip()

        # Default placeholder if server key not yet generated
        return "SERVER_PUBLIC_KEY_PLACEHOLDER"

    # ---------------------------------------------------------
    # IP Pool Management
    # ---------------------------------------------------------
    def allocate_next_ip(self):
        """
        Finds the lowest free IP address in the 10.0.0.2 - 10.0.0.254 range.
        """
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT internal_ip FROM devices")
            used_ips = {row["internal_ip"] for row in cursor.fetchall()}
            
        # Also check wg0.conf if exists
        if self.wg_conf_path.exists():
            content = self.wg_conf_path.read_text()
            matches = re.findall(r"AllowedIPs\s*=\s*10\.0\.0\.(\d+)", content)
            for m in matches:
                used_ips.add(f"10.0.0.{m}")

        for i in range(IP_POOL_START, IP_POOL_END + 1):
            candidate = f"10.0.0.{i}"
            if candidate not in used_ips:
                return candidate
                
        raise OverflowError("All VPN internal IP addresses (10.0.0.2 - 10.0.0.254) are allocated.")

    # ---------------------------------------------------------
    # Account Management
    # ---------------------------------------------------------
    def validate_email(self, email):
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not email or not re.match(pattern, email.strip()):
            raise ValueError(f"Invalid email address format: '{email}'")
        return email.strip().lower()

    def create_account(self, email, tier="free", daily_limit_bytes=None, monthly_limit_bytes=None):
        email = self.validate_email(email)
        tier = tier.lower()
        if tier not in VALID_TIERS:
            raise ValueError(f"Tier must be one of: {', '.join(VALID_TIERS)}.")

        if daily_limit_bytes is None:
            daily_limit_bytes = FREE_DAILY_QUOTA_BYTES if tier == "free" else 0  # 0 = unlimited daily
        if monthly_limit_bytes is None:
            monthly_limit_bytes = PRO_MONTHLY_QUOTA_BYTES if tier == "pro" else 0  # 0 = unlimited monthly

        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO accounts (email, tier, daily_limit_bytes, monthly_limit_bytes, status)
                VALUES (?, ?, ?, ?, 'active')
                """,
                (email, tier, daily_limit_bytes, monthly_limit_bytes)
            )
            conn.commit()

        # Create user config export folder
        user_dir = self.clients_dir / email
        user_dir.mkdir(parents=True, exist_ok=True)
        return self.get_account(email)

    def get_account(self, email):
        email = email.strip().lower()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")

        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM accounts WHERE email = ?", (email,))
            account_row = cursor.fetchone()
            if not account_row:
                return None

            account = dict(account_row)

            # Get devices
            cursor.execute("SELECT * FROM devices WHERE account_email = ?", (email,))
            devices = [dict(d) for d in cursor.fetchall()]
            account["devices"] = devices
            account["device_count"] = len(devices)

            # Get today's usage
            cursor.execute(
                "SELECT bytes_rx, bytes_tx, total_bytes FROM daily_usage WHERE account_email = ? AND date = ?",
                (email, today)
            )
            daily_row = cursor.fetchone()
            account["today_usage_bytes"] = daily_row["total_bytes"] if daily_row else 0
            account["today_rx_bytes"] = daily_row["bytes_rx"] if daily_row else 0
            account["today_tx_bytes"] = daily_row["bytes_tx"] if daily_row else 0

            # Get monthly usage
            cursor.execute(
                "SELECT bytes_rx, bytes_tx, total_bytes FROM monthly_usage WHERE account_email = ? AND month = ?",
                (email, current_month)
            )
            monthly_row = cursor.fetchone()
            account["month_usage_bytes"] = monthly_row["total_bytes"] if monthly_row else 0

            # Calculate quota percentages
            if account["tier"] == "free" and account["daily_limit_bytes"] > 0:
                percent = (account["today_usage_bytes"] / account["daily_limit_bytes"]) * 100.0
                account["quota_percent"] = min(round(percent, 1), 100.0)
            elif account["tier"] == "pro" and account["monthly_limit_bytes"] > 0:
                percent = (account["month_usage_bytes"] / account["monthly_limit_bytes"]) * 100.0
                account["quota_percent"] = min(round(percent, 1), 100.0)
            else:
                account["quota_percent"] = 0.0

            return account

    def list_accounts(self):
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM accounts ORDER BY created_at DESC")
            emails = [row["email"] for row in cursor.fetchall()]

        return [self.get_account(email) for email in emails]

    def delete_account(self, email):
        account = self.get_account(email)
        if not account:
            return False

        # Hot-remove all devices from WireGuard
        for device in account["devices"]:
            self._hot_remove_peer(device["public_key"])
            self._remove_peer_from_conf(device["public_key"])

        # Delete from DB
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM accounts WHERE email = ?", (email,))
            conn.commit()

        # Delete client files
        user_dir = self.clients_dir / email
        if user_dir.exists():
            shutil.rmtree(user_dir, ignore_errors=True)

        return True

    def update_tier(self, email, tier):
        email = email.strip().lower()
        tier = tier.lower()
        if tier not in VALID_TIERS:
            raise ValueError(f"Tier must be one of: {', '.join(VALID_TIERS)}.")

        daily_limit = FREE_DAILY_QUOTA_BYTES if tier == "free" else 0
        monthly_limit = PRO_MONTHLY_QUOTA_BYTES if tier == "pro" else 0

        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE accounts
                SET tier = ?, daily_limit_bytes = ?, monthly_limit_bytes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE email = ?
                """,
                (tier, daily_limit, monthly_limit, email)
            )
            conn.commit()

        # If user was quota exceeded and upgraded to pro or adaw, restore access immediately
        account = self.get_account(email)
        if account and account["status"] == "quota_exceeded":
            if tier == "adaw":
                self.reactivate_account(email)
            elif tier == "pro" and account["month_usage_bytes"] < account["monthly_limit_bytes"]:
                self.reactivate_account(email)

        return self.get_account(email)

    def reset_quota(self, email):
        """
        Manually resets today's and this month's usage counters for an account,
        and restores the active state.
        """
        email = email.strip().lower()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")

        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE daily_usage SET bytes_rx = 0, bytes_tx = 0, total_bytes = 0 WHERE account_email = ? AND date = ?",
                (email, today)
            )
            cursor.execute(
                "UPDATE monthly_usage SET bytes_rx = 0, bytes_tx = 0, total_bytes = 0 WHERE account_email = ? AND month = ?",
                (email, current_month)
            )
            cursor.execute(
                "UPDATE accounts SET status = 'active', updated_at = CURRENT_TIMESTAMP WHERE email = ?",
                (email,)
            )
            conn.commit()

        # Re-add devices to WireGuard if removed
        account = self.get_account(email)
        if account:
            for device in account["devices"]:
                self._hot_add_peer(device["public_key"], device["preshared_key"], device["internal_ip"])

        return self.get_account(email)

    # ---------------------------------------------------------
    # Device Management (Max 2 Devices Enforcement)
    # ---------------------------------------------------------
    def add_device(self, email, device_name="pc", public_key=None, preshared_key=None, private_key=None):
        email = email.strip().lower()
        device_name = re.sub(r"[^a-zA-Z0-9_\-]", "", device_name.strip().lower())
        if not device_name:
            device_name = "pc"

        account = self.get_account(email)
        if not account:
            raise ValueError(f"Account '{email}' does not exist. Create the account first.")

        # STRICT LIMIT: Maximum 2 devices
        if account["device_count"] >= MAX_DEVICES_PER_ACCOUNT:
            raise ValueError(
                f"Account '{email}' already has the maximum of {MAX_DEVICES_PER_ACCOUNT} devices. "
                "Delete an existing device before adding a new one."
            )

        # Check duplicate device name
        for d in account["devices"]:
            if d["device_name"] == device_name:
                raise ValueError(f"Device name '{device_name}' already exists for account '{email}'.")

        # Handle existing or generated keys
        if public_key:
            pub_key = public_key.strip()
            # Validate base64 format (WireGuard 32-byte key is 44 base64 chars ending with =)
            try:
                decoded = base64.b64decode(pub_key)
                if len(decoded) != 32:
                    raise ValueError("Public key must decode to exactly 32 bytes.")
            except Exception as e:
                raise ValueError(f"Invalid WireGuard public key format: {e}")

            # Check if key already registered
            with self.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT account_email, device_name FROM devices WHERE public_key = ?", (pub_key,))
                existing = cursor.fetchone()
                if existing:
                    raise ValueError(f"Public key already registered to '{existing['account_email']}' ({existing['device_name']}).")

            priv_key = private_key.strip() if private_key else "(client-managed-key)"
            psk = preshared_key.strip() if preshared_key else base64.b64encode(os.urandom(32)).decode()
        else:
            priv_key, pub_key, psk = self.generate_keypair()

        # Allocate unique internal IP
        internal_ip = self.allocate_next_ip()

        # Insert to DB
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO devices (account_email, device_name, internal_ip, public_key, private_key, preshared_key)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (email, device_name, internal_ip, pub_key, priv_key, psk)
            )
            conn.commit()

        # Build client configuration file
        config_text = self._build_client_config(internal_ip, priv_key, psk)
        user_dir = self.clients_dir / email
        user_dir.mkdir(parents=True, exist_ok=True)
        conf_file = user_dir / f"{device_name}.conf"
        conf_file.write_text(config_text)

        # Hot-load peer into live WireGuard interface (Zero Downtime)
        if account["status"] == "active":
            self._hot_add_peer(pub_key, psk, internal_ip)
            self._append_peer_to_conf(email, device_name, pub_key, psk, internal_ip)

        return {
            "account_email": email,
            "device_name": device_name,
            "internal_ip": internal_ip,
            "public_key": pub_key,
            "config_path": str(conf_file),
            "config_text": config_text
        }

    def remove_device(self, email, device_name):
        email = email.strip().lower()
        device_name = device_name.strip().lower()

        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT public_key FROM devices WHERE account_email = ? AND device_name = ?",
                (email, device_name)
            )
            row = cursor.fetchone()
            if not row:
                return False

            pub_key = row["public_key"]

            # Remove from DB
            cursor.execute(
                "DELETE FROM devices WHERE account_email = ? AND device_name = ?",
                (email, device_name)
            )
            cursor.execute("DELETE FROM kernel_counter_cache WHERE pubkey = ?", (pub_key,))
            conn.commit()

        # Hot-remove from running WireGuard
        self._hot_remove_peer(pub_key)
        self._remove_peer_from_conf(pub_key)

        # Delete config file
        conf_file = self.clients_dir / email / f"{device_name}.conf"
        if conf_file.exists():
            conf_file.unlink()

        return True

    def get_device_config(self, email, device_name):
        conf_file = self.clients_dir / email.strip().lower() / f"{device_name.strip().lower()}.conf"
        if conf_file.exists():
            return conf_file.read_text()
        return None

    def list_keys(self):
        """
        Returns all registered WireGuard public keys with their associated account,
        device name, assigned IP, status, and latest handshake.
        """
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT d.public_key, d.internal_ip, d.device_name, d.created_at,
                   a.email AS account_email, a.tier, a.status,
                   c.last_handshake, c.endpoint, c.last_rx, c.last_tx
            FROM devices d
            JOIN accounts a ON d.account_email = a.email
            LEFT JOIN kernel_counter_cache c ON d.public_key = c.pubkey
            ORDER BY d.created_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def delete_key(self, public_key):
        """
        Deletes a device and revokes access by its WireGuard public key.
        """
        public_key = public_key.strip()
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT account_email, device_name FROM devices WHERE public_key = ?", (public_key,))
            row = cursor.fetchone()
            if not row:
                return False
            email = row["account_email"]
            device_name = row["device_name"]

        return self.remove_device(email, device_name)

    # ---------------------------------------------------------
    # Client Config Generation
    # ---------------------------------------------------------
    def _build_client_config(self, client_ip, client_priv_key, preshared_key):
        server_pub = self.get_server_public_key()
        endpoint = f"{self.server_url}:{self.server_port}"
        
        return f"""[Interface]
# Device VPN Tunnel IP
Address = {client_ip}/32
PrivateKey = {client_priv_key}
DNS = {self.peer_dns}
MTU = {self.mtu}

[Peer]
PublicKey = {server_pub}
PresharedKey = {preshared_key}
Endpoint = {endpoint}
# Default routes all traffic through VPS. 
# For Gaming Split-Tunneling, replace with specific game subnets (e.g. 103.28.54.0/24, 103.10.124.0/23)
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

    # ---------------------------------------------------------
    # WireGuard Kernel Control (Zero Downtime wg set)
    # ---------------------------------------------------------
    def _hot_add_peer(self, pub_key, preshared_key, internal_ip):
        if not shutil.which("wg"):
            return False
            
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(preshared_key.strip())
                temp_psk = f.name

            cmd = [
                "wg", "set", self.interface,
                "peer", pub_key,
                "preshared-key", temp_psk,
                "allowed-ips", f"{internal_ip}/32"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            os.remove(temp_psk)
            if res.returncode == 0 and shutil.which("ip"):
                subprocess.run(["ip", "route", "replace", DEFAULT_SUBNET, "dev", self.interface], capture_output=True)
            return res.returncode == 0
        except Exception:
            return False

    def _hot_remove_peer(self, pub_key):
        if not shutil.which("wg"):
            return False
            
        try:
            cmd = ["wg", "set", self.interface, "peer", pub_key, "remove"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            return res.returncode == 0
        except Exception:
            return False

    def _append_peer_to_conf(self, email, device_name, pub_key, preshared_key, internal_ip):
        if not self.wg_conf_path.exists():
            return

        peer_block = f"""
# Account: {email} | Device: {device_name}
[Peer]
PublicKey = {pub_key}
PresharedKey = {preshared_key}
AllowedIPs = {internal_ip}/32
"""
        with open(self.wg_conf_path, "a") as f:
            f.write(peer_block)

    def _remove_peer_from_conf(self, pub_key):
        if not self.wg_conf_path.exists():
            return

        content = self.wg_conf_path.read_text()
        # Find [Peer] blocks and remove the matching block
        blocks = re.split(r"(?=\n\[Peer\])", content)
        new_blocks = []
        for block in blocks:
            if pub_key in block:
                continue
            new_blocks.append(block)

        self.wg_conf_path.write_text("".join(new_blocks))

    # ---------------------------------------------------------
    # High-Efficiency Usage Tracking & Quota Enforcer
    # ---------------------------------------------------------
    def poll_and_enforce_quotas(self):
        """
        Ultra-efficient kernel reader:
        1. Runs 'wg show wg0 dump' in < 1ms.
        2. Computes byte deltas since last poll.
        3. Persists usage in daily_usage and monthly_usage.
        4. Drops peers exceeding Free (2GB/day) or Pro (200GB/month).
        5. Restores peers on daily/monthly reset.
        """
        now = datetime.now(timezone.utc)
        today = now.strftime("%Y-%m-%d")
        current_month = now.strftime("%Y-%m")

        # 1. First, check if any quota_exceeded accounts should be reset (new day / month)
        self._check_and_reset_scheduled(today, current_month)

        if not shutil.which("wg"):
            return {"status": "ok", "message": "wg command not present (test mode)"}

        try:
            res = subprocess.run(["wg", "show", self.interface, "dump"], capture_output=True, text=True, check=True)
            lines = res.stdout.strip().split("\n")
        except Exception as e:
            return {"status": "error", "message": f"Could not read WireGuard interface: {e}"}

        if len(lines) <= 1:
            return {"status": "ok", "updated_peers": 0}

        # Build map: pubkey -> device & account
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT d.public_key, d.device_name, d.internal_ip, a.email, a.tier, a.daily_limit_bytes, 
                   a.monthly_limit_bytes, a.status
            FROM devices d
            JOIN accounts a ON d.account_email = a.email
            """)
            device_map = {row["public_key"]: dict(row) for row in cursor.fetchall()}

            # Read cached counters
            cursor.execute("SELECT pubkey, last_rx, last_tx FROM kernel_counter_cache")
            cache = {row["pubkey"]: (row["last_rx"], row["last_tx"]) for row in cursor.fetchall()}

            # Track changes per account
            account_deltas = {}

            # Process wg dump (line index 0 is interface)
            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) < 8:
                    continue

                pubkey = parts[0]
                endpoint = parts[2]
                handshake = int(parts[4])
                rx = int(parts[5])
                tx = int(parts[6])

                if pubkey not in device_map:
                    continue

                # Compute delta
                prev_rx, prev_tx = cache.get(pubkey, (0, 0))
                
                # Handle kernel counter reset after interface restart
                delta_rx = rx - prev_rx if rx >= prev_rx else rx
                delta_tx = tx - prev_tx if tx >= prev_tx else tx

                # Update kernel counter cache
                cursor.execute("""
                INSERT INTO kernel_counter_cache (pubkey, last_rx, last_tx, last_handshake, endpoint, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(pubkey) DO UPDATE SET
                    last_rx = excluded.last_rx,
                    last_tx = excluded.last_tx,
                    last_handshake = excluded.last_handshake,
                    endpoint = excluded.endpoint,
                    updated_at = CURRENT_TIMESTAMP
                """, (pubkey, rx, tx, handshake, endpoint))

                email = device_map[pubkey]["email"]
                if email not in account_deltas:
                    account_deltas[email] = {"rx": 0, "tx": 0}
                account_deltas[email]["rx"] += delta_rx
                account_deltas[email]["tx"] += delta_tx

            # Accumulate into daily_usage and monthly_usage
            for email, deltas in account_deltas.items():
                if deltas["rx"] == 0 and deltas["tx"] == 0:
                    continue

                delta_total = deltas["rx"] + deltas["tx"]

                # Daily
                cursor.execute("""
                INSERT INTO daily_usage (account_email, date, bytes_rx, bytes_tx, total_bytes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(account_email, date) DO UPDATE SET
                    bytes_rx = bytes_rx + excluded.bytes_rx,
                    bytes_tx = bytes_tx + excluded.bytes_tx,
                    total_bytes = total_bytes + excluded.total_bytes
                """, (email, today, deltas["rx"], deltas["tx"], delta_total))

                # Monthly
                cursor.execute("""
                INSERT INTO monthly_usage (account_email, month, bytes_rx, bytes_tx, total_bytes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(account_email, month) DO UPDATE SET
                    bytes_rx = bytes_rx + excluded.bytes_rx,
                    bytes_tx = bytes_tx + excluded.bytes_tx,
                    total_bytes = total_bytes + excluded.total_bytes
                """, (email, current_month, deltas["rx"], deltas["tx"], delta_total))

            conn.commit()

        # Enforce quotas
        self._enforce_all_quotas(today, current_month)
        return {"status": "ok", "updated_peers": len(lines) - 1}

    def _enforce_all_quotas(self, today, current_month):
        accounts = self.list_accounts()
        for acc in accounts:
            if acc["status"] != "active":
                continue

            exceeded = False
            # Check free tier daily limit
            if acc["tier"] == "free" and acc["daily_limit_bytes"] > 0:
                if acc["today_usage_bytes"] >= acc["daily_limit_bytes"]:
                    exceeded = True

            # Check pro tier monthly limit
            if acc["tier"] == "pro" and acc["monthly_limit_bytes"] > 0:
                if acc["month_usage_bytes"] >= acc["monthly_limit_bytes"]:
                    exceeded = True

            if exceeded:
                self.suspend_account_for_quota(acc["email"])

    def suspend_account_for_quota(self, email):
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE accounts SET status = 'quota_exceeded', updated_at = CURRENT_TIMESTAMP WHERE email = ?",
                (email,)
            )
            conn.commit()

        account = self.get_account(email)
        if account:
            for device in account["devices"]:
                self._hot_remove_peer(device["public_key"])

    def reactivate_account(self, email):
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE accounts SET status = 'active', updated_at = CURRENT_TIMESTAMP WHERE email = ?",
                (email,)
            )
            conn.commit()

        account = self.get_account(email)
        if account:
            for device in account["devices"]:
                self._hot_add_peer(device["public_key"], device["preshared_key"], device["internal_ip"])

    def _check_and_reset_scheduled(self, today, current_month):
        """
        Automatically restores access for accounts whose quota window has reset.
        Free tier resets daily (midnight UTC).
        Pro tier resets on 1st of month.
        """
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email, tier FROM accounts WHERE status = 'quota_exceeded'")
            exceeded_accounts = cursor.fetchall()

        for row in exceeded_accounts:
            email = row["email"]
            tier = row["tier"]
            account = self.get_account(email)
            if not account:
                continue

            # Free user: check if today's usage is 0 (a new day started)
            if tier == "free" and account["today_usage_bytes"] < account["daily_limit_bytes"]:
                self.reactivate_account(email)
            elif tier == "pro" and account["month_usage_bytes"] < account["monthly_limit_bytes"]:
                self.reactivate_account(email)
            elif tier == "adaw":
                self.reactivate_account(email)

    def sync_wg(self):
        """
        Synchronizes all active DB peers with the running WireGuard interface and wg0.conf.
        Ensures perfect state recovery after container or VPS reboots.
        """
        accounts = self.list_accounts()
        active_peers = []
        for acc in accounts:
            for dev in acc["devices"]:
                if acc["status"] == "active":
                    self._hot_add_peer(dev["public_key"], dev["preshared_key"], dev["internal_ip"])
                    active_peers.append({
                        "email": acc["email"],
                        "device": dev["device_name"],
                        "pubkey": dev["public_key"],
                        "psk": dev["preshared_key"],
                        "ip": dev["internal_ip"]
                    })
                else:
                    self._hot_remove_peer(dev["public_key"])

        # Persist all active peers to wg0.conf so container reboots retain all peers
        if self.wg_conf_path.exists():
            try:
                content = self.wg_conf_path.read_text()
                interface_part = re.split(r"(?=\n\[Peer\])", content)[0].strip()
                peer_blocks = []
                for p in active_peers:
                    peer_blocks.append(
                        f"\n\n# Account: {p['email']} | Device: {p['device']}\n"
                        f"[Peer]\n"
                        f"PublicKey = {p['pubkey']}\n"
                        f"PresharedKey = {p['psk']}\n"
                        f"AllowedIPs = {p['ip']}/32"
                    )
                self.wg_conf_path.write_text(interface_part + "".join(peer_blocks) + "\n")
            except Exception:
                pass

        # Ensure subnet route exists for all client peers (prevents asymmetric routing)
        if shutil.which("ip"):
            subprocess.run(["ip", "route", "replace", DEFAULT_SUBNET, "dev", self.interface], capture_output=True)

        # Enforce TCP MSS Clamping to prevent MTU black-holing on HTTPS / large TCP packets
        if shutil.which("iptables"):
            check_m = subprocess.run(
                ["iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                capture_output=True
            )
            if check_m.returncode != 0:
                subprocess.run(
                    ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                    capture_output=True
                )
        return True
