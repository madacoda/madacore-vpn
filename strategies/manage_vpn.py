#!/usr/bin/env python3
"""
MadaCore VPN - Administrator Command-Line Tool
Author: Professional Network Engineer

Usage Examples:
  # 1. Create a user and automatically provision 2 devices in one command:
  python manage_vpn.py create-user alice@example.com --tier free --devices pc,phone

  # 2. Add an account only:
  python manage_vpn.py add-user bob@example.com --tier pro

  # 3. Add a single device to an existing account (enforces max 2 devices):
  python manage_vpn.py add-device bob@example.com laptop

  # 4. View all accounts, device counts, usage metrics, and quota status:
  python manage_vpn.py list-users

  # 5. Display a device's client config:
  python manage_vpn.py show-config alice@example.com pc

  # 6. Display a scannable terminal QR code for mobile:
  python manage_vpn.py show-qr alice@example.com phone

  # 7. Reset quota or upgrade tier:
  python manage_vpn.py reset-quota alice@example.com
  python manage_vpn.py upgrade-user alice@example.com --tier pro

  # 8. Delete device or user:
  python manage_vpn.py delete-device alice@example.com phone
  python manage_vpn.py delete-user alice@example.com
"""

import sys
import os
import argparse
import shutil
import subprocess
from pathlib import Path

# Locate strategies directory
current_dir = Path(__file__).parent.resolve()
if (current_dir / "vpn_manager.py").exists():
    sys.path.insert(0, str(current_dir))
elif (current_dir / "strategies" / "vpn_manager.py").exists():
    sys.path.insert(0, str(current_dir / "strategies"))

from vpn_manager import VPNManager

def format_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"

def render_progress_bar(percent, width=15):
    filled = int(width * (min(percent, 100.0) / 100.0))
    try:
        "█".encode(sys.stdout.encoding or "ascii")
        fill_char = "█"
        empty_char = "░"
    except Exception:
        fill_char = "="
        empty_char = "-"
    bar = fill_char * filled + empty_char * (width - filled)
    return f"[{bar}] {percent:.1f}%"

def main():
    parser = argparse.ArgumentParser(
        description="MadaCore VPN Management CLI - High Performance & Resource Efficient",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. create-user (combined user + devices)
    p_create = subparsers.add_parser("create-user", help="Create an account and provision devices in 1 command")
    p_create.add_argument("email", help="Unique user email address")
    p_create.add_argument("--tier", choices=["free", "pro", "adaw"], default="free", help="Tier: free (2GB/day), pro (200GB/month), or adaw (unlimited)")
    p_create.add_argument("--devices", default="pc,phone", help="Comma-separated device names (max 2, e.g. pc,phone)")

    # 2. add-user
    p_add_user = subparsers.add_parser("add-user", help="Create a user account")
    p_add_user.add_argument("email", help="Unique user email address")
    p_add_user.add_argument("--tier", choices=["free", "pro", "adaw"], default="free", help="Tier: free, pro, or adaw")

    # 3. add-device
    p_add_dev = subparsers.add_parser("add-device", help="Add a device to an existing user (max 2)")
    p_add_dev.add_argument("email", help="User email address")
    p_add_dev.add_argument("device_name", help="Device name (e.g. pc, phone, laptop)")
    p_add_dev.add_argument("--public-key", help="Existing WireGuard public key (optional)")
    p_add_dev.add_argument("--psk", help="Optional preshared key")

    # 3b. add-key (direct alias for registering an existing public key)
    p_add_key = subparsers.add_parser("add-key", help="Register an existing WireGuard public key for an account")
    p_add_key.add_argument("email", help="User email address")
    p_add_key.add_argument("device_name", help="Device name (e.g. pc, phone, router)")
    p_add_key.add_argument("public_key", help="WireGuard public key (base64)")
    p_add_key.add_argument("--psk", help="Optional preshared key")

    # 3c. list-keys
    subparsers.add_parser("list-keys", help="List all registered WireGuard public keys and their mappings")

    # 3d. delete-key
    p_del_key = subparsers.add_parser("delete-key", help="Delete a device and revoke its WireGuard public key")
    p_del_key.add_argument("public_key", help="WireGuard public key to remove")

    # 4. list-users
    subparsers.add_parser("list-users", help="List all users, devices, live usage, and quotas")

    # 5. show-user
    p_show = subparsers.add_parser("show-user", help="Show detailed info for a specific user")
    p_show.add_argument("email", help="User email address")

    # 6. show-config
    p_conf = subparsers.add_parser("show-config", help="Print WireGuard client configuration (.conf)")
    p_conf.add_argument("email", help="User email address")
    p_conf.add_argument("device_name", help="Device name")
    p_conf.add_argument("--output", help="Optional file path to save .conf")

    # 7. show-qr
    p_qr = subparsers.add_parser("show-qr", help="Render terminal QR code for mobile client")
    p_qr.add_argument("email", help="User email address")
    p_qr.add_argument("device_name", help="Device name")

    # 8. delete-device
    p_del_dev = subparsers.add_parser("delete-device", help="Remove a device from an account")
    p_del_dev.add_argument("email", help="User email address")
    p_del_dev.add_argument("device_name", help="Device name")

    # 9. delete-user
    p_del_user = subparsers.add_parser("delete-user", help="Delete a user account and all devices")
    p_del_user.add_argument("email", help="User email address")

    # 10. upgrade-user
    p_upg = subparsers.add_parser("upgrade-user", help="Change account tier between free, pro, and adaw")
    p_upg.add_argument("email", help="User email address")
    p_upg.add_argument("--tier", choices=["free", "pro", "adaw"], required=True, help="New tier")

    # 11. reset-quota
    p_reset = subparsers.add_parser("reset-quota", help="Manually reset usage quota and restore active status")
    p_reset.add_argument("email", help="User email address")

    # 12. sync
    subparsers.add_parser("sync", help="Synchronize active DB peers with live WireGuard kernel interface")

    # 13. poll
    subparsers.add_parser("poll", help="Run one usage collection and quota enforcement cycle")

    args = parser.parse_args()
    manager = VPNManager()

    try:
        if args.command == "create-user":
            dev_names = [d.strip() for d in args.devices.split(",") if d.strip()]
            if len(dev_names) > 2:
                print("[-] Error: An account can have a maximum of 2 devices.")
                sys.exit(1)

            print(f"[*] Creating account: {args.email} [Tier: {args.tier.upper()}]...")
            acc = manager.create_account(args.email, tier=args.tier)

            created_devs = []
            for d in dev_names:
                print(f"[*] Provisioning device '{d}'...")
                dev_info = manager.add_device(args.email, d)
                created_devs.append(dev_info)

            print(f"\n[+] Success! Account '{args.email}' created with {len(created_devs)} device(s):")
            for d in created_devs:
                print(f"    - Device: {d['device_name']:<8} IP: {d['internal_ip']:<12} Config: {d['config_path']}")
            print(f"\nTo inspect or scan QR code:\n    python manage_vpn.py show-qr {args.email} {created_devs[0]['device_name']}")

        elif args.command == "add-user":
            acc = manager.create_account(args.email, tier=args.tier)
            print(f"[+] Account '{acc['email']}' created successfully [Tier: {acc['tier'].upper()}].")
            print(f"    Now add devices: python manage_vpn.py add-device {acc['email']} pc")

        elif args.command == "add-device":
            dev = manager.add_device(args.email, args.device_name, public_key=args.public_key, preshared_key=args.psk)
            print(f"[+] Device '{dev['device_name']}' added to '{args.email}'.")
            print(f"    Internal IP: {dev['internal_ip']}")
            print(f"    Public Key : {dev['public_key']}")
            print(f"    Config file: {dev['config_path']}")

        elif args.command == "add-key":
            dev = manager.add_device(args.email, args.device_name, public_key=args.public_key, preshared_key=args.psk)
            print(f"[+] Existing key registered to '{args.email}' [{dev['device_name']}].")
            print(f"    Internal IP: {dev['internal_ip']}")
            print(f"    Public Key : {dev['public_key']}")
            print(f"    Config file: {dev['config_path']}")

        elif args.command == "list-keys":
            keys = manager.list_keys()
            if not keys:
                print("[-] No registered WireGuard keys found in database.")
                return

            print("=" * 115)
            print(f"{'PUBLIC KEY':<46} {'INTERNAL IP':<14} {'ACCOUNT / DEVICE':<32} {'STATUS':<15}")
            print("=" * 115)
            for k in keys:
                user_label = f"{k['account_email']} ({k['device_name']})"
                status = k["status"].upper()
                if status == "ACTIVE":
                    status_col = f"\033[92m{status}\033[0m"
                elif status == "QUOTA_EXCEEDED":
                    status_col = f"\033[91m{status}\033[0m"
                else:
                    status_col = f"\033[93m{status}\033[0m"
                print(f"{k['public_key']:<46} {k['internal_ip']:<14} {user_label:<32} {status_col:<15}")
            print("=" * 115)

        elif args.command == "delete-key":
            if manager.delete_key(args.public_key):
                print(f"[+] Key '{args.public_key}' deleted and revoked from WireGuard interface.")
            else:
                print(f"[-] Key '{args.public_key}' not found.")

        elif args.command == "list-users":
            accounts = manager.list_accounts()
            if not accounts:
                print("[-] No accounts configured yet. Use 'create-user' to add one.")
                return

            print("=" * 115)
            print(f"{'EMAIL':<30} {'TIER':<6} {'DEVICES':<8} {'TODAY USAGE / LIMIT':<24} {'QUOTA':<22} {'STATUS':<15}")
            print("=" * 115)

            for a in accounts:
                dev_str = f"{a['device_count']}/2"
                
                # Quota display
                if a["tier"] == "free":
                    limit_str = format_bytes(a["daily_limit_bytes"])
                    usage_str = f"{format_bytes(a['today_usage_bytes'])} / {limit_str} (d)"
                elif a["tier"] == "pro":
                    limit_str = format_bytes(a["monthly_limit_bytes"])
                    usage_str = f"{format_bytes(a['month_usage_bytes'])} / {limit_str} (m)"
                else:
                    usage_str = f"{format_bytes(a['today_usage_bytes'])} / Unlimited"

                quota_bar = render_progress_bar(a["quota_percent"])

                status = a["status"].upper()
                if status == "ACTIVE":
                    status_colored = f"\033[92m{status}\033[0m"
                elif status == "QUOTA_EXCEEDED":
                    status_colored = f"\033[91m{status}\033[0m"
                else:
                    status_colored = f"\033[93m{status}\033[0m"

                print(f"{a['email']:<30} {a['tier'].upper():<6} {dev_str:<8} {usage_str:<24} {quota_bar:<22} {status_colored:<15}")
                bullet = "   └─ " if (sys.stdout.encoding and "utf" in sys.stdout.encoding.lower()) else "   |- "
                for d in a["devices"]:
                    print(f"{bullet}[{d['device_name']}] IP: {d['internal_ip']} | PubKey: {d['public_key'][:16]}...")
            print("=" * 115)

        elif args.command == "show-user":
            a = manager.get_account(args.email)
            if not a:
                print(f"[-] User '{args.email}' not found.")
                return

            print(f"\nUser Details: {a['email']}")
            print(f"  Tier         : {a['tier'].upper()}")
            print(f"  Status       : {a['status'].upper()}")
            print(f"  Device Count : {a['device_count']}/2")
            print(f"  Today Usage  : {format_bytes(a['today_usage_bytes'])} (Rx: {format_bytes(a['today_rx_bytes'])}, Tx: {format_bytes(a['today_tx_bytes'])})")
            print(f"  Month Usage  : {format_bytes(a['month_usage_bytes'])}")
            if a["tier"] == "free":
                limit_display = format_bytes(a["daily_limit_bytes"]) + " (Daily)"
            elif a["tier"] == "pro":
                limit_display = format_bytes(a["monthly_limit_bytes"]) + " (Monthly)"
            else:
                limit_display = "Unlimited (Adaw)"
            print(f"  Quota Limit  : {limit_display}")
            print(f"  Quota Bar    : {render_progress_bar(a['quota_percent'])}")
            print("  Devices:")
            for d in a["devices"]:
                print(f"    - Name       : {d['device_name']}")
                print(f"      IP Address : {d['internal_ip']}")
                print(f"      Public Key : {d['public_key']}")
                dev_conf_path = manager.clients_dir / a["email"] / f"{d['device_name']}.conf"
                print(f"      Config File: {dev_conf_path}")

        elif args.command == "show-config":
            cfg = manager.get_device_config(args.email, args.device_name)
            if not cfg:
                print(f"[-] Config for {args.email}/{args.device_name} not found.")
                return

            if args.output:
                Path(args.output).write_text(cfg)
                print(f"[+] Config saved to: {args.output}")
            else:
                print(cfg)

        elif args.command == "show-qr":
            cfg = manager.get_device_config(args.email, args.device_name)
            if not cfg:
                print(f"[-] Config for {args.email}/{args.device_name} not found.")
                return

            if shutil.which("qrencode"):
                print(f"\n[+] Scan QR Code below for {args.email} ({args.device_name}):\n")
                subprocess.run(["qrencode", "-t", "ansiutf8"], input=cfg, text=True)
            else:
                print("[-] 'qrencode' is not installed in the current environment.")
                print("    Raw Configuration:")
                print(cfg)

        elif args.command == "delete-device":
            if manager.remove_device(args.email, args.device_name):
                print(f"[+] Device '{args.device_name}' removed from '{args.email}'.")
            else:
                print(f"[-] Device '{args.device_name}' not found on '{args.email}'.")

        elif args.command == "delete-user":
            if manager.delete_account(args.email):
                print(f"[+] Account '{args.email}' and all associated devices deleted.")
            else:
                print(f"[-] Account '{args.email}' not found.")

        elif args.command == "upgrade-user":
            acc = manager.update_tier(args.email, args.tier)
            print(f"[+] Account '{args.email}' updated to tier: {acc['tier'].upper()}.")

        elif args.command == "reset-quota":
            acc = manager.reset_quota(args.email)
            print(f"[+] Quota reset for '{args.email}'. Status is now ACTIVE.")

        elif args.command == "sync":
            manager.sync_wg()
            print("[+] All active database peers synchronized to WireGuard kernel interface.")

        elif args.command == "poll":
            res = manager.poll_and_enforce_quotas()
            print(f"[+] Usage poll completed: {res}")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
