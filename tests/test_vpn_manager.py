#!/usr/bin/env python3
"""
Unit test suite for MadaCore VPN Account & Peer Management Engine.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add strategies to sys.path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "strategies"))
from vpn_manager import VPNManager, MAX_DEVICES_PER_ACCOUNT, FREE_DAILY_QUOTA_BYTES, PRO_MONTHLY_QUOTA_BYTES

class TestVPNManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="madacore_vpn_test_")
        self.config_dir = Path(self.test_dir) / "config"
        self.manager = VPNManager(config_dir=self.config_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_account_and_validation(self):
        # Valid account
        acc = self.manager.create_account("player1@gmail.com", tier="free")
        self.assertEqual(acc["email"], "player1@gmail.com")
        self.assertEqual(acc["tier"], "free")
        self.assertEqual(acc["daily_limit_bytes"], FREE_DAILY_QUOTA_BYTES)
        self.assertEqual(acc["status"], "active")
        self.assertEqual(acc["device_count"], 0)

        # Invalid email format
        with self.assertRaises(ValueError):
            self.manager.create_account("not-an-email")

        # Invalid tier
        with self.assertRaises(ValueError):
            self.manager.create_account("valid@email.com", tier="enterprise")

    def test_device_limit_enforcement(self):
        """Verify strict enforcement of maximum 2 devices per account."""
        email = "gamer@domain.com"
        self.manager.create_account(email, tier="free")

        # Add Device 1
        dev1 = self.manager.add_device(email, "pc")
        self.assertEqual(dev1["device_name"], "pc")
        self.assertEqual(dev1["internal_ip"], "10.0.0.2")
        self.assertTrue(os.path.exists(dev1["config_path"]))

        # Add Device 2
        dev2 = self.manager.add_device(email, "phone")
        self.assertEqual(dev2["device_name"], "phone")
        self.assertEqual(dev2["internal_ip"], "10.0.0.3")

        # Verify account has 2 devices
        acc = self.manager.get_account(email)
        self.assertEqual(acc["device_count"], 2)

        # Attempting to add Device 3 MUST fail
        with self.assertRaises(ValueError) as ctx:
            self.manager.add_device(email, "laptop")
        self.assertIn("already has the maximum of 2 devices", str(ctx.exception))

    def test_ip_allocation_and_reuse(self):
        """Verify sequential IP allocation and reuse after device removal."""
        email = "solo@domain.com"
        self.manager.create_account(email, tier="free")

        dev1 = self.manager.add_device(email, "dev1")
        dev2 = self.manager.add_device(email, "dev2")
        self.assertEqual(dev1["internal_ip"], "10.0.0.2")
        self.assertEqual(dev2["internal_ip"], "10.0.0.3")

        # Remove dev1
        self.manager.remove_device(email, "dev1")
        acc = self.manager.get_account(email)
        self.assertEqual(acc["device_count"], 1)

        # Add new device -> should re-use lowest available IP (10.0.0.2)
        dev3 = self.manager.add_device(email, "dev3")
        self.assertEqual(dev3["internal_ip"], "10.0.0.2")

    def test_quota_tracking_and_reset(self):
        email = "quota_user@domain.com"
        self.manager.create_account(email, tier="free")
        self.manager.add_device(email, "pc")

        # Simulate usage in DB: 1 GB out of 2 GB
        with self.manager.get_db() as conn:
            conn.execute("""
            INSERT INTO daily_usage (account_email, date, bytes_rx, bytes_tx, total_bytes)
            VALUES (?, CURRENT_DATE, ?, ?, ?)
            """, (email, 500000000, 573741824, 1073741824))
            conn.commit()

        acc = self.manager.get_account(email)
        self.assertEqual(acc["today_usage_bytes"], 1073741824)
        self.assertAlmostEqual(acc["quota_percent"], 50.0, places=1)
        self.assertEqual(acc["status"], "active")

        # Simulate hitting quota: 2.1 GB out of 2.0 GB
        self.manager.suspend_account_for_quota(email)
        acc = self.manager.get_account(email)
        self.assertEqual(acc["status"], "quota_exceeded")

        # Reset quota
        self.manager.reset_quota(email)
        acc_reset = self.manager.get_account(email)
        self.assertEqual(acc_reset["status"], "active")
        self.assertEqual(acc_reset["today_usage_bytes"], 0)
        self.assertEqual(acc_reset["quota_percent"], 0.0)

    def test_upgrade_tier(self):
        email = "upgrade@domain.com"
        self.manager.create_account(email, tier="free")
        acc = self.manager.get_account(email)
        self.assertEqual(acc["tier"], "free")
        self.assertEqual(acc["daily_limit_bytes"], FREE_DAILY_QUOTA_BYTES)

        # Upgrade to pro
        upgraded = self.manager.update_tier(email, "pro")
        self.assertEqual(upgraded["tier"], "pro")
        self.assertEqual(upgraded["monthly_limit_bytes"], PRO_MONTHLY_QUOTA_BYTES)

    def test_delete_account_cascade(self):
        email = "delete_me@domain.com"
        self.manager.create_account(email, tier="free")
        self.manager.add_device(email, "pc")
        self.assertTrue(self.manager.delete_account(email))
        self.assertIsNone(self.manager.get_account(email))
        # Ensure directory cleaned up
        self.assertFalse((self.config_dir / "clients" / email).exists())

    def test_add_existing_key_and_key_operations(self):
        email = "custom_key_user@domain.com"
        self.manager.create_account(email, tier="free")

        # Generate a valid 32-byte WireGuard public key
        import base64
        test_pub = base64.b64encode(b"01234567890123456789012345678901").decode()

        # Add device with pre-existing public key
        dev = self.manager.add_device(email, "router", public_key=test_pub)
        self.assertEqual(dev["public_key"], test_pub)
        self.assertEqual(dev["device_name"], "router")
        self.assertEqual(dev["internal_ip"], "10.0.0.2")

        # Verify key shows up in list_keys()
        keys = self.manager.list_keys()
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["public_key"], test_pub)
        self.assertEqual(keys[0]["account_email"], email)

        # Attempting to re-add duplicate public key must fail
        email2 = "another_user@domain.com"
        self.manager.create_account(email2, tier="free")
        with self.assertRaises(ValueError) as ctx:
            self.manager.add_device(email2, "pc", public_key=test_pub)
        self.assertIn("already registered", str(ctx.exception))

        # Delete key by public key string
        self.assertTrue(self.manager.delete_key(test_pub))
        self.assertEqual(len(self.manager.list_keys()), 0)

if __name__ == "__main__":
    unittest.main()
