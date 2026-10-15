#!/usr/bin/env python3
"""
Unit test suite for MadaCore VPN Flask REST API.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add strategies to sys.path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "strategies"))

from vpn_manager import VPNManager
import monitor_web

class TestVPNWebAPI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="madacore_api_test_")
        self.config_dir = Path(self.test_dir) / "config"
        # Re-initialize VPNManager for testing with temporary dir
        monitor_web.manager = VPNManager(config_dir=self.config_dir)
        self.app = monitor_web.app.test_client()
        self.app.testing = True

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_index_page(self):
        res = self.app.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"MadaCore Gaming VPN", res.data)
        self.assertIn(b"Accounts & Quotas", res.data)

    def test_account_lifecycle_api(self):
        email = "tester@vpn.com"

        # 1. Create account with 2 devices
        res = self.app.post("/api/accounts", json={
            "email": email,
            "tier": "free",
            "devices": ["pc", "mobile"]
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["account"]["email"], email)
        self.assertEqual(data["account"]["device_count"], 2)

        # 2. Attempting to add a 3rd device MUST be blocked (400)
        res_3rd = self.app.post(f"/api/accounts/{email}/devices", json={"device_name": "laptop"})
        self.assertEqual(res_3rd.status_code, 400)
        self.assertIn("maximum of 2 devices", res_3rd.get_json()["message"])

        # 3. List accounts
        res_list = self.app.get("/api/accounts")
        self.assertEqual(res_list.status_code, 200)
        accs = res_list.get_json()["accounts"]
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0]["email"], email)

        # 4. Download config
        res_cfg = self.app.get(f"/api/accounts/{email}/devices/pc/config")
        self.assertEqual(res_cfg.status_code, 200)
        self.assertIn(b"[Interface]", res_cfg.data)
        self.assertIn(b"[Peer]", res_cfg.data)

        # 5. Upgrade tier to pro
        res_tier = self.app.post(f"/api/accounts/{email}/tier", json={"tier": "pro"})
        self.assertEqual(res_tier.status_code, 200)
        self.assertEqual(res_tier.get_json()["account"]["tier"], "pro")

        # 6. Reset quota
        res_reset = self.app.post(f"/api/accounts/{email}/reset-quota")
        self.assertEqual(res_reset.status_code, 200)
        self.assertEqual(res_reset.get_json()["account"]["status"], "active")

        # 7. Delete device
        res_del_dev = self.app.delete(f"/api/accounts/{email}/devices/mobile")
        self.assertEqual(res_del_dev.status_code, 200)

        # 8. Delete account
        res_del_acc = self.app.delete(f"/api/accounts/{email}")
        self.assertEqual(res_del_acc.status_code, 200)

        # Verify empty
        res_final = self.app.get("/api/accounts")
        self.assertEqual(len(res_final.get_json()["accounts"]), 0)

    def test_keys_api(self):
        email = "key_tester@vpn.com"
        self.app.post("/api/accounts", json={"email": email, "tier": "free"})

        import base64
        custom_pub = base64.b64encode(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345").decode()

        # Add device with pre-existing public key
        res = self.app.post(f"/api/accounts/{email}/devices", json={
            "device_name": "custom_pc",
            "public_key": custom_pub
        })
        self.assertEqual(res.status_code, 200)

        # List keys
        res_keys = self.app.get("/api/keys")
        self.assertEqual(res_keys.status_code, 200)
        keys = res_keys.get_json()["keys"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["public_key"], custom_pub)

        # Delete key
        res_del = self.app.delete(f"/api/keys/{custom_pub}")
        self.assertEqual(res_del.status_code, 200)

        # Confirm deleted
        res_after = self.app.get("/api/keys")
        self.assertEqual(len(res_after.get_json()["keys"]), 0)

if __name__ == "__main__":
    unittest.main()
