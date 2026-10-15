#!/usr/bin/env python3
"""
MadaCore VPN Management CLI Entrypoint
Redirects execution to strategies/manage_vpn.py
"""
import sys
from pathlib import Path

# Add strategies to sys.path
sys.path.insert(0, str(Path(__file__).parent / "strategies"))
import manage_vpn

if __name__ == "__main__":
    manage_vpn.main()
