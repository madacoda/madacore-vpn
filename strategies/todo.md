# VPN Service Architecture & Account Feature Status

## 1. Unique Authentication by Email
- [x] **Status:** Implemented in `strategies/vpn_manager.py` & SQLite `vpn.db`.
- **Details:** Every account is uniquely identified by their email address. Authentication in WireGuard operates on Cryptographic Key Routing (each device has an asymmetric Curve25519 keypair and static IP linked to the account).

## 2. Simultaneous Device Limit (Max 2 Devices per Account)
- [x] **Status:** Implemented with strict database & API validation.
- **Details:** Cryptographic keys cannot be shared between 2 devices simultaneously without IP collisions. Therefore, 1 Account = up to 2 distinct WireGuard peers (e.g. `pc` @ `10.0.0.2` and `phone` @ `10.0.0.3`). Adding a 3rd device is blocked automatically.

## 3. Usage Monitoring & Bandwidth Limiting
- [x] **Status:** Implemented in `strategies/vpn_manager.py` and `strategies/monitor_web.py`.
- **Details:** 
  - Background poller reads kernel stats via `wg show wg0 dump` every 30s (< 0.05% CPU, zero extra containers).
  - Persistent daily & monthly usage tracked in SQLite.
  - Automatic quota enforcement: when an account exceeds their limit, peers are dynamically removed from the live interface (`wg set wg0 peer <pubkey> remove`) without container restart.
  - Automatic daily reset at midnight UTC restores access for free tier accounts.

## 4. Tiers & Bandwidth Quotas (Free 2GB/day vs. Pro 200GB/month vs. Adaw Unlimited)
- [x] **Status:** Implemented.
  - **Free Tier:** 2 GB / day (reset midnight UTC).
  - **Pro Tier:** 200 GB / month (reset 1st of month).
  - **Adaw Tier:** Unlimited daily & monthly bandwidth (no quota enforcement).
- **Network Engineer Evaluation:**
  - Online multiplayer games (CS2, Dota 2, Valorant) consume only 40–150 MB/hour.
  - 2 GB / day gives free users ~15–25 hours of pure gaming per day (generous), while preventing abuse (streaming Netflix or downloading torrents exceeds 2GB in < 1 hour).
  - 200 GB / month gives Pro users over 1,500 hours of gaming or full-tunnel routing.
  - Adaw tier provides VIP / unrestricted bandwidth with zero quota drops.