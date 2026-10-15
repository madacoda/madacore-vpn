# MadaCore VPN - Command Reference & Capabilities
Concise command reference for managing accounts, devices, WireGuard public keys, and usage quotas.

Commands can be run on the VPS host via `./vpn-admin` or directly via `python manage_vpn.py`.

---

## 1. WireGuard Public Key Management

Directly manage cryptographic keys without restarting containers or dropping active connections.

| Command | Description | Example |
| :--- | :--- | :--- |
| `list-keys` | Lists all registered public keys, assigned IPs, owner emails, devices, and online status. | `./vpn-admin list-keys` |
| `add-key <email> <device> <public_key>` | Registers an existing client-generated WireGuard public key to an account. | `./vpn-admin add-key user@vpn.com pc "aB3...k9="` |
| `delete-key <public_key>` | Revokes and deletes a peer immediately from the live interface and database by its public key. | `./vpn-admin delete-key "aB3...k9="` |
| `add-device ... --public-key <key>` | Adds a device with a pre-existing public key instead of auto-generating one. | `./vpn-admin add-device user@vpn.com phone --public-key "xY8...m1="` |

---

## 2. Account Lifecycle & Quotas

Accounts are uniquely identified by email and enforce a **strict limit of max 2 simultaneous devices**.

| Command | Description | Example |
| :--- | :--- | :--- |
| `create-user <email>` | Creates an account and auto-provisions devices (default `pc,phone`) in one command. | `./vpn-admin create-user gamer@vpn.com --tier free --devices pc,phone` |
| `add-user <email>` | Registers a new account without provisioning devices yet. | `./vpn-admin add-user pro@vpn.com --tier pro` |
| `list-users` | Displays a table of all accounts, device counts, daily/monthly bandwidth used, and quota status. | `./vpn-admin list-users` |
| `show-user <email>` | Displays full details for an account, including assigned IPs, public keys, and config paths. | `./vpn-admin show-user gamer@vpn.com` |
| `upgrade-user <email> --tier <free\|pro>` | Switches account tier between Free (2GB/day) and Pro (200GB/month). | `./vpn-admin upgrade-user gamer@vpn.com --tier pro` |
| `reset-quota <email>` | Manually resets accumulated usage to 0 and restores active status for a quota-exceeded account. | `./vpn-admin reset-quota gamer@vpn.com` |
| `delete-user <email>` | Deletes an account, removes all associated devices from WireGuard, and deletes config files. | `./vpn-admin delete-user gamer@vpn.com` |

---

## 3. Device & Client Configurations

| Command | Description | Example |
| :--- | :--- | :--- |
| `add-device <email> <name>` | Provisions a new device under an account (blocks if account already has 2 devices). | `./vpn-admin add-device gamer@vpn.com laptop` |
| `delete-device <email> <name>` | Removes a specific device and revokes its WireGuard tunnel IP. | `./vpn-admin delete-device gamer@vpn.com phone` |
| `show-config <email> <name>` | Prints the complete WireGuard `.conf` file to terminal or saves to a file. | `./vpn-admin show-config gamer@vpn.com pc --output pc.conf` |
| `show-qr <email> <name>` | Displays a terminal ANSI QR code to scan with the WireGuard mobile app. | `./vpn-admin show-qr gamer@vpn.com phone` |

---

## 4. Kernel Synchronization & Maintenance

| Command | Description | Example |
| :--- | :--- | :--- |
| `sync` | Synchronizes active database peers to the live WireGuard interface and restores state on VPS reboot. | `./vpn-admin sync` |
| `poll` | Executes one cycle of reading kernel byte counters and dropping any peers exceeding quota. | `./vpn-admin poll` |

---

## 5. Web Portal & REST API (`http://localhost:10000`)

The background monitoring daemon provides a web interface and HTTP API:

* `GET /api/accounts` — Returns JSON list of all accounts, devices, usage, and quota status.
* `POST /api/accounts` — Creates an account `{ "email": "...", "tier": "free", "devices": ["pc"] }`.
* `POST /api/accounts/<email>/devices` — Provisions a device (supports auto keygen or `{ "public_key": "..." }`).
* `DELETE /api/accounts/<email>/devices/<name>` — Deletes a device.
* `DELETE /api/accounts/<email>` — Deletes an account.
* `GET /api/accounts/<email>/devices/<name>/config` — Direct `.conf` file download.
* `POST /api/accounts/<email>/reset-quota` — Resets quota and reactivates account.
* `GET /api/keys` — Lists all registered public keys and mapped devices.
* `DELETE /api/keys/<public_key>` — Revokes peer access by public key.
