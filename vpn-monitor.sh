#!/usr/bin/with-contenv sh

# 1. Wait for WireGuard interface to be brought up by linuxserver init
echo "[*] Waiting for wg0 interface..."
for i in $(seq 1 30); do
    if wg show wg0 >/dev/null 2>&1; then
        echo "[+] wg0 interface detected!"
        break
    fi
    sleep 1
done

# 2. Synchronize database peers to live WireGuard interface on startup
python3 /app/manage_vpn.py sync 2>/dev/null || true

# 3. Launch high-efficiency, multi-threaded monitoring & management service (1 worker, 4 threads to minimize RAM)
exec gunicorn -w 1 --threads 4 -b 0.0.0.0:10000 app.monitor_web:app
