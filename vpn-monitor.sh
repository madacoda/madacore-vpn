#!/usr/bin/with-contenv sh
# 1. Synchronize database peers to live WireGuard interface on startup
python3 /app/manage_vpn.py sync 2>/dev/null || true

# 2. Launch high-efficiency, multi-threaded monitoring & management service (1 worker, 4 threads to minimize RAM)
exec gunicorn -w 1 --threads 4 -b 0.0.0.0:10000 app.monitor_web:app
