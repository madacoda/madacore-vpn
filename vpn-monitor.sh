#!/usr/bin/with-contenv sh
exec gunicorn -w 2 -b 0.0.0.0:10000 app.monitor_web:app
