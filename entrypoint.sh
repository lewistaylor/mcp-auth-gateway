#!/bin/sh
# Fix ownership on the data directory — Railway volume mounts are root-owned
# but the app runs as the unprivileged `node` user.
chown -R node:node /app/data 2>/dev/null || true

exec su -s /bin/sh node -c 'exec node /app/server.mjs'
