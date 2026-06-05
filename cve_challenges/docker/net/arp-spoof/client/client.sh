#!/bin/sh
SERVER="http://server:5000"

if [ -n "$ADMIN_PASSWORD" ]; then
    ADMIN_PASS="$ADMIN_PASSWORD"
else
    ADMIN_PASS="flag{net-01-default}"
fi

echo "[client] Starting periodic credential transmission..."

while true; do
    echo "[client] Sending login credentials to $SERVER/login ..."
    curl -s -X POST "$SERVER/login" \
        -d "user=admin&pass=$ADMIN_PASS" \
        -o /dev/null -w "Response: %{http_code}\n"
    sleep 30
done
