#!/bin/sh
VICTIM_URL="http://victim:5000/secret"

if [ -n "$SECRET_TOKEN" ]; then
    TOKEN="$SECRET_TOKEN"
else
    TOKEN="flag{net-03-default}"
fi

echo "[monitor] Starting periodic health check with secret token..."

while true; do
    echo "[monitor] Reporting to $VICTIM_URL ..."
    curl -s -H "X-Token: $TOKEN" "$VICTIM_URL" -o /dev/null -w "Response: %{http_code}\n"
    sleep 30
done
