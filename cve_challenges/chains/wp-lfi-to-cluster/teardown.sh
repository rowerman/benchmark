#!/bin/bash
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain17-wp-lfi"

echo "[Chain 17] Tearing down..."

# Stop Docker scenarios
docker compose -f "$ROOT/docker/web/wordpress-jupiterx-lfi/docker-compose.yml" down -v 2>/dev/null || true

# Delete K8s cluster
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

# Clean up flags
rm -rf /home/kianabin/cve-flags/chain17

echo "[Chain 17] Teardown complete"
