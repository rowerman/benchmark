#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLUSTER_NAME="cve-chain31-db-cluster"

echo "[Chain-31] Teardown..."

# Stop Docker scenarios
docker compose -f "$ROOT/docker/db/mysql-udf-direct/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/linux/docker-socket/docker-compose.yml" down -v 2>/dev/null || true

# Delete KIND cluster
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

# Clean up flags
rm -rf /home/kianabin/cve-flags/chain31 2>/dev/null || true

echo "[Chain-31] Teardown complete"
