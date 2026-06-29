#!/bin/bash
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain15-pg-node"

echo "[Chain 15] Tearing down..."

# Stop Docker scenarios
docker compose -f "$ROOT/docker/web/postgres-sqli/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/db/postgres-weak-auth/docker-compose.yml" down -v 2>/dev/null || true

# Delete K8s cluster
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

# Clean up flags
rm -rf /home/kianabin/cve-flags/chain15

echo "[Chain 15] Teardown complete"
