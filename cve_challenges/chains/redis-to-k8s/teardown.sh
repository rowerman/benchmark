#!/bin/bash
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
CLUSTER_NAME="cve-chain16-redis-k8s"

echo "[Chain 16] Tearing down..."

# Stop Docker scenarios
docker compose -f "$ROOT/docker/db/redis-unauth/docker-compose.yml" down -v 2>/dev/null || true

# Delete K8s cluster
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

# Clean up flags
rm -rf /home/kianabin/cve-flags/chain16

echo "[Chain 16] Teardown complete"
