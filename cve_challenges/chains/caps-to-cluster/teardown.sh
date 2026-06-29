#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain12-caps-cluster"

echo "[Chain 12] Tearing down..."

# Delete K8s cluster
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

# Clean up flags
rm -rf /home/kianabin/cve-flags/chain12

echo "[Chain 12] Teardown complete"
