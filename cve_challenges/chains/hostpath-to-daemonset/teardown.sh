#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain11-hostpath-ds"

echo "[Chain 11] Tearing down..."

# Delete K8s cluster
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

# Clean up flags
rm -rf /home/kianabin/cve-flags/chain11

echo "[Chain 11] Teardown complete"
