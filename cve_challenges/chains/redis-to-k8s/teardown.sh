#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain16-redis-k8s"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain16 2>/dev/null || true
echo "[+] Chain 16 teardown complete"
