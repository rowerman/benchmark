#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain12-caps-cluster"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain12 2>/dev/null || true
echo "[+] Chain 12 teardown complete"
