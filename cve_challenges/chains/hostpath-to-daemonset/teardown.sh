#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain11-hostpath-node"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain11 2>/dev/null || true
echo "[+] Chain 11 teardown complete"
