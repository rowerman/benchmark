#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain-k8s-admin"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain2-flags 2>/dev/null || true
echo "[+] Chain 2 teardown complete"
