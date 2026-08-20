#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain15-pg-node"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain15 /home/kianabin/cve-flags/chain15-write 2>/dev/null || true
echo "[+] Chain 15 teardown complete"
