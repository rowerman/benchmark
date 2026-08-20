#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain17-wp-lfi"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain17 2>/dev/null || true
echo "[+] Chain 17 teardown complete"
