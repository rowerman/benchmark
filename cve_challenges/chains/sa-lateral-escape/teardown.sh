#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain13-sa-escape"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain13 2>/dev/null || true
echo "[+] Chain 13 teardown complete"
