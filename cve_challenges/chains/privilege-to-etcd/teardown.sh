#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain10-priv-etcd"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain10 2>/dev/null || true
echo "[+] Chain 10 teardown complete"
