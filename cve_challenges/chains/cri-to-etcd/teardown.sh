#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain-cri-etcd"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain21 2>/dev/null || true
echo "[+] Chain CRI-to-etcd teardown complete"
