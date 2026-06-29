#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain-cri-etcd"

echo "[*] Tearing down CRI-to-etcd chain..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already deleted"

rm -rf /home/kianabin/cve-flags/chain21 2>/dev/null || true
docker rmi chain21-cri-pod:local 2>/dev/null || true

echo "[+] Chain CRI-to-etcd torn down"
