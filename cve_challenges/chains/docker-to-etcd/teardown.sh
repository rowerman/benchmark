#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain-docker-etcd"

echo "[*] Tearing down Docker-to-etcd chain..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already deleted"

docker rm -f chain22-registry 2>/dev/null || true
rm -rf /home/kianabin/cve-flags/chain22 2>/dev/null || true

echo "[+] Chain Docker-to-etcd torn down"
