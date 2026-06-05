#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain23-ingress-to-etcd"
FLAG_DIR="/home/kianabin/cve-flags/chain23"

echo "[Chain-23] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
rm -f /tmp/chain23-kind-config.yaml
echo "[+] Chain-23 teardown complete"