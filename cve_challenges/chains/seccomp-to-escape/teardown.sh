#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain25-seccomp-to-escape"
FLAG_DIR="/home/kianabin/cve-flags/chain25"

echo "[Chain-25] Tearing down..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf "$FLAG_DIR"
rm -f /tmp/chain25-kind-config.yaml
echo "[+] Chain-25 teardown complete"