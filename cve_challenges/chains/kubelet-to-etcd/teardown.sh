#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain6-kubelet-pods"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
echo "[+] Chain 6 teardown complete"
