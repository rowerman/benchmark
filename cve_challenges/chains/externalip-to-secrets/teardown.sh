#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain24-externalip-to-secrets"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
echo "[+] Chain-24 teardown complete"
