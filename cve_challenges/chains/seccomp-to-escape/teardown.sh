#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain25-seccomp-to-escape"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
rm -rf /home/kianabin/cve-flags/chain25 2>/dev/null || true
echo "[+] Chain-25 teardown complete"
