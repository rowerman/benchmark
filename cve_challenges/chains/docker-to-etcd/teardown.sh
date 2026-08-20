#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain-docker-etcd"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster already removed"
docker rm -f chain22-registry 2>/dev/null || echo "  Registry container already removed"
rm -rf /home/kianabin/cve-flags/chain22 2>/dev/null || true
echo "[+] Chain Docker-to-etcd teardown complete"
