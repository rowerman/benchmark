#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-chain6-k8s-kubelet-etcd 2>/dev/null || true

echo "[Chain 6] Teardown complete"
