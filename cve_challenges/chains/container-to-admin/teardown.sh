#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-chain-k8s-admin 2>/dev/null || true
rm -rf $HOME/.cache/cve-challenges/chain2-flags
echo "[Chain 2] Teardown complete"
