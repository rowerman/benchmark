#!/bin/bash
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
kind delete cluster --name cve-chain10-priv-etcd 2>/dev/null || true
rm -rf /home/kianabin/cve-flags/chain10
echo "[Chain 10] Teardown complete"
