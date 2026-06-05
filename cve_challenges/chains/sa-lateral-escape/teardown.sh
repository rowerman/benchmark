#!/bin/bash
set -euo pipefail
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
kind delete cluster --name cve-chain13-sa-escape 2>/dev/null || true
rm -rf /home/kianabin/cve-flags/chain13
echo "[Chain 13] Teardown complete"
