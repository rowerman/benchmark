#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[*] Tearing down GPP-to-DCSync chain..."

# Remove chain-specific flag files from DC
docker exec ad-dc01 bash -c "rm -f /var/lib/samba/private/chain19_dcsync_flag.txt" 2>/dev/null || true

# Note: We do NOT stop the shared AD DC — it may be used by other scenarios
echo "[+] Chain torn down (AD DC kept running for other scenarios)"
