#!/bin/bash
set -euo pipefail

echo "[*] Tearing down Kerb-to-Deleg chain..."

# Clean flag files from DC
docker exec ad-dc01 bash -c "rm -f /var/lib/samba/private/chain20_*.txt" 2>/dev/null || true

echo "[+] Chain torn down (AD DC kept running)"
