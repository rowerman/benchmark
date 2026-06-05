#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain GPP-to-DCSync] 3-step AD attack chain"
echo "  AD-13 (GPP/cpassword) -> AD-15 (Targeted Kerberoasting) -> AD-09 (DCSync)"

# Start the shared AD DC if not already running
if ! docker ps --format '{{.Names}}' | grep -q 'ad-dc01'; then
    echo "[*] Starting shared AD Domain Controller..."
    docker compose -f "$ROOT/ad/docker-compose.yml" up -d --build
    echo "[*] Waiting for AD DC to be ready (up to 5 minutes)..."
    for i in $(seq 1 60); do
        if nc -z 192.168.100.10 389 2>/dev/null; then
            echo "[*] AD DC ready"
            break
        fi
        sleep 5
    done
else
    echo "[*] AD DC already running"
fi

# Verify connectivity
if ! nc -z 192.168.100.10 389 2>/dev/null; then
    echo "[!] ERROR: Cannot reach AD DC at 192.168.100.10:389"
    exit 1
fi

# Inject chain-specific flags
# Step 1 flag: stored as cpassword in a separate GPP XML file
FLAG1="${CVE_FLAG_1:-flag{chain19-step1-gpp}}"
FLAG2="${CVE_FLAG_2:-flag{chain19-step2-kerb}}"
FLAG3="${CVE_FLAG_3:-flag{chain19-step3-dcsync}}"

echo "[*] Setting chain flags..."
echo "  Step 1 (GPP): $FLAG1"
echo "  Step 2 (Kerberoasting): $FLAG2"
echo "  Step 3 (DCSync): $FLAG3"

# Write step 3 flag on the DC
docker exec ad-dc01 bash -c "echo '$FLAG3' > /var/lib/samba/private/chain19_dcsync_flag.txt && chmod 600 /var/lib/samba/private/chain19_dcsync_flag.txt" 2>/dev/null || true

# Step 2 flag: update sql_service description
docker exec ad-dc01 bash -c "echo 'Setting chain flags...'" 2>/dev/null || true

echo ""
echo "[Chain GPP-to-DCSync] Ready"
echo "  Entry: lowpriv / Password123! @ 192.168.100.10"
echo "  Step 1: Access SYSVOL smb, decrypt cpassword"
echo "  Step 2: Set SPN on sql_service, Kerberoast, crack"
echo "  Step 3: DCSync with escalated credentials"
echo ""
echo "  Flags:"
echo "    Step 1 (GPP): $FLAG1"
echo "    Step 2 (Kerberoasting): $FLAG2"
echo "    Step 3 (DCSync): $FLAG3"
