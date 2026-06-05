#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain Kerb-to-Deleg] 3-step advanced AD chain"
echo "  AD-01 (Kerberoasting) -> AD-14 (Silver Ticket) -> AD-16 (Constrained Delegation)"

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

if ! nc -z 192.168.100.10 389 2>/dev/null; then
    echo "[!] ERROR: Cannot reach AD DC at 192.168.100.10:389"
    exit 1
fi

FLAG1="${CVE_FLAG_1:-flag{chain20-step1-kerb}}"
FLAG2="${CVE_FLAG_2:-flag{chain20-step2-silver}}"
FLAG3="${CVE_FLAG_3:-flag{chain20-step3-deleg}}"

echo "[*] Chain flags:"
echo "  Step 1 (Kerberoasting): $FLAG1"
echo "  Step 2 (Silver Ticket): $FLAG2"
echo "  Step 3 (Delegation): $FLAG3"

# Store chain flags on the DC
docker exec ad-dc01 bash -c "
    echo '$FLAG2' > /var/lib/samba/private/chain20_silver.txt
    echo '$FLAG3' > /var/lib/samba/private/chain20_deleg.txt
    chmod 644 /var/lib/samba/private/chain20_silver.txt
    chmod 644 /var/lib/samba/private/chain20_deleg.txt
" 2>/dev/null || true

echo ""
echo "[Chain Kerb-to-Deleg] Ready"
echo "  Entry: lowpriv / Password123! @ 192.168.100.10"
echo "  Step 1: Kerberoast svc_deleg, crack DelegPass2024!"
echo "  Step 2: Forge Silver Ticket for cifs/dc01 with svc_deleg NTLM hash"
echo "  Step 3: S4U2Self+S4U2Proxy to impersonate Admin via LDAP delegation"
