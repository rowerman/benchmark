#!/bin/bash
# Chain 4: AS-REP Roasting to Golden Ticket
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
echo "[Chain 4] AS-REP to Golden Ticket — 4 steps, AD only"
echo ""
echo "  This chain runs on the shared Samba AD DC (Docker)."
echo "  Ensure AD is running: docker compose -f $ROOT/ad/docker-compose.yml up -d --build"
echo ""
echo "  Step 1: impacket-GetNPUsers → AS-REP roast 'no_preauth' → crack → flag{chain4-step1-asrep}"
echo "  Step 2: Pass-the-Hash → castelblack → flag{chain4-step2-pth}"
echo "  Step 3: impacket-secretsdump → DCSync → KRBTGT hash → flag{chain4-step3-dcsync}"
echo "  Step 4: ticketer.py → Golden Ticket → Enterprise Admin → flag{chain4-step4-golden-final}"
echo ""
echo "[Chain 4] Ready."
