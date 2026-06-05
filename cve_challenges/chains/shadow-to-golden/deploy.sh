#!/bin/bash
set -euo pipefail

echo "[Chain-27] Shadow Credentials to Golden Ticket"
echo "[*] This chain uses the shared Samba AD DC infrastructure."
echo "[*] Ensure the AD DC is running: cd ../../ad && docker compose up -d --build"
echo ""
echo "[+] Chain-27 Ready (shared AD infrastructure)"
echo "    DC IP: 192.168.100.10"
echo "    Domain: north.sevenkingdoms.local"
echo "    Entry: lowpriv/Password123!"
echo ""
echo "    Flags:"
echo "    Step 1: flag{chain27-step1-shadow} - after PKINIT auth as svc_shadow"
echo "    Step 2: flag{chain27-step2-ntlm} - NTLM hash extracted from TGT PAC"
echo "    Step 3: flag{chain27-step3-dcsync} - krbtgt hash via DCSync"
echo "    Step 4: flag{chain27-step4-golden-final} - Golden Ticket forged and verified"