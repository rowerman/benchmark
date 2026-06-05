#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-30] Web to Domain Admin — 4 steps, Web→Linux→AD"

# Step 1: WordPress RCE (Docker)
echo "=== Step 1: WEB-03 WordPress RCE ==="
docker compose -f "$ROOT/docker/web/wordpress-simple-file-list/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] WordPress at http://localhost:10103"

# Step 2: Linux SUID Privesc (Docker)
echo "=== Step 2: LNX-06 SUID find Privesc ==="
docker compose -f "$ROOT/docker/linux/suid-find/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] SSH access: ssh attacker@localhost -p 10301 (password: password123)"

# Steps 3-4: AD (Docker Samba AD DC)
echo "=== Steps 3-4: AD Kerberoasting → DCSync ==="
AD_COMPOSE="$ROOT/ad/docker-compose.yml"
if ! docker ps --format '{{.Names}}' | grep -q ad-dc01; then
  echo "  [*] Starting Samba AD DC..."
  docker compose -f "$AD_COMPOSE" up -d --build 2>&1 | tail -2
  echo "  [*] Waiting for AD DC to be ready (up to 5 minutes)..."
  for i in $(seq 1 60); do
    if nc -z 192.168.100.10 389 2>/dev/null; then
      echo "  [*] AD DC ready"
      break
    fi
    sleep 5
  done
fi
echo "  [+] AD DC at 192.168.100.10 (north.sevenkingdoms.local)"

echo ""
echo "[Chain-30] Ready"
echo "  Step 1: http://localhost:10103 → WordPress RCE → flag{c30-step1-wp}"
echo "  Step 2: ssh attacker@localhost -p 10301 → SUID find → flag{c30-step2-suid}"
echo "  Step 3: impacket-GetUserSPNs → Kerberoasting → flag{c30-step3-kerb}"
echo "  Step 4: impacket-secretsdump → DCSync → flag{c30-step4-dcsync-final}"
