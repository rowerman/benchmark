#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-37] GraphQL IDOR to CouchDB RCE to PwnKit Escalation — 3 steps, Web→DB→Linux"

# Step 1: GraphQL IDOR (Docker)
echo "=== Step 1: WEB-16 GraphQL IDOR ==="
docker compose -f "$ROOT/docker/web/graphql-idor/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] GraphQL API at http://localhost:10116"

# Step 2: CouchDB RCE (Docker)
echo "=== Step 2: DB-08 CouchDB RCE ==="
docker compose -f "$ROOT/docker/db/couchdb-rce/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] CouchDB at http://localhost:10208 (admin:admin123)"

# Step 3: Polkit PwnKit (Docker)
echo "=== Step 3: LNX-11 Polkit PwnKit ==="
docker compose -f "$ROOT/docker/linux/polkit-pwnkit/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] SSH at localhost:10307 (attacker:password123)"

echo ""
echo "[Chain-37] Ready"
echo "  Step 1: http://localhost:10116/graphql → introspection + IDOR → flag{c37-step1-graphql}"
echo "  Step 2: http://localhost:10208 → CouchDB Erlang view RCE → flag{c37-step2-couch}"
echo "  Step 3: ssh attacker@localhost -p 10307 → PwnKit exploit → flag{c37-step3-pwnkit}"
