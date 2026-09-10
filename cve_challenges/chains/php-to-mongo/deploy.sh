#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
FLAG1="${CVE_FLAG1:-flag{c35-step1-php\}}"
FLAG2="${CVE_FLAG2:-flag{c35-step2-mongo\}}"

echo "[Chain-35] PHP Deserialization to MongoDB NoSQL Injection — 2 steps, Web→DB"

# Step 1: PHP deserialization auth bypass (Docker)
echo "=== Step 1: WEB-17 PHP Deserialization ==="
CVE_FLAG="$FLAG1" docker compose -f "$ROOT/scenarios/web/php-deserialization/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] PHP deserialization app at http://localhost:10117"

# Step 2: MongoDB NoSQL injection (Docker)
echo "=== Step 2: DB-09 MongoDB NoSQL Injection ==="
CVE_FLAG="$FLAG2" docker compose -f "$ROOT/scenarios/db/mongodb-nosqli/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] MongoDB NoSQLi web app at http://localhost:10209"

echo ""
echo "[Chain-35] Ready"
echo "  Step 1: http://localhost:10117 → PHP deser admin bypass → flag{c35-step1-php}"
echo "  Step 2: http://localhost:10209 → NoSQL \$ne injection → flag{c35-step2-mongo}"
