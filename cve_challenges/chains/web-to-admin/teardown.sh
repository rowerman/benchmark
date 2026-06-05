#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-30] Teardown..."

docker compose -f "$ROOT/docker/web/wordpress-simple-file-list/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/linux/suid-find/docker-compose.yml" down -v 2>/dev/null || true

# Note: AD DC is shared, not stopped here since other chains may use it.
echo "  [*] AD DC left running (shared infrastructure). Stop manually if needed:"
echo "      docker compose -f $ROOT/ad/docker-compose.yml down"

echo "[Chain-30] Teardown complete"
