#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-34] Teardown — stopping components..."

docker compose -f "$ROOT/docker/web/xxe-svg/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/db/elasticsearch-script/docker-compose.yml" down -v 2>/dev/null || true

echo "[Chain-34] Teardown complete"
