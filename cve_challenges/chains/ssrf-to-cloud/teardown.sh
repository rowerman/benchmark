#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-32] Teardown..."

docker compose -f "$ROOT/docker/web/ssrf-internal/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/cloud/ssrf-imds/docker-compose.yml" down -v 2>/dev/null || true

echo "[Chain-32] Teardown complete"
