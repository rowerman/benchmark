#!/bin/bash
set -euo pipefail
echo "[notebook-to-scp] Tearing down chain..."
cd "$(dirname "$0")"
docker compose -f ../scenarios/cloud/scp-bypass/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/cosmiss-notebook/docker-compose.yml down -v 2>/dev/null || true
docker compose -f ../scenarios/cloud/notebook-escape/docker-compose.yml down -v 2>/dev/null || true
echo "[notebook-to-scp] Cleaned up"
