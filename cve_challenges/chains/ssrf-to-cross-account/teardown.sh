#!/bin/bash
cd "$(dirname "$0")"
docker compose down -v 2>/dev/null || true
echo "[Chain-32] Cleaned up"
