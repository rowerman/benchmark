#!/bin/bash
# Reset all CVE benchmark environments: stop Docker, K8s, and Vagrant scenarios.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== CVE Benchmark: Reset All ==="

# Stop all Docker scenarios
echo "[*] Stopping Docker scenarios..."
docker ps --format '{{.Names}}' | grep -E '^(db05|web03|lnx05|postgres|mysql|redis|tomcat|sudo-chroot|mssql|oracle)' | while read c; do
  docker stop "$c" 2>/dev/null || true
  docker rm "$c" 2>/dev/null || true
done

# Tear down KIND clusters
echo "[*] Removing K8s clusters..."
kind get clusters 2>/dev/null | grep 'cve-' | while read c; do
  kind delete cluster --name "$c" 2>/dev/null || true
done

# Stop Vagrant VMs
echo "[*] Halting Vagrant VMs..."
if command -v vagrant &>/dev/null; then
  for vmdir in "$ROOT"/docker/linux/*/; do
    (cd "$vmdir" && vagrant halt 2>/dev/null) || true
  done
fi

# Clean up flag directories
echo "[*] Cleaning flag files..."
rm -rf /home/kianabin/cve-flags

# Remove leftover docker networks
echo "[*] Pruning Docker networks..."
docker network prune -f 2>/dev/null || true

echo "[+] Reset complete"
