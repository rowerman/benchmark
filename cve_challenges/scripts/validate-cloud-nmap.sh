#!/bin/bash
# Feature-driven nmap service-identification regression for cloud scenarios.
# Usage:
#   bash scripts/setup-cloud-nmap.sh        # once: merge probes (+ iptables, root)
#   bash scripts/validate-cloud-nmap.sh cloud-01 cloud-07 ...
#   bash scripts/validate-cloud-nmap.sh --include-aux cloud-01 cloud-07 ...
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${NMAP_DATADIR:-$HOME/.nmap}"

if [ ! -f "$DATA_DIR/nmap-service-probes" ]; then
  echo "[!] merged nmap probe database not found at $DATA_DIR/nmap-service-probes"
  echo "    run: bash $SCRIPT_DIR/setup-cloud-nmap.sh" >&2
  exit 2
fi

exec python3 "$SCRIPT_DIR/validate-cloud-nmap.py" --datadir "$DATA_DIR" "$@"
