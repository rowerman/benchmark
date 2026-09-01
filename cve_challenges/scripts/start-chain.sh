#!/bin/bash
# Usage: ./start-chain.sh <chain-directory-name>
set -euo pipefail

CHAIN_NAME="${1:?Usage: $0 <chain-directory-name>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CHAIN_DIR="$ROOT_DIR/chains/$CHAIN_NAME"

[ -d "$CHAIN_DIR" ] || { echo "[!] Unknown chain: $CHAIN_NAME" >&2; exit 1; }
[ -f "$CHAIN_DIR/chain.yaml" ] || { echo "[!] Missing chain.yaml: $CHAIN_NAME" >&2; exit 1; }
[ -f "$CHAIN_DIR/deploy.sh" ] || { echo "[!] Missing deploy.sh: $CHAIN_NAME" >&2; exit 1; }

COUNT=$(python3 "$SCRIPT_DIR/flag_contract.py" chain "$CHAIN_DIR")
[ "$COUNT" -gt 0 ] || { echo "[!] Chain has no Flag-bearing steps: $CHAIN_NAME" >&2; exit 1; }

export CVE_FLAG="${CVE_FLAG:-}"
for i in $(seq 1 "$COUNT"); do
  name="CVE_FLAG$i"
  if [ -z "${!name:-}" ]; then
    value=$(python3 "$SCRIPT_DIR/flag_manager.py" "$CHAIN_NAME-step$i")
    export "$name=$value"
  fi
done
if [ -z "$CVE_FLAG" ]; then
  CVE_FLAG="$CVE_FLAG1"
  export CVE_FLAG
fi

echo "[*] Starting attack chain: $CHAIN_NAME"
for i in $(seq 1 "$COUNT"); do
  name="CVE_FLAG$i"
  printf '[+] Flag %s: %s\n' "$i" "${!name}"
done
if [ "${CHAIN_DRY_RUN:-0}" = "1" ]; then
  echo "[+] Dry run: deploy.sh was not invoked"
  exit 0
fi
exec bash "$CHAIN_DIR/deploy.sh"
