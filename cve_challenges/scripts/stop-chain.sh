#!/bin/bash
# Usage: ./stop-chain.sh <chain-directory-name>
set -euo pipefail

CHAIN_NAME="${1:?Usage: $0 <chain-directory-name>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHAIN_DIR="$(dirname "$SCRIPT_DIR")/chains/$CHAIN_NAME"

[ -f "$CHAIN_DIR/teardown.sh" ] || { echo "[!] Missing teardown.sh: $CHAIN_NAME" >&2; exit 1; }
exec bash "$CHAIN_DIR/teardown.sh"
