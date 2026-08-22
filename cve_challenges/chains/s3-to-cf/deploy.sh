#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
python3 ../_runtime/deploy_chain.py "$(pwd)" 36
