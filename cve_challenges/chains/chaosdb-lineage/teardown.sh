#!/bin/bash
set -euo pipefail
python3 "$(dirname "$0")/../_runtime/teardown_chain.py" 50
