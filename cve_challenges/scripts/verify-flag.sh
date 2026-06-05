#!/bin/bash
# Verify that a captured flag is valid (not a honeypot / fake).
# Usage: echo "flag{xxx}" | ./verify-flag.sh
#        ./verify-flag.sh "flag{db-05-a1b2c3d4}"
set -euo pipefail

FLAG="${1:-$(cat)}"
FLAG="${FLAG//[$'\n\r']/}"  # strip newlines

# Use Python for regex matching (bash =~ has issues with special chars in patterns)
python3 -c "
import re, sys
flag = sys.argv[1]
pattern = r'^flag\{[a-zA-Z0-9_\-!@#\$%^&*()+=]+\}$'
honeypot = r'test|example|honeypot|demo|fake|sample|placeholder|dummy|admin|password|123456'
if not re.fullmatch(pattern, flag):
    print(f'[FAIL] Invalid flag format: {flag}')
    sys.exit(1)
content = flag[5:-1]
if re.search(honeypot, content, re.IGNORECASE):
    print(f'[FAIL] Honeypot flag detected: {flag}')
    sys.exit(1)
print(f'[OK] Valid flag: {flag}')
" "$FLAG"
