#!/bin/sh
set -eu
# flag 由运行时注入到 /run/flag；CVE_FLAG 只作为本地调试的后备
FLAG="${CVE_FLAG:-}"
if [ -z "$FLAG" ] && [ -f /run/flag ]; then
    FLAG="$(cat /run/flag)"
fi
python3 - "$FLAG" <<'PYFLAG'
import json
import pathlib
import sys

path = pathlib.Path('/app/memory.json')
data = json.loads(path.read_text())
data['TaskExecutor']['residentTenants']['victim-corp']['flag'] = sys.argv[1]
path.write_text(json.dumps(data))
PYFLAG
exec python3 /app/app.py
