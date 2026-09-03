#!/bin/sh
set -eu
python3 - "$CVE_FLAG" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path('/app/memory.json')
data = json.loads(path.read_text())
data['TaskExecutor']['residentTenants']['victim-corp']['flag'] = sys.argv[1]
path.write_text(json.dumps(data))
PY
exec python3 /app/app.py
