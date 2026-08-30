#!/bin/bash
# Temporary Docker scenario validation loop (resume of 2026-08-29 task).
# Start -> poll registered host port -> stop -> clean up images per scenario.
set -uo pipefail
cd "$(dirname "$0")/.."

LOG=/tmp/cve-benchmark-docker-$(date +%Y%m%d-%H%M%S).log
CSV=/tmp/cve-benchmark-docker-results.tsv
DONE=/tmp/docker-done.txt
[ -f "$DONE" ] || : > "$DONE"
echo "=== Docker scenario validation $(date) ===" | tee "$LOG"

PASS=0; FAIL=0

cleanup_images() {
  local sid="$1"
  local path="$2"
  # 1) images built for this compose project
  docker image prune -af --filter "label=com.docker.compose.project=$(basename "$path")" >/dev/null 2>&1 || true
  # 2) dangling images (interrupted builds etc.)
  docker image prune -f >/dev/null 2>&1 || true
  # 3) registry images pulled by this scenario that no later scenario needs
  python3 - "$sid" <<'PYEOF' > /tmp/imgs-to-rm.txt
import os, sys, yaml
sid = sys.argv[1]
d = yaml.safe_load(open('scripts/scenarios.yaml'))
s = d['scenarios'][sid]
data = None
for cf in ('docker-compose.yml', 'docker-compose.yaml'):
    f = os.path.join(s['path'], cf)
    if os.path.exists(f):
        data = yaml.safe_load(open(f)) or {}
        break
if data:
    for c in (data.get('services') or {}).values():
        if c.get('image'):
            print(c['image'].split('@')[0])
PYEOF
  python3 - <<'PYEOF' > /tmp/needed-imgs.txt
import os, yaml
done = set(open('/tmp/docker-done.txt').read().split())
d = yaml.safe_load(open('scripts/scenarios.yaml'))
need = set()
for sid2, s in sorted(d['scenarios'].items()):
    if s['type'] != 'docker' or s.get('optional') or sid2 in done:
        continue
    for cf in ('docker-compose.yml', 'docker-compose.yaml'):
        f = os.path.join(s['path'], cf)
        if not os.path.exists(f):
            continue
        data = yaml.safe_load(open(f)) or {}
        for c in (data.get('services') or {}).values():
            if c.get('image'):
                need.add(c['image'].split('@')[0].split(':')[0])
print('\n'.join(sorted(need)))
PYEOF
  while IFS= read -r img; do
    [ -n "$img" ] || continue
    base="${img%%:*}"
    if ! grep -qx "$base" /tmp/needed-imgs.txt; then
      docker rmi "$img" >/dev/null 2>&1 || true
    fi
  done < /tmp/imgs-to-rm.txt
}

python3 - <<'PYEOF' > /tmp/docker-scenario-ids.txt
import yaml
d = yaml.safe_load(open('scripts/scenarios.yaml'))
for sid, s in sorted(d['scenarios'].items()):
    if s['type'] == 'docker' and not s.get('optional'):
        print(sid)
PYEOF

while IFS= read -r sid; do
  [ -n "$sid" ] || continue
  if grep -qx "$sid" "$DONE"; then
    echo "[SKIP] $sid already validated" | tee -a "$LOG"
    continue
  fi
  # Memory-limited scenarios (Oracle XE / MSSQL need >= 2GB RAM; host has 1.9GB)
  heavy=$(python3 - "$sid" <<'PYEOF'
import os, sys, yaml
sid = sys.argv[1]
d = yaml.safe_load(open('scripts/scenarios.yaml'))
s = d['scenarios'][sid]
for cf in ('docker-compose.yml', 'docker-compose.yaml'):
    f = os.path.join(s['path'], cf)
    if not os.path.exists(f):
        continue
    data = yaml.safe_load(open(f)) or {}
    for c in (data.get('services') or {}).values():
        img = (c.get('image') or '').lower()
        if any(k in img for k in ('mssql', 'sqlserver', 'oracle')):
            print('1')
            raise SystemExit
PYEOF
)
  if [ "$heavy" = "1" ]; then
    echo "[RESULT] $sid SKIP-MEM (Oracle/MSSQL need >=2GB RAM; host 1.9GB)" | tee -a "$LOG"
    printf '%s\tSKIP-MEM\tram-limited\n' "$sid" >> "$CSV"
    echo "$sid" >> "$DONE"
    continue
  fi
  path=$(python3 -c "import yaml;print(yaml.safe_load(open('scripts/scenarios.yaml'))['scenarios']['$sid']['path'])")
  start_ts=$(date +%s)
  echo "[TEST] $sid start=$(date +%T)" | tee -a "$LOG"
  if timeout 1800 bash scripts/start-scenario.sh "$sid" >> "$LOG" 2>&1; then
    port=$(python3 -c "import yaml;print(yaml.safe_load(open('scripts/scenarios.yaml'))['scenarios']['$sid'].get('port',0))")
    ok=0; waited=0
    for i in $(seq 1 48); do
      if timeout 3 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
        ok=1; waited=$((i*5))
        break
      fi
      sleep 5
    done
    if [ "$ok" = 1 ]; then
      code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$port/" 2>/dev/null || echo n/a)
      echo "[RESULT] $sid PASS port=$port http=$code wait=${waited}s" | tee -a "$LOG"
      printf '%s\tPASS\tport=%s\thttp=%s\n' "$sid" "$port" "$code" >> "$CSV"
      echo "$sid" >> "$DONE"
      PASS=$((PASS+1))
    else
      echo "[RESULT] $sid STARTED-BUT-PORT-UNREACHABLE port=$port" | tee -a "$LOG"
      printf '%s\tSTARTED-BUT-PORT-UNREACHABLE\tport=%s\n' "$sid" "$port" >> "$CSV"
      echo "$sid" >> "$DONE"
      FAIL=$((FAIL+1))
    fi
  else
    rc=$?
    echo "[RESULT] $sid START_FAILED rc=$rc" | tee -a "$LOG"
    printf '%s\tSTART_FAILED\trc=%s\n' "$sid" "$rc" >> "$CSV"
    echo "$sid" >> "$DONE"
    FAIL=$((FAIL+1))
  fi
  echo "[CLEANUP] $sid stop ..." | tee -a "$LOG"
  timeout 180 bash scripts/stop-scenario.sh "$sid" >> "$LOG" 2>&1
  cleanup_images "$sid" "$path"
  elapsed=$(( $(date +%s) - start_ts ))
  echo "[CLEANUP] $sid done (elapsed ${elapsed}s, free: $(df -h / | awk 'NR==2{print $4}'))" | tee -a "$LOG"
done < /tmp/docker-scenario-ids.txt

echo "" | tee -a "$LOG"
echo "=== Docker results: PASS=$PASS FAIL=$FAIL ===" | tee -a "$LOG"
echo "CSV: $CSV"
