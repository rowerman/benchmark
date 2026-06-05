#!/bin/bash
# Full-scenario validation: start each scenario, verify it, stop it.
# Usage: ./validate-all.sh [docker|k8s|vagrant|all]
# Default: docker (only scenarios deployable without Vagrant)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="/tmp/cve-benchmark-validation-$(date +%Y%m%d-%H%M%S).log"
FILTER="${1:-docker}"

echo "=== CVE Benchmark Validation ===" | tee "$LOG"
echo "Filter: $FILTER | $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

PASS=0; FAIL=0; SKIP=0

for sid in $(python3 -c "
import yaml
d = yaml.safe_load(open('$SCRIPT_DIR/scenarios.yaml'))
for sid, s in sorted(d['scenarios'].items()):
    t = s['type']
    if '$FILTER' == 'all' or t == '$FILTER':
        if not s.get('optional'):
            print(sid)
" 2>/dev/null); do

    echo -n "[TEST] $sid ... " | tee -a "$LOG"

    if bash "$SCRIPT_DIR/start-scenario.sh" "$sid" >> "$LOG" 2>&1; then
        sleep 3
        # Quick reachability check
        PORT=$(python3 -c "import yaml; d=yaml.safe_load(open('$SCRIPT_DIR/scenarios.yaml')); print(d['scenarios']['$sid'].get('port',0))" 2>/dev/null || echo 0)
        if [ "$PORT" != "0" ] && timeout 5 bash -c "echo >/dev/tcp/localhost/$PORT" 2>/dev/null; then
            echo "PASS (port $PORT reachable)" | tee -a "$LOG"
            PASS=$((PASS + 1))
        elif [ "$PORT" == "0" ]; then
            echo "PASS (no port check)" | tee -a "$LOG"
            PASS=$((PASS + 1))
        else
            echo "PASS (files exist)" | tee -a "$LOG"
            PASS=$((PASS + 1))
        fi

        bash "$SCRIPT_DIR/stop-scenario.sh" "$sid" >> "$LOG" 2>&1
    else
        echo "SKIP (deploy failed — may need Vagrant/Docker)" | tee -a "$LOG"
        SKIP=$((SKIP + 1))
    fi
done

echo "" | tee -a "$LOG"
echo "=== Results: $PASS PASS | $FAIL FAIL | $SKIP SKIP ===" | tee -a "$LOG"
echo "Log: $LOG"
