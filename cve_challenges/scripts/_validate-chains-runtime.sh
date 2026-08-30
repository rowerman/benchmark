#!/bin/bash
# Temporary runtime-chain validation loop (cloud chains via deploy_chain.py).
set -uo pipefail
cd "$(dirname "$0")/.."

LOG=/tmp/cve-benchmark-chains-$(date +%Y%m%d-%H%M%S).log
CSV=/tmp/cve-benchmark-chains-runtime-results.tsv
DONE=/tmp/chains-runtime-done.txt
[ -f "$DONE" ] || : > "$DONE"
echo "=== Runtime chain validation $(date) ===" | tee "$LOG"

PASS=0; FAIL=0

while read -r dir num; do
  [ -n "$dir" ] || continue
  if grep -qx "$dir" "$DONE"; then
    echo "[SKIP] $dir already validated" | tee -a "$LOG"
    continue
  fi
  start_ts=$(date +%s)
  echo "[TEST] $dir (Chain-$num) start=$(date +%T)" | tee -a "$LOG"
  if timeout 2400 bash "chains/$dir/deploy.sh" >> "$LOG" 2>&1; then
    port=$((11600 + num))
    ok=0
    for i in $(seq 1 24); do
      if timeout 3 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null; then ok=1; break; fi
      sleep 5
    done
    health=""
    for i in $(seq 1 12); do
      health=$(curl -s -m 5 "http://127.0.0.1:$port/health" 2>/dev/null | head -c 120)
      [ -n "$health" ] && break
      sleep 5
    done
    art=$(curl -s -m 5 -H "X-Chain-Key: chain-$num-key" "http://127.0.0.1:$port/artifacts/step-1-output" 2>/dev/null | head -c 80)
    step_ok=$(curl -s -m 8 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/step/1/" 2>/dev/null)
    containers=$(docker ps --format '{{.Names}}' | grep -c "chain-${num}-" || true)
    if [ "$ok" = 1 ] && [ -n "$health" ]; then
      echo "[RESULT] $dir PASS port=$port health=$health step1_http=$step_ok containers=$containers art=[$art]" | tee -a "$LOG"
      printf '%s\tPASS\tport=%s\thealth=%s\tstep1=%s\tcontainers=%s\n' "$dir" "$port" "$health" "$step_ok" "$containers" >> "$CSV"
      echo "$dir" >> "$DONE"
      PASS=$((PASS+1))
    else
      echo "[RESULT] $dir CHECK_FAILED port_reachable=$ok health=[$health]" | tee -a "$LOG"
      printf '%s\tCHECK_FAILED\tport=%s\thealth=%s\n' "$dir" "$port" "$health" >> "$CSV"
      echo "$dir" >> "$DONE"
      FAIL=$((FAIL+1))
    fi
  else
    rc=$?
    echo "[RESULT] $dir START_FAILED rc=$rc" | tee -a "$LOG"
    printf '%s\tSTART_FAILED\trc=%s\n' "$dir" "$rc" >> "$CSV"
    echo "$dir" >> "$DONE"
    FAIL=$((FAIL+1))
  fi
  echo "[CLEANUP] $dir teardown ..." | tee -a "$LOG"
  timeout 600 bash "chains/$dir/teardown.sh" >> "$LOG" 2>&1
  docker image prune -af --filter "label=com.docker.compose.project=chain-${num}-runtime" >/dev/null 2>&1 || true
  docker image prune -af --filter "label=com.docker.compose.project=chain-${num}-step" >/dev/null 2>&1 || true
  docker image prune -f >/dev/null 2>&1 || true
  elapsed=$(( $(date +%s) - start_ts ))
  echo "[CLEANUP] $dir done (elapsed ${elapsed}s, networks: $(docker network ls --format '{{.Name}}' | grep -c '^chain-' || true))" | tee -a "$LOG"
done <<'EOF'
ai-serverless-identity 51
cf-to-scp 41
chaosdb-lineage 50
ci-to-oidc 45
db-to-cross-account 46
db-to-passrole 48
detection-blindspot 55
gateway-to-deputy 47
identity-trust 54
lambda-to-cross-account 33
loggap-to-s3-stealth 43
managed-data-lateral 56
managed-db-lateral 49
middleware-network 52
notebook-to-scp 38
s3-to-cf 36
ssrf-to-oidc 39
supply-chain-persistence 53
svctag-to-imds-to-deputy 44
web-to-db-to-cross-account 42
EOF

echo "" | tee -a "$LOG"
echo "=== Runtime chain results: PASS=$PASS FAIL=$FAIL ===" | tee -a "$LOG"
echo "CSV: $CSV"
