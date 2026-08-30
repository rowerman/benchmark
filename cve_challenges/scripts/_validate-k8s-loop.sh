#!/bin/bash
# Temporary K8s/KIND scenario validation loop.
# start -> cluster/node checks -> stop -> clean per-scenario images.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="${HOME}/kind-tools/usr/bin:/tmp/kind-tools/usr/bin:$PATH"
export FLAGS_ROOT="/tmp/cve-flags"
export KUBECONFIG="/tmp/cve-kind-kubeconfig"
export KIND_POD_WAIT_TIMEOUT=900s
export KIND_WAIT_TIMEOUT=300s

LOG=/tmp/cve-benchmark-k8s-$(date +%Y%m%d-%H%M%S).log
CSV=/tmp/cve-benchmark-k8s-results.tsv
DONE=/tmp/k8s-done.txt
[ -f "$DONE" ] || : > "$DONE"
docker image ls --format '{{.Repository}}:{{.Tag}}' | sort > /tmp/k8s-image-baseline.txt
echo "=== K8s scenario validation $(date) ===" | tee "$LOG"

PASS=0; FAIL=0

python3 - <<'PYEOF' > /tmp/k8s-scenario-ids.txt
import yaml
d = yaml.safe_load(open('scripts/scenarios.yaml'))
for sid, s in sorted(d['scenarios'].items()):
    if s['type'] == 'k8s' and not s.get('optional'):
        print(sid)
PYEOF

cleanup_k8s_images() {
  docker image ls --format '{{.Repository}}:{{.Tag}}' | sort > /tmp/k8s-images-now.txt
  comm -13 /tmp/k8s-image-baseline.txt /tmp/k8s-images-now.txt | grep -v '^kindest/node' | while IFS= read -r img; do
    docker rmi "$img" >/dev/null 2>&1 || true
  done
  docker image prune -f >/dev/null 2>&1 || true
}

while IFS= read -r sid; do
  [ -n "$sid" ] || continue
  if grep -qx "$sid" "$DONE"; then
    echo "[SKIP] $sid already validated" | tee -a "$LOG"
    continue
  fi
  path=$(python3 -c "import yaml;print(yaml.safe_load(open('scripts/scenarios.yaml'))['scenarios']['$sid']['path'])")
  cluster=$(grep -m1 '^CLUSTER_NAME=' "$path/deploy.sh" 2>/dev/null | cut -d= -f2 || echo unknown)
  start_ts=$(date +%s)
  echo "[TEST] $sid cluster=$cluster start=$(date +%T)" | tee -a "$LOG"
  timeout 2400 bash scripts/start-scenario.sh "$sid" >> "$LOG" 2>&1 &
  deploy_pid=$!
  # Wait for the cluster to appear, then preload common images while deploy.sh runs
  for i in $(seq 1 90); do
    if kind get clusters 2>/dev/null | grep -q .; then break; fi
    sleep 2
  done
  if [ "$cluster" != "unknown" ]; then
    for img in python:3.11-slim python:3.10-slim alpine:latest nginx:alpine nginx:1.24-alpine \
               nicolaka/netshoot:latest bitnami/kubectl:1.27 bitnami/kubectl:1.28 curlimages/curl:latest; do
      if docker image inspect "$img" >/dev/null 2>&1; then
        kind load docker-image "$img" --name "$cluster" >/dev/null 2>&1 || true
      fi
    done
    echo "[PRELOAD] $sid images loaded into $cluster" | tee -a "$LOG"
  fi
  wait "$deploy_pid"; rc=$?
  if [ "$rc" = 0 ]; then
    nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
    ready=$(kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{c++}END{print c+0}')
    kind_have=$(kind get clusters 2>/dev/null | grep -c . || true)
    # Re-check common images after deploy (cluster fully up); fixes loads that
    # happened while the cluster was still initializing
    if [ "$kind_have" -ge 1 ] && [ "$cluster" != "unknown" ]; then
      for img in python:3.11-slim python:3.10-slim alpine:latest nginx:alpine nginx:1.24-alpine \
                 nicolaka/netshoot:latest bitnami/kubectl:1.27 bitnami/kubectl:1.28 curlimages/curl:latest; do
        if docker image inspect "$img" >/dev/null 2>&1; then
          kind load docker-image "$img" --name "$cluster" >/dev/null 2>&1 || true
        fi
      done
    fi
    # Wait for default-namespace scenario pods to settle (up to 4 min)
    for i in $(seq 1 48); do
      bad=$(kubectl get pods -n default --no-headers 2>/dev/null | awk '$3!="Running" && $3!="Completed" && $3!="Succeeded"{c++}END{print c+0}')
      [ "$bad" = 0 ] && break
      sleep 5
    done
    echo "[PODS] $sid" | tee -a "$LOG"
    kubectl get pods -n default 2>/dev/null | tee -a "$LOG" || true
    issues=$(kubectl get pods -n default --no-headers 2>/dev/null | awk '$3!="Running" && $3!="Completed" && $3!="Succeeded"{print $1"="$3}' | tr '\n' ' ')
    if [ "$kind_have" -ge 1 ] && [ -z "$issues" ]; then
      echo "[RESULT] $sid PASS nodes=$nodes ready=$ready cluster=$cluster" | tee -a "$LOG"
      printf '%s\tPASS\tnodes=%s\tready=%s\tcluster=%s\n' "$sid" "$nodes" "$ready" "$cluster" >> "$CSV"
      echo "$sid" >> "$DONE"
      PASS=$((PASS+1))
    else
      echo "[RESULT] $sid CHECK_FAILED kind=$kind_have nodes=$nodes ready=$ready issues=[$issues]" | tee -a "$LOG"
      printf '%s\tCHECK_FAILED\tkind=%s\tnodes=%s\tready=%s\tissues=%s\n' "$sid" "$kind_have" "$nodes" "$ready" "$issues" >> "$CSV"
      echo "$sid" >> "$DONE"
      FAIL=$((FAIL+1))
    fi
  else
    echo "[RESULT] $sid START_FAILED rc=$rc" | tee -a "$LOG"
    printf '%s\tSTART_FAILED\trc=%s\n' "$sid" "$rc" >> "$CSV"
    echo "$sid" >> "$DONE"
    FAIL=$((FAIL+1))
  fi
  echo "[CLEANUP] $sid stop ..." | tee -a "$LOG"
  timeout 600 bash scripts/stop-scenario.sh "$sid" >> "$LOG" 2>&1
  cleanup_k8s_images
  elapsed=$(( $(date +%s) - start_ts ))
  echo "[CLEANUP] $sid done (elapsed ${elapsed}s, clusters: $(kind get clusters 2>/dev/null | tr '\n' ' '), free: $(df -h / | awk 'NR==2{print $4}'))" | tee -a "$LOG"
done < /tmp/k8s-scenario-ids.txt

echo "" | tee -a "$LOG"
echo "=== K8s results: PASS=$PASS FAIL=$FAIL ===" | tee -a "$LOG"
echo "CSV: $CSV"
