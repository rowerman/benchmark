#!/bin/bash
# Temporary own-chain validation loop (non-runtime chains).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="${HOME}/kind-tools/usr/bin:/tmp/kind-tools/usr/bin:$PATH"
export FLAGS_ROOT="/tmp/cve-flags"
export KUBECONFIG="/tmp/cve-kind-kubeconfig"
export KIND_POD_WAIT_TIMEOUT=900s
export KIND_WAIT_TIMEOUT=300s

LOG=/tmp/cve-benchmark-chains-own-$(date +%Y%m%d-%H%M%S).log
CSV=/tmp/cve-benchmark-chains-own-results.tsv
DONE=/tmp/chains-own-done.txt
[ -f "$DONE" ] || : > "$DONE"
docker image ls --format '{{.Repository}}:{{.Tag}}' | sort > /tmp/chains-own-baseline.txt
echo "=== Own chain validation $(date) ===" | tee "$LOG"

PASS=0; FAIL=0

cleanup_chain_images() {
  docker image ls --format '{{.Repository}}:{{.Tag}}' | sort > /tmp/chains-own-now.txt
  comm -13 /tmp/chains-own-baseline.txt /tmp/chains-own-now.txt | grep -v '^kindest/node' | while IFS= read -r img; do
    docker rmi "$img" >/dev/null 2>&1 || true
  done
  docker image prune -f >/dev/null 2>&1 || true
}

# dir|type|ports(comma)|cluster
while IFS='|' read -r dir ctype ports cluster; do
  [ -n "$dir" ] || continue
  if grep -qx "$dir" "$DONE"; then
    echo "[SKIP] $dir already validated" | tee -a "$LOG"
    continue
  fi
  start_ts=$(date +%s)
  echo "[TEST] $dir ($ctype) start=$(date +%T)" | tee -a "$LOG"
  if timeout 2400 bash scripts/start-chain.sh "$dir" >> "$LOG" 2>&1; then
    if [ "$ctype" = "docker" ]; then
      allok=1
      for p in ${ports//,/ }; do
        pok=0
        for i in $(seq 1 24); do
          if timeout 3 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null; then pok=1; break; fi
          sleep 5
        done
        [ "$pok" = 1 ] || { allok=0; echo "[NOTE] $dir port $p unreachable" | tee -a "$LOG"; }
      done
      if [ "$allok" = 1 ]; then
        echo "[RESULT] $dir PASS ports=[$ports]" | tee -a "$LOG"
        printf '%s\tPASS\tports=%s\n' "$dir" "$ports" >> "$CSV"
        echo "$dir" >> "$DONE"; PASS=$((PASS+1))
      else
        echo "[RESULT] $dir CHECK_FAILED ports=[$ports]" | tee -a "$LOG"
        printf '%s\tCHECK_FAILED\tports=%s\n' "$dir" "$ports" >> "$CSV"
        echo "$dir" >> "$DONE"; FAIL=$((FAIL+1))
      fi
    else
      kind_have=$(kind get clusters 2>/dev/null | grep -cx "$cluster" || true)
      ready=$(kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{c++}END{print c+0}')
      for i in $(seq 1 48); do
        bad=$(kubectl get pods -A --no-headers 2>/dev/null | awk '$4!="Running" && $4!="Completed" && $4!="Succeeded"{c++}END{print c+0}')
        [ "${bad:-0}" = 0 ] && break
        sleep 5
      done
      echo "[PODS] $dir" | tee -a "$LOG"
      kubectl get pods -A 2>/dev/null | rg -v 'kube-system|local-path' | tee -a "$LOG" || true
      issues=$(kubectl get pods -A --no-headers 2>/dev/null | awk '$4!="Running" && $4!="Completed" && $4!="Succeeded"{print $1"/"$2"="$4}' | tr '\n' ' ')
      if [ "$kind_have" = 1 ] && [ "$ready" -ge 1 ] && [ -z "$issues" ]; then
        echo "[RESULT] $dir PASS cluster=$cluster nodes_ready=$ready" | tee -a "$LOG"
        printf '%s\tPASS\tcluster=%s\tnodes=%s\n' "$dir" "$cluster" "$ready" >> "$CSV"
        echo "$dir" >> "$DONE"; PASS=$((PASS+1))
      else
        echo "[RESULT] $dir CHECK_FAILED cluster_have=$kind_have ready=$ready issues=[$issues]" | tee -a "$LOG"
        printf '%s\tCHECK_FAILED\tcluster=%s\tready=%s\tissues=%s\n' "$dir" "$cluster" "$ready" "$issues" >> "$CSV"
        echo "$dir" >> "$DONE"; FAIL=$((FAIL+1))
      fi
    fi
  else
    rc=$?
    echo "[RESULT] $dir START_FAILED rc=$rc" | tee -a "$LOG"
    printf '%s\tSTART_FAILED\trc=%s\n' "$dir" "$rc" >> "$CSV"
    echo "$dir" >> "$DONE"; FAIL=$((FAIL+1))
  fi
  echo "[CLEANUP] $dir teardown ..." | tee -a "$LOG"
  timeout 600 bash scripts/stop-chain.sh "$dir" >> "$LOG" 2>&1 || true
  cleanup_chain_images
  elapsed=$(( $(date +%s) - start_ts ))
  echo "[CLEANUP] $dir done (elapsed ${elapsed}s, clusters: $(kind get clusters 2>/dev/null | tr '\n' ' '))" | tee -a "$LOG"
done <<'EOF'
php-to-mongo|docker|10117,10209|-
xxe-to-es|docker|10114,10207|-
ssrf-to-cross-account|docker|11632|-
caps-to-cluster|k8s|-|cve-chain12-caps-cluster
container-to-admin|k8s|-|cve-chain-k8s-admin
cri-to-etcd|k8s|-|cve-chain-cri-etcd
docker-to-etcd|k8s|-|cve-chain-docker-etcd
externalip-to-secrets|k8s|-|chain24-externalip-to-secrets
hostpath-to-daemonset|k8s|-|cve-chain11-hostpath-node
hostpid-to-node|k8s|-|chain25-hostpid-to-node
ingress-to-etcd|k8s|-|chain23-ingress-to-etcd
kubelet-to-pod-access|k8s|-|cve-chain6-kubelet-pods
pg-sqli-to-node|k8s|-|cve-chain15-pg-node
privilege-to-etcd|k8s|-|cve-chain10-priv-etcd
redis-to-k8s|k8s|-|cve-chain16-redis-k8s
sa-lateral-escape|k8s|-|cve-chain13-sa-escape
wp-lfi-to-cluster|k8s|-|cve-chain17-wp-lfi
EOF

echo "" | tee -a "$LOG"
echo "=== Own chain results: PASS=$PASS FAIL=$FAIL ===" | tee -a "$LOG"
echo "CSV: $CSV"
