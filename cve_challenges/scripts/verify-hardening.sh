#!/bin/bash
# 逐场景实际部署验收：start-scenario.sh → 负向门禁 → 参考利用 → stop-scenario.sh。
#
# 用法：verify-hardening.sh [cloud|k8s|all] [--only id,id] [--keep]
#   --keep  场景跑完后不清理（排障用）
# 结果写进 <run-root>/results.tsv，并逐行打印。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SCOPE="all"
ONLY=""
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        cloud|k8s|all) SCOPE="$1" ;;
        --only) ONLY="${2:-}"; shift ;;
        --keep) KEEP=1 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

RUN_ROOT="${HARDENING_RUN_ROOT:-/tmp/hv}"
mkdir -p "$RUN_ROOT"
RESULTS="${RUN_ROOT}/results.tsv"
[ -f "$RESULTS" ] || printf 'scenario\tstart\tgate\texploit\tresult\n' > "$RESULTS"

PLAN="${RUN_ROOT}/plan.tsv"
python3 scripts/hardening-plan.py "$SCOPE" "$ONLY" > "$PLAN"
echo "[verify] 待验收 $(wc -l < "$PLAN") 个场景，结果写入 ${RESULTS}"

# 计划表从 fd 3 读，避免子进程（kubectl/docker 等）吃掉循环的 stdin
exec 3< "$PLAN"
while IFS=$'\t' read -r sid kind path <&3; do
    [ -n "$sid" ] || continue
    run_dir="${RUN_ROOT}/${sid}"
    rm -rf "$run_dir"
    mkdir -p "$run_dir"
    export KUBECONFIG="${run_dir}/admin-kubeconfig"
    export AGENT_KUBECONFIG="${run_dir}/agent-kubeconfig"
    export FLAGS_ROOT="${run_dir}/flags"

    # 本轮 flag 由验收侧生成并显式传入；参考利用按同一值判定。
    count="$(python3 scripts/flag_contract.py scenario "$sid")"
    expected="flag{${sid}-$(python3 -c 'import secrets;print(secrets.token_hex(8))')}"
    export CVE_FLAG="$expected"
    for i in $(seq 2 "$count"); do
        export "CVE_FLAG${i}=flag{${sid}-step${i}-$(python3 -c 'import secrets;print(secrets.token_hex(8))')}"
    done
    export CVE_FLAG1="$expected"

    echo "[verify] ===== ${sid} (${kind}) ====="
    start_rc=1; gate_rc=1; exploit_rc=1
    bash scripts/start-scenario.sh "$sid" >"${run_dir}/start.log" 2>&1 </dev/null && start_rc=0
    if [ "$start_rc" != "0" ]; then
        echo "[verify] ${sid} 启动失败，见 ${run_dir}/start.log"
    else
        cluster=""
        agent_kc="$AGENT_KUBECONFIG"
        [ -f "$agent_kc" ] || agent_kc=none
        if [ "$kind" = "k8s" ]; then
            cluster="$(kind get clusters 2>/dev/null | grep -i "$sid" | head -1)"
            bash scripts/validate-k8s-gate.sh "$sid" "$agent_kc" "$expected" "$cluster" \
                >"${run_dir}/gate.log" 2>&1 && gate_rc=0
            bash tests/k8s/run.sh "$sid" "$agent_kc" "$expected" "$cluster" \
                >"${run_dir}/exploit.log" 2>&1 && exploit_rc=0
        else
            python3 scripts/validate-cloud-gate.py "$sid" "$expected" \
                >"${run_dir}/gate.log" 2>&1 && gate_rc=0
            python3 tests/cloud/run.py "$sid" "$expected" \
                >"${run_dir}/exploit.log" 2>&1 && exploit_rc=0
        fi
        tail -3 "${run_dir}/gate.log" 2>/dev/null | sed 's/^/    gate| /'
        tail -2 "${run_dir}/exploit.log" 2>/dev/null | sed 's/^/    exploit| /'
        [ "$KEEP" = "1" ] || bash scripts/stop-scenario.sh "$sid" >"${run_dir}/stop.log" 2>&1
    fi

    if [ "$start_rc" = 0 ] && [ "$gate_rc" = 0 ] && [ "$exploit_rc" = 0 ]; then
        result=OK
    else
        result="FAIL(start=${start_rc},gate=${gate_rc},exploit=${exploit_rc})"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$sid" "$start_rc" "$gate_rc" "$exploit_rc" "$result" >> "$RESULTS"
    echo "[verify] ${sid} -> ${result}"
done < "$PLAN"

echo "[verify] 汇总："
awk -F'\t' 'NR>1{print "  "$1" -> "$5}' "$RESULTS" | tail -n 80
