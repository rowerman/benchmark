#!/bin/bash
# 参考利用脚手架：按场景预期路径走一遍，必须能拿到本轮 flag。
#
# 用法：run.sh <scenario-id> <agent-kubeconfig|none> <expected-flag> <cluster-name>
# 每个场景在 tests/k8s/exploits/<id>.sh 里实现 exploit()，把拿到的 flag 写进变量
# CAPTURED。退出码 0 表示拿到的是预期 flag；2 表示拿到别的 flag；1 表示没拿到。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCENARIO_ID="${1:?usage: run.sh <scenario-id> <agent-kubeconfig|none> <expected-flag> <cluster-name>}"
AGENT_KC="${2:-none}"
EXPECTED="${3:?expected flag required}"
CLUSTER_NAME="${4:-}"
export AGENT_KC EXPECTED CLUSTER_NAME

CASE_FILE="${ROOT}/tests/k8s/exploits/${SCENARIO_ID}.sh"
if [ ! -f "$CASE_FILE" ]; then
    echo "[exploit] ${SCENARIO_ID}: 没有参考利用脚本"
    exit 1
fi

# shellcheck disable=SC1090
[ -f "${ROOT}/tests/k8s/exploits/_common.sh" ] && source "${ROOT}/tests/k8s/exploits/_common.sh"
# shellcheck disable=SC1090
source "$CASE_FILE"

CAPTURED=""
if ! declare -f exploit >/dev/null; then
    echo "[exploit] ${SCENARIO_ID}: exploits 文件未定义 exploit()"
    exit 1
fi

exploit

echo "[exploit] ${SCENARIO_ID} captured=${CAPTURED:-<none>}"
if [ -z "$CAPTURED" ]; then
    echo "[exploit] ${SCENARIO_ID} FAIL（未拿到 flag）"
    exit 1
fi
if [ "$CAPTURED" != "$EXPECTED" ]; then
    echo "[exploit] ${SCENARIO_ID} FAIL（拿到的是非本轮 flag）"
    exit 2
fi
echo "[exploit] ${SCENARIO_ID} PASS"
