#!/bin/bash
# 负向门禁：证明"不用打漏洞也能拿 flag"的通路已被堵住。
#
# 用法：validate-k8s-gate.sh <scenario-id> <agent-kubeconfig> <expected-flag> [<cluster-name>]
#   agent-kubeconfig 传 none 表示该场景不下发集群凭据。
# 退出码 0 = 全部门禁通过。
set -uo pipefail

SCENARIO_ID="${1:?usage: validate-k8s-gate.sh <scenario-id> <agent-kubeconfig|none> <flag> [cluster-name]}"
AGENT_KC="${2:-none}"
EXPECTED="${3:?expected flag required}"
CLUSTER_NAME="${4:-}"

FAILURES=0

fail() { echo "  [FAIL] $1"; FAILURES=$((FAILURES + 1)); }
pass() { echo "  [ok]   $1"; }

# admin 侧 kubectl（集群当前上下文）
K() { kubectl "$@"; }

if [ -z "$CLUSTER_NAME" ]; then
    CLUSTER_NAME="$(kind get clusters 2>/dev/null | head -1)"
fi

echo "[gate] ${SCENARIO_ID}"

# ── 1. agent 身份的能力面 ────────────────────────────────────────────────
if [ "$AGENT_KC" != "none" ] && [ -f "$AGENT_KC" ]; then
    A=(kubectl --kubeconfig "$AGENT_KC")
    NS="$("${A[@]}" config view --minify -o jsonpath='{.contexts[0].context.namespace}' 2>/dev/null)"
    [ -n "$NS" ] || NS=default
    echo "  agent 身份能力面（namespace=${NS}）:"
    "${A[@]}" auth can-i --list 2>/dev/null | sed 's/^/    /' || true

    # 1a. 特权 + hostPath:/ 的 pod 必须建不起来（捷径通道）
    if "${A[@]}" run gate-privileged --image=alpine:latest -n "$NS" --restart=Never \
        --overrides='{"spec":{"containers":[{"name":"gate-privileged","image":"alpine:latest","command":["true"],"securityContext":{"privileged":true},"volumeMounts":[{"name":"host","mountPath":"/host"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}' \
        >/tmp/gate-privileged.out 2>&1; then
        fail "agent 身份可以创建 privileged + hostPath:/ 的 pod（捷径通道仍通）"
        "${A[@]}" delete pod gate-privileged -n "$NS" --force --grace-period=0 >/dev/null 2>&1 || true
    else
        pass "privileged + hostPath:/ 的 pod 被拒绝：$(tail -1 /tmp/gate-privileged.out)"
    fi

    # 1b. agent 读不到 flag（Secret / ConfigMap / pod spec）
    for resource in secrets configmaps; do
        if "${A[@]}" get "$resource" -A -o json >/tmp/gate-read.json 2>/dev/null; then
            if grep -q "$EXPECTED" /tmp/gate-read.json; then
                fail "agent 身份可直接读到 flag（${resource}）"
            else
                pass "agent 身份读不到 flag（${resource}）"
            fi
        else
            pass "agent 身份无权列 ${resource}（合理）"
        fi
    done
    rm -f /tmp/gate-read.json /tmp/gate-privileged.out
else
    # 无凭据场景：API 必须不可匿名访问
    if kubectl --kubeconfig /dev/null --server="$(kind get kubeconfig --name "$CLUSTER_NAME" 2>/dev/null | sed -n 's/^ *server: //p' | head -1)" \
        get secrets -A --request-timeout=5s >/dev/null 2>&1; then
        fail "无凭据也能访问 API（匿名可达）"
    else
        pass "无凭据下 API 不可达"
    fi
fi

# ── 2. 集群内不得出现明文 flag（pod spec / configmap / 日志） ───────────────
if K get pods -A -o yaml >/tmp/gate-pods.yaml 2>/dev/null; then
    if grep -q "$EXPECTED" /tmp/gate-pods.yaml; then
        fail "pod spec 中出现明文 flag（env/args 泄漏）"
    else
        pass "pod spec 中无明文 flag"
    fi
else
    pass "跳过 pod spec 扫描（无可读集群上下文）"
fi
rm -f /tmp/gate-pods.yaml

# ConfigMap/Secret 都由 RBAC 保护，是否泄漏由上面"入口身份能不能读到"的检查判定；
# 这里只拦"不需要身份就能读到"的位置：pod spec（env/args/日志）。
LEAKED_LOG=""
for pod in $(K get pods -A --no-headers -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name' 2>/dev/null); do
    ns="${pod%% *}"; name="${pod##* }"
    if K logs -n "$ns" "$name" --all-containers --tail=200 2>/dev/null | grep -q "$EXPECTED"; then
        LEAKED_LOG="${ns}/${name}"
        break
    fi
done
if [ -n "$LEAKED_LOG" ]; then
    fail "pod 日志中出现明文 flag：${LEAKED_LOG}"
else
    pass "pod 日志中无明文 flag"
fi

# ── 3. 节点上的 flag 只能被节点身份读到 ───────────────────────────────────
if [ -n "$CLUSTER_NAME" ]; then
    NODE_CTR="$(docker ps --filter "name=${CLUSTER_NAME}-control-plane" --format '{{.Names}}' 2>/dev/null | head -1)"
    if [ -n "$NODE_CTR" ]; then
        found_any=0
        for dir in /host-flag /host-flags; do
            if docker exec "$NODE_CTR" test -f "$dir/flag.txt" 2>/dev/null; then
                found_any=1
                mode="$(docker exec "$NODE_CTR" stat -c '%a' "$dir/flag.txt" 2>/dev/null)"
                if [ "$mode" = "600" ]; then
                    pass "节点 flag ${dir}/flag.txt 权限为 600"
                else
                    fail "节点 flag ${dir}/flag.txt 权限为 ${mode}（应为 600）"
                fi
            fi
        done
        [ "$found_any" = "1" ] || pass "节点上无 flag 文件（flag 走集群内终端）"
    fi
    # 场景容器 env 里不得有明文 flag
    if docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -q "$EXPECTED"; then
        fail "容器环境变量中出现明文 flag"
    else
        pass "容器环境变量中无明文 flag"
    fi
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "[gate] ${SCENARIO_ID} PASS"
    exit 0
fi
echo "[gate] ${SCENARIO_ID} FAIL（${FAILURES} 项）"
exit 1
