#!/bin/bash
# k8s-common.sh — Shared functions for CVE Benchmark K8s scenarios
#
# Usage (deploy.sh):
#   #!/bin/bash
#   set -euo pipefail
#   K8S_ID="k8s-11"
#   CLUSTER_NAME="cve-k8s-11-privileged"
#   source "$(dirname "$0")/../../scripts/k8s-common.sh"
#
#   k8s_init
#   k8s_create_cluster
#   k8s_load_images alpine:latest
#   k8s_wait_ready
#   k8s_create_host_flag
#   k8s_apply << 'YAML' ...
#
# Usage (teardown.sh):
#   #!/bin/bash
#   set -euo pipefail
#   K8S_ID="k8s-11"
#   CLUSTER_NAME="cve-k8s-11-privileged"
#   source "$(dirname "$0")/../../scripts/k8s-common.sh"
#
#   k8s_init
#   k8s_delete_cluster

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────

KIND_IMAGE="${KIND_IMAGE:-kindest/node:v1.27.3}"
KIND_WAIT_TIMEOUT="${KIND_WAIT_TIMEOUT:-120s}"
KIND_POD_WAIT_TIMEOUT="${KIND_POD_WAIT_TIMEOUT:-120s}"
FLAGS_ROOT="${FLAGS_ROOT:-/home/kianabin/cve-flags}"

# ── Initialization ────────────────────────────────────────────────

k8s_init() {
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    FLAG="${CVE_FLAG:-flag{${K8S_ID}-default\}}"
    FLAG_DIR="${FLAGS_ROOT}/${K8S_ID}"
    export K8S_ID CLUSTER_NAME FLAG FLAG_DIR SCRIPT_DIR
}

# ── Cluster Lifecycle ─────────────────────────────────────────────

k8s_create_cluster() {
    echo "[${K8S_ID}] Creating KIND cluster: ${CLUSTER_NAME}..."

    local config_flag=""
    local config_file="${SCRIPT_DIR}/kind-config.yaml"
    if [ -f "$config_file" ]; then
        config_flag="--config $config_file"
    fi

    # If cluster already exists, delete it first (idempotent)
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        echo "  Cluster ${CLUSTER_NAME} already exists, removing..."
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
        sleep 3
    fi

    kind create cluster --name "$CLUSTER_NAME" $config_flag

    echo "[${K8S_ID}] Cluster created successfully"
}

k8s_delete_cluster() {
    echo "[${K8S_ID}] Tearing down..."

    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster ${CLUSTER_NAME} already removed"

    echo "[+] ${K8S_ID} teardown complete"
}

# ── Readiness ─────────────────────────────────────────────────────

k8s_wait_ready() {
    echo "[${K8S_ID}] Waiting for cluster stabilization..."
    kubectl wait --for=condition=Ready pods --all -n kube-system --timeout="${KIND_WAIT_TIMEOUT}"
    sleep 5
}

k8s_wait_pod() {
    local pod_name="$1"
    local namespace="${2:-default}"
    echo "[${K8S_ID}] Waiting for pod ${namespace}/${pod_name}..."
    kubectl wait --for=condition=Ready "pod/${pod_name}" -n "$namespace" --timeout="${KIND_POD_WAIT_TIMEOUT}"
}

k8s_wait_pods_label() {
    local label="$1"
    local namespace="${2:-default}"
    echo "[${K8S_ID}] Waiting for pods with label ${label} in ${namespace}..."
    kubectl wait --for=condition=Ready pods -l "$label" -n "$namespace" --timeout="${KIND_POD_WAIT_TIMEOUT}"
}

k8s_wait_job() {
    local job_name="$1"
    local namespace="${2:-default}"
    echo "[${K8S_ID}] Waiting for job ${namespace}/${job_name}..."
    kubectl wait --for=condition=Complete "job/${job_name}" -n "$namespace" --timeout=180s
}

# ── NetworkPolicy CNI ────────────────────────────────────────────

k8s_install_calico() {
    echo "[${K8S_ID}] Installing Calico (NetworkPolicy enforcement)..."
    local calico_manifest="/tmp/calico-${K8S_ID}.yaml"
    # The manifest is fetched over the network; retry so a slow mirror does not fail the deploy.
    for attempt in 1 2 3; do
        curl -sL --connect-timeout 10 --max-time 120 \
            https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml \
            -o "$calico_manifest" || true
        if grep -q 'name: calico-node' "$calico_manifest" 2>/dev/null; then
            break
        fi
        echo "  Calico manifest download attempt ${attempt} incomplete, retrying..."
        sleep 5
    done
    if ! grep -q 'name: calico-node' "$calico_manifest" 2>/dev/null; then
        echo "[${K8S_ID}] ERROR: could not download the Calico manifest" >&2
        exit 1
    fi
    kubectl apply -f "$calico_manifest"
    # KIND does not support IPIP; switch Calico to VXLAN
    kubectl -n kube-system set env daemonset/calico-node CALICO_IPV4POOL_IPIP=Never 2>/dev/null || true
    kubectl -n kube-system set env daemonset/calico-node CALICO_IPV4POOL_VXLAN=Always 2>/dev/null || true
    kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s 2>/dev/null || \
        kubectl wait --for=condition=Ready pods -n kube-system -l k8s-app=calico-node --timeout=180s 2>/dev/null || true
    sleep 5
}

# ── etcd helpers ─────────────────────────────────────────────────

# Write a value into the cluster's real etcd under a NON-/registry custom key.
# Such a key is invisible to the Kubernetes API, so it can only be read by
# directly querying etcd - used for chain final flags to prevent shortcuts.
k8s_put_etcd_key() {
    local etcd_key="$1"
    local etcd_value="$2"
    echo "[${K8S_ID}] Writing etcd key ${etcd_key} via hostNetwork helper..."
    docker pull curlimages/curl:latest >/dev/null 2>&1 || true
    kind load docker-image curlimages/curl:latest --name "$CLUSTER_NAME" 2>/dev/null || true
    kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: etcd-key-writer
  namespace: kube-system
spec:
  hostNetwork: true
  restartPolicy: Never
  containers:
    - name: w
      image: curlimages/curl:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          KEY_B64=\$(printf '%s' "$etcd_key" | base64 -w0)
          VAL_B64=\$(printf '%s' "$etcd_value" | base64 -w0)
          curl -sk -X POST https://127.0.0.1:2379/v3/kv/put \
            -H 'Content-Type: application/json' \
            -d "{\"key\":\"\${KEY_B64}\",\"value\":\"\${VAL_B64}\"}"
YAML
    kubectl wait --for=condition=Complete pod/etcd-key-writer -n kube-system --timeout=120s 2>/dev/null || true
    kubectl delete pod etcd-key-writer -n kube-system 2>/dev/null || true
}

# ── Image Management ──────────────────────────────────────────────

k8s_load_images() {
    for img in "$@"; do
        if [ -z "$img" ]; then continue; fi
        echo "[${K8S_ID}] Loading image: $img"
        # Pull first to ensure latest version is available locally
        docker pull "$img" 2>/dev/null || echo "  Note: pull of $img may have failed, will try loading from local cache"
        kind load docker-image "$img" --name "$CLUSTER_NAME" 2>/dev/null || {
            echo "  Warning: Could not load $img into KIND, pod will pull from registry if needed"
        }
    done
    sleep 3
}

k8s_load_image() {
    k8s_load_images "$1"
}


# ── Flag 与 agent 身份 ────────────────────────────────────────────

# 把 flag 写进 KIND 节点容器自身的文件系统（宿主不留副本；挂载目录已废弃）。
k8s_write_node_flag() {
    local node_flag_dir="${1:-/host-flag}"
    local container
    container="$(k8s_get_node_container)"
    if [ -z "$container" ]; then
        echo "[${K8S_ID}] ERROR: control-plane container not found" >&2
        exit 1
    fi
    printf '%s\n' "$FLAG" | docker exec -i "$container" sh -c "umask 022; mkdir -p '$node_flag_dir'; cat > '$node_flag_dir/flag.txt'"
    echo "[${K8S_ID}] Flag placed at ${node_flag_dir}/flag.txt inside the node"
}

# 给 agent 生成最小权限身份：mode=pods-author|pods-executor|node-reader|sa-token|none
#   用法：k8s_publish_agent_identity <mode> <namespace> [<existing-sa>]
k8s_publish_agent_identity() {
    local mode="${1:-none}" namespace="${2:-default}" existing="${3:-}"
    if [ -z "${AGENT_KUBECONFIG:-}" ]; then
        echo "[${K8S_ID}] AGENT_KUBECONFIG not set; skip agent identity" >&2
        return 0
    fi
    mkdir -p "$(dirname "$AGENT_KUBECONFIG")"
    case "$mode" in
        none)
            rm -f "$AGENT_KUBECONFIG"
            echo "[${K8S_ID}] agent 入口：无集群凭据（网络型场景）"
            return 0
            ;;
        node-reader)
            kubectl -n default create serviceaccount agent-entry --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl create clusterrole "${K8S_ID}-agent-node-reader" --verb=get,list --resource=nodes \
                --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl create clusterrolebinding "${K8S_ID}-agent-node-reader" \
                --clusterrole="${K8S_ID}-agent-node-reader" --serviceaccount="default:agent-entry" \
                --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            namespace=default
            existing=agent-entry
            ;;
        pods-author)
            kubectl -n "$namespace" create serviceaccount agent-entry --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create role "${K8S_ID}-agent-pods-author" \
                --verb=get,list,create,delete --resource=pods --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create rolebinding "${K8S_ID}-agent-pods-author" \
                --role="${K8S_ID}-agent-pods-author" --serviceaccount="${namespace}:agent-entry" \
                --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            existing=agent-entry
            ;;
        pods-executor)
            kubectl -n "$namespace" create serviceaccount agent-entry --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create role "${K8S_ID}-agent-pods-executor" \
                --verb=get,list,watch --resource=pods --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create rolebinding "${K8S_ID}-agent-pods-executor" \
                --role="${K8S_ID}-agent-pods-executor" --serviceaccount="${namespace}:agent-entry" \
                --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create role "${K8S_ID}-agent-pods-exec" \
                --verb=create --resource=pods/exec --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create rolebinding "${K8S_ID}-agent-pods-exec" \
                --role="${K8S_ID}-agent-pods-exec" --serviceaccount="${namespace}:agent-entry" \
                --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create role "${K8S_ID}-agent-pod-logs" \
                --verb=get --resource=pods/log --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            kubectl -n "$namespace" create rolebinding "${K8S_ID}-agent-pod-logs" \
                --role="${K8S_ID}-agent-pod-logs" --serviceaccount="${namespace}:agent-entry" \
                --dry-run=client -o yaml | kubectl apply -f - >/dev/null
            existing=agent-entry
            ;;
        sa-token)
            if [ -z "$existing" ]; then
                echo "[${K8S_ID}] ERROR: sa-token mode needs an existing serviceaccount" >&2
                exit 1
            fi
            ;;
        *)
            echo "[${K8S_ID}] ERROR: unknown agent mode $mode" >&2
            exit 1
            ;;
    esac
    if [ "$mode" = "node-reader" ]; then
        namespace=default
    fi
    K8S_AGENT_NAMESPACE="$namespace" K8S_AGENT_SA="$existing" k8s_write_agent_kubeconfig
}

# 用 agent 身份的 token 组装 kubeconfig（复用集群 CA 与 server，不含 admin 凭据）
k8s_write_agent_kubeconfig() {
    local namespace="$K8S_AGENT_NAMESPACE" sa="$K8S_AGENT_SA" token server ca_file
    token="$(kubectl -n "$namespace" create token "$sa" --duration=2h)"
    server="$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.server}')"
    ca_file="$(mktemp)"
    kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$ca_file"
    ( umask 077
      KUBECONFIG="$AGENT_KUBECONFIG" kubectl config set-cluster "${K8S_ID}" --server="$server" \
          --certificate-authority="$ca_file" --embed-certs=true >/dev/null
      KUBECONFIG="$AGENT_KUBECONFIG" kubectl config set-credentials "${K8S_ID}-agent" --token="$token" >/dev/null
      KUBECONFIG="$AGENT_KUBECONFIG" kubectl config set-context "${K8S_ID}-agent" \
          --cluster="${K8S_ID}" --user="${K8S_ID}-agent" --namespace="$namespace" >/dev/null
      KUBECONFIG="$AGENT_KUBECONFIG" kubectl config use-context "${K8S_ID}-agent" >/dev/null )
    rm -f "$ca_file"
    echo "[${K8S_ID}] agent kubeconfig -> ${AGENT_KUBECONFIG}（身份 ${namespace}/${sa}）"
}

# ── Flag Management ───────────────────────────────────────────────

k8s_create_host_flag() {
    mkdir -p "$FLAG_DIR"
    echo "$FLAG" > "${FLAG_DIR}/flag.txt"
    echo "[${K8S_ID}] Flag placed at ${FLAG_DIR}/flag.txt"
}

k8s_create_k8s_secret() {
    local secret_name="$1"
    local namespace="${2:-kube-system}"

    # Idempotent: create if not exists, patch if exists
    kubectl create secret generic "$secret_name" \
        --namespace="$namespace" \
        --from-literal=flag="$FLAG" 2>/dev/null && return 0

    # Already exists — patch it
    kubectl patch secret "$secret_name" -n "$namespace" \
        -p "{\"stringData\":{\"flag\":\"$FLAG\"}}" 2>/dev/null || true
}

k8s_create_k8s_configmap() {
    local cm_name="$1"
    local namespace="${2:-default}"

    kubectl create configmap "$cm_name" \
        --namespace="$namespace" \
        --from-literal=flag="$FLAG" 2>/dev/null && return 0

    # Already exists — patch it
    kubectl patch configmap "$cm_name" -n "$namespace" \
        -p "{\"data\":{\"flag\":\"$FLAG\"}}" 2>/dev/null || true
}

# ── YAML Application ──────────────────────────────────────────────

k8s_apply() {
    kubectl apply -f -
}

# ── Utility ───────────────────────────────────────────────────────

k8s_get_node_container() {
    # Get the Docker container name for the KIND control-plane node
    docker ps --filter "name=${CLUSTER_NAME}-control-plane" --format '{{.Names}}' 2>/dev/null | head -1
}

k8s_get_pod_name() {
    local label_selector="$1"
    local namespace="${2:-default}"
    kubectl get pods -n "$namespace" -l "$label_selector" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

k8s_exec_in_pod() {
    local pod_name="$1"
    local namespace="$2"
    shift 2
    kubectl exec -n "$namespace" "$pod_name" -- "$@" 2>/dev/null || {
        echo "  Warning: kubectl exec into ${namespace}/${pod_name} failed"
        return 1
    }
}

k8s_info() {
    echo ""
    echo "[+] ${K8S_ID} Ready"
    echo "    Cluster: ${CLUSTER_NAME}"
    if [ "${CVE_SHOW_FLAGS:-0}" = "1" ]; then
        echo "    Flag: ${FLAG}"
    else
        echo "    Flag: <hidden>"
    fi
    if [ -d "$FLAG_DIR" ]; then
        echo "    Flag directory: ${FLAG_DIR}"
    fi
    echo ""
}
