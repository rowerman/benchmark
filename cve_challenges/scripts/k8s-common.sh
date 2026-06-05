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
    FLAG="${CVE_FLAG:-flag{${K8S_ID}-default}}"
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

    if [ -d "$FLAG_DIR" ]; then
        rm -rf "$FLAG_DIR"
        echo "  Removed flag directory: $FLAG_DIR"
    fi

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
    echo "    Flag: ${FLAG}"
    if [ -d "$FLAG_DIR" ]; then
        echo "    Flag directory: ${FLAG_DIR}"
    fi
    echo ""
}
