#!/bin/bash
set -euo pipefail
K8S_ID="k8s-23"
CLUSTER_NAME="cve-k8s-23-seccomp-bypass"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-23] hostPID Process Information Disclosure"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_write_node_flag /host-flag

echo "[*] Pre-loading container images into KIND..."
k8s_load_images alpine:latest

echo "[*] Placing flag in host process cmdline..."
# Start a background process on the KIND node with the flag in its arguments
# This simulates a real-world scenario: credentials/tokens leaked via cmdline
# in monitoring scripts, cron jobs, or daemon arguments
NODE_CONTAINER=$(k8s_get_node_container)
if [ -n "$NODE_CONTAINER" ]; then
  docker exec -d "$NODE_CONTAINER" sh -c \
    "echo 'CREDENTIAL_MONITOR: detected flag=${FLAG}' > /dev/null; while true; do sleep 99999; done" 2>/dev/null || \
    echo "    Warning: Could not start flag process on KIND node"
else
  echo "    Warning: Could not find KIND node container"
fi

echo "[*] Deploying pod with hostPID..."
k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: monitor-ns
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: monitor-sa
  namespace: monitor-ns
---
apiVersion: v1
kind: Pod
metadata:
  name: monitor-pod
  namespace: monitor-ns
spec:
  serviceAccountName: monitor-sa
  hostPID: true
  containers:
    - name: monitor
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        runAsUser: 0
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
  restartPolicy: Always
YAML

echo "[*] Waiting for pod to be ready..."
k8s_wait_pod "monitor-pod" "monitor-ns"

k8s_publish_agent_identity exec-only monitor-ns monitor-pod
k8s_info
