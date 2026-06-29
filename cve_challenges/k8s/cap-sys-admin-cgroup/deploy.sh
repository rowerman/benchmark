#!/bin/bash
# K8S-14: CAP_SYS_ADMIN cgroup Escape
set -euo pipefail
K8S_ID="k8s-14"
CLUSTER_NAME="cve-k8s-14-capsys"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_load_images alpine:latest
k8s_wait_ready
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: capsys-pod
spec:
  containers:
    - name: escape
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["SYS_ADMIN"]
      volumeMounts:
        - name: host-flag
          mountPath: /host-flag
        - name: cgroup
          mountPath: /sys/fs/cgroup
  volumes:
    - name: host-flag
      hostPath:
        path: /host-flag
        type: Directory
    - name: cgroup
      hostPath:
        path: /sys/fs/cgroup
YAML

k8s_info
echo "[+] Attack: mount cgroup → write release_agent → trigger escape → cat /host-flag/flag.txt"
