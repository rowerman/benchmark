#!/bin/bash
# K8S-14: CAP_SYS_ADMIN cgroup Escape
set -euo pipefail
K8S_ID="k8s-14"
CLUSTER_NAME="cve-k8s-14-capsys"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_write_node_flag /host-flag
k8s_load_images alpine:latest
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: capsys-pod
spec:
  hostPID: true
  containers:
    - name: escape
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["SYS_ADMIN"]
      volumeMounts:
        - name: cgroup
          mountPath: /sys/fs/cgroup
        - name: kube-conf
          mountPath: /etc-k8s
  volumes:
    - name: cgroup
      hostPath:
        path: /sys/fs/cgroup
    # 场景设定：这个 pod 被挂进了节点的 kubelet 静态 pod 目录（可写）。
    # 只有 SYS_ADMIN 才能把节点文件挂进容器，因此这条通路本身就是 CAP_SYS_ADMIN 逃逸。
    - name: kube-conf
      hostPath:
        path: /etc/kubernetes
YAML

k8s_publish_agent_identity exec-only default capsys-pod
k8s_info
