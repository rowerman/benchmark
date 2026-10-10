#!/bin/bash
set -euo pipefail
K8S_ID="k8s-17"
CLUSTER_NAME="cve-k8s-17-docker-sock"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_load_images alpine:latest

# 攻击者与受害者必须落在同一个节点上，socket 才能看到目标容器
NODE_NAME=$(kubectl get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].metadata.name}')

# 受害者工作负载：flag 只在这个容器自己的文件系统里
k8s_apply << YAML
apiVersion: v1
kind: Pod
metadata:
  name: victim-app
  namespace: default
spec:
  nodeName: ${NODE_NAME}
  containers:
    - name: app
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML
k8s_wait_pod "victim-app"
printf '%s\n' "$FLAG" | kubectl exec -i victim-app -- sh -c 'cat > /flag.txt && chmod 600 /flag.txt'

# 攻击者 pod：挂进节点的 containerd socket 与 crictl，可以操作同节点的其它容器
k8s_apply << YAML
apiVersion: v1
kind: Pod
metadata:
  name: docker-escape-pod
  namespace: default
spec:
  nodeName: ${NODE_NAME}
  # crictl 的 exec 走节点上的 streaming server（127.0.0.1），所以这个 pod 与节点共享网络命名空间
  hostNetwork: true
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: runtime-sock
          mountPath: /run/containerd/containerd.sock
        - name: crictl
          mountPath: /usr/local/bin/crictl
  volumes:
    - name: runtime-sock
      hostPath:
        path: /run/containerd/containerd.sock
        type: Socket
    - name: crictl
      hostPath:
        path: /usr/local/bin/crictl
YAML

k8s_wait_pod "docker-escape-pod"

k8s_publish_agent_identity exec-only default docker-escape-pod
k8s_info
