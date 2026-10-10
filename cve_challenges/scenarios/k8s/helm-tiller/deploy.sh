#!/bin/bash
set -euo pipefail
K8S_ID="k8s-10"
CLUSTER_NAME="cve-k8s-10-helm"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_load_images ghcr.io/helm/tiller:v2.17.0 nginx:1.24-alpine

# Create Tiller ServiceAccount and ClusterRoleBinding
kubectl create serviceaccount tiller -n kube-system
kubectl create clusterrolebinding tiller-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:tiller

# Install Helm v2 Tiller (in-cluster)
k8s_apply << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tiller-deploy
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tiller
  template:
    metadata:
      labels:
        app: tiller
    spec:
      serviceAccountName: tiller
      containers:
        - name: tiller
          image: ghcr.io/helm/tiller:v2.17.0
          ports:
            - containerPort: 44134
          command: ["/tiller"]
          env:
            - name: TILLER_NAMESPACE
              value: kube-system
---
apiVersion: v1
kind: Service
metadata:
  name: tiller-deploy
  namespace: kube-system
spec:
  type: NodePort
  selector:
    app: tiller
  ports:
    - port: 44134
      targetPort: 44134
      nodePort: 30434
YAML

k8s_create_k8s_secret "helm-flag" "kube-system"

# Tiller 起来之后入口才可用
k8s_wait_pods_label "app=tiller" "kube-system"

# Tiller 走 NodePort 暴露，入口只给 nodes 读权限（无 pod 操作），
# 避免"进 kube-system 的 pod 直接翻 Secret"这条捷径。
k8s_publish_agent_identity node-reader default
k8s_info
echo "[+] Tiller gRPC: 127.0.0.1:10434（NodePort 30434，无鉴权）"
echo "    连通性自检：ETCDCTL_API 无关；用 helm v2 客户端 --host 127.0.0.1:10434"
