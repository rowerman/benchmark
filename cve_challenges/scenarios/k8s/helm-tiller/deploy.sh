#!/bin/bash
set -euo pipefail
K8S_ID="k8s-10"
CLUSTER_NAME="cve-k8s-10-helm"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

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
  selector:
    app: tiller
  ports:
    - port: 44134
      targetPort: 44134
YAML

k8s_create_k8s_secret "helm-flag" "kube-system"

k8s_info
echo "[+] Tiller at tiller-deploy.kube-system:44134 (no auth)"
echo "[+] Attack: helm --host tiller-deploy.kube-system:44134 ls --all"
