#!/bin/bash
set -euo pipefail
echo "[Chain 6] Kubelet → RBAC → etcd — 3 steps, K8s"
echo "[*] Creating KIND cluster with Kubelet anonymous + etcd exposed..."

# Pre-create flag dirs
mkdir -p /home/kianabin/cve-flags/chain6

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraPortMappings:
      - containerPort: 2379
        hostPort: 11379
        protocol: TCP
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            anonymous-auth: "true"
            authorization-mode: "AlwaysAllow"
KINDCFG

kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Step 1 flag: accessible via kubelet pods endpoint
kubectl create configmap chain6-step1 --from-literal=flag="flag{chain6-step1-kubelet}" -n kube-system
kubectl apply -f - << 'POD'
apiVersion: v1
kind: Pod
metadata:
  name: chain6-target
  namespace: default
spec:
  containers:
    - name: nginx
      image: nginx:1.24-alpine
POD

# Step 2 flag: RBAC secret
kubectl create sa chain6-sa -n default
kubectl apply -f - << 'RBAC'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chain6-secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chain6-binding
subjects:
  - kind: ServiceAccount
    name: chain6-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: chain6-secrets-reader
  apiGroup: rbac.authorization.k8s.io
RBAC

kubectl create secret generic chain6-step2 --from-literal=flag="flag{chain6-step2-rbac}" -n kube-system
kubectl create secret generic chain6-step3 --from-literal=flag="flag{chain6-step3-etcd-final}" -n kube-system

echo ""
echo "[Chain 6] Ready"
echo "  Step 1: curl -k https://NODE_IP:10250/runningpods/ → exec → flag{chain6-step1-kubelet}"
echo "  Step 2: kubectl get secret chain6-step2 -n kube-system → flag{chain6-step2-rbac}"
echo "  Step 3: etcdctl get /registry/secrets/kube-system/chain6-step3 → FINAL"
