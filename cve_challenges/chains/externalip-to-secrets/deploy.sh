#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain24-externalip-to-secrets"

echo "[Chain-24] ExternalIP Hijack to Secret Theft"
echo "[*] Deploying infrastructure..."

kind create cluster --name "$CLUSTER_NAME" --config - << 'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
YAML

kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Set up namespaces
kubectl create ns secure-ns 2>/dev/null || true
kubectl create ns ns-alpha 2>/dev/null || true
kubectl create ns ns-beta 2>/dev/null || true
kubectl create ns attack-ns 2>/dev/null || true

# Step 1: Target service with flag-bearing traffic
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Service
metadata:
  name: internal-api
  namespace: secure-ns
spec:
  selector:
    app: internal-api
  ports:
    - port: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: internal-api
  namespace: secure-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: internal-api
  template:
    metadata:
      labels:
        app: internal-api
    spec:
      containers:
        - name: api
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              echo 'flag{chain24-step1-hijack}' > /tmp/step1_flag.txt
              cat > /etc/nginx/conf.d/default.conf << 'NGX'
              server { listen 8080; location / { return 200 "ok\n"; } }
              NGX
              while true; do
                curl -s -H "X-Flag: flag{chain24-step2-capture}" \
                  -H "X-Cred: k8s-token-hint" \
                  -d '{"svc":"internal-api"}' \
                  http://localhost:8080/data 2>/dev/null || true
                sleep 30
              done &
              nginx -g 'daemon off;'
          ports:
            - containerPort: 8080
YAML

# Step 2: Attacker pod
kubectl create sa attacker-sa -n attack-ns 2>/dev/null || true
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: svc-creator
  namespace: attack-ns
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["create", "get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: svc-creator
  namespace: attack-ns
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attack-ns
roleRef:
  kind: Role
  name: svc-creator
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: attack-ns
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: shell
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

# Step 3: Cross-ns SA token (from K8S-13 pattern)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secret-reader-sa
  namespace: ns-beta
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: secret-reader
subjects:
  - kind: ServiceAccount
    name: secret-reader-sa
    namespace: ns-beta
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
---
# Leak the token into ns-alpha
apiVersion: v1
kind: Secret
metadata:
  name: leaked-sa-token
  namespace: ns-alpha
  annotations:
    kubernetes.io/service-account.name: secret-reader-sa
type: kubernetes.io/service-account-token
YAML

# Step 3 flag
kubectl create secret generic flag-secret -n ns-beta \
  --from-literal=flag='flag{chain24-step3-crossns}' 2>/dev/null || true

# Step 4 flag
kubectl create secret generic flag-secret -n kube-system \
  --from-literal=flag='flag{chain24-step4-secrets-final}' 2>/dev/null || true

echo ""
echo "[+] Chain-24 Ready"
echo "    Cluster: $CLUSTER_NAME"
echo "    Flags at each stage: intercept → credentials → cross-ns → kube-system secrets"