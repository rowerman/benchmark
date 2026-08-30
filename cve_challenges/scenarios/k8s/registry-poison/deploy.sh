#!/bin/bash
set -euo pipefail
K8S_ID="k8s-09"
CLUSTER_NAME="cve-k8s-09-registry"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

# Start insecure private registry on the kind network, published on host port 10500 (10000-14000)
echo "[*] Starting insecure private registry on port 10500..."
docker rm -f k8s-registry 2>/dev/null || echo "  Registry container already removed"
docker run -d --name k8s-registry --network kind \
  -p 10500:5000 \
  -e REGISTRY_HTTP_TLS_ENABLED=false \
  registry:2.8.3

# Wait for the registry and seed it with a benign image
for i in $(seq 1 20); do
  if docker push localhost:10500/backdoored-nginx:latest 2>/dev/null; then
    break
  fi
  docker tag nginx:1.24-alpine localhost:10500/backdoored-nginx:latest 2>/dev/null || true
  sleep 2
done

# Flag secret readable by the workload SA (only via the poisoned image payload)
k8s_create_k8s_secret "registry-flag" "default"
k8s_apply << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: registry-secret-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: registry-secret-reader
  namespace: default
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: Role
  name: registry-secret-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry-target
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: registry-target
  template:
    metadata:
      labels:
        app: registry-target
    spec:
      serviceAccountName: default
      containers:
        - name: app
          image: k8s-registry:5000/backdoored-nginx:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 80
YAML

k8s_wait_pods_label "app=registry-target" "default"

k8s_info
echo "    Registry: localhost:10500 (no TLS, on kind network as 'k8s-registry')"
echo "    Flag Secret: registry-flag in default namespace (readable only by the workload SA)"
echo "[+] Attack: push malicious image to localhost:10500/backdoored-nginx:latest → kubectl delete pod → payload reads secret → cat /tmp/flag.txt"
