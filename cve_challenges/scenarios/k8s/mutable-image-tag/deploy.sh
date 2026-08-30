#!/bin/bash
# K8S-15: Mutable Image Tag Supply Chain Attack
set -euo pipefail
K8S_ID="k8s-15"
CLUSTER_NAME="cve-k8s-15-image-tag"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

k8s_init

k8s_create_cluster
k8s_wait_ready
k8s_load_images nginx:1.24-alpine

# Start local registry on the kind network (published on host port 10501)
docker compose -f "$SCRIPT_DIR/registry-compose.yml" up -d 2>/dev/null || true

# Seed the mirror with the benign image (mirror rewrites docker.io/library/nginx)
for i in $(seq 1 20); do
  if docker push localhost:10501/library/nginx:1.24-alpine 2>/dev/null; then
    break
  fi
  docker tag nginx:1.24-alpine localhost:10501/library/nginx:1.24-alpine 2>/dev/null || true
  sleep 2
done

# Deploy with mutable tag + Always pull
k8s_apply << YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
    spec:
      serviceAccountName: default
      containers:
        - name: app
          image: nginx:1.24-alpine
          imagePullPolicy: Always
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: configmap-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default-configmap-reader
  namespace: default
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: Role
  name: configmap-reader
  apiGroup: rbac.authorization.k8s.io
YAML

k8s_create_k8s_configmap "app-config"

k8s_info
echo "    Registry: localhost:10501 (no TLS, on kind network as 'registry')"
echo "[+] Attack: push malicious image with same tag → trigger redeploy → payload reads configmap → get flag"
