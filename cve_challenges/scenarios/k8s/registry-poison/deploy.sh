#!/bin/bash
set -euo pipefail
K8S_ID="k8s-09"
CLUSTER_NAME="cve-k8s-09-registry"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_host_flag

# Start insecure private registry
docker rm -f k8s-registry 2>/dev/null || echo "  Registry container already removed"
docker run -d --name k8s-registry --network host \
  -e REGISTRY_HTTP_TLS_ENABLED=false \
  registry:2.8.3

sleep 3

# Push a tagged nginx to the private registry
docker tag nginx:1.24-alpine localhost:10500/backdoored-nginx:latest
docker push localhost:10500/backdoored-nginx:latest 2>/dev/null || echo "  Push may have failed, continuing"

# Create KIND cluster
k8s_create_cluster
k8s_wait_ready

# Deploy a pod using the private registry image
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: registry-target
  namespace: default
spec:
  containers:
    - name: app
      image: localhost:10500/backdoored-nginx:latest
      ports:
        - containerPort: 80
YAML

k8s_info
echo "[+] Private registry at localhost:10500 (no TLS)"
echo "[+] Attack: push malicious image → modify Deployment → lateral movement"
