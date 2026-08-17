#!/bin/bash
set -euo pipefail
K8S_ID="k8s-18"
CLUSTER_NAME="cve-k8s-18-sa-admin"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

# Create namespace for the privileged service account
kubectl create namespace ns-admin 2>/dev/null || true
# Create namespace for the attacker
kubectl create namespace ns-ops 2>/dev/null || true

# Create ServiceAccount with cluster-admin privileges
kubectl create serviceaccount cluster-admin-sa -n ns-admin 2>/dev/null || true
kubectl create clusterrolebinding ca-full-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=ns-admin:cluster-admin-sa 2>/dev/null || true

# Store the flag as a Secret in a different namespace (needs cluster-admin to read)
k8s_create_k8s_secret "flag-secret" "ns-admin"

# Generate a token for the cluster-admin SA and leak it to the attacker namespace
TOKEN=$(kubectl create token cluster-admin-sa -n ns-admin --duration=24h 2>/dev/null || echo "token-unavailable")
kubectl create secret generic leaked-admin-token \
  --namespace=ns-ops \
  --from-literal=token="$TOKEN" 2>/dev/null || \
  kubectl create secret generic leaked-admin-token \
  --namespace=ns-ops \
  --from-literal=token="$TOKEN" --dry-run=client -o yaml | kubectl apply -f -

# Deploy attacker pod in ns-ops with the leaked token mounted
k8s_apply << YAML
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: ns-ops
spec:
  containers:
    - name: kubectl
      image: bitnami/kubectl:1.27
      command: ["sleep", "3600"]
      volumeMounts:
        - name: leaked-token
          mountPath: /var/run/secrets/leaked
          readOnly: true
  volumes:
    - name: leaked-token
      secret:
        secretName: leaked-admin-token
YAML

# Also create a limited pod for the initial foothold
k8s_apply << YAML
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
  namespace: ns-ops
spec:
  containers:
    - name: alpine
      image: alpine:latest
      command: ["sleep", "3600"]
YAML

k8s_wait_pod "attacker-pod" "ns-ops"
k8s_wait_pod "init-pod" "ns-ops"

k8s_info
echo "    Exploitation steps:"
echo "    1. kubectl exec -it init-pod -n ns-ops -- sh"
echo "    2. Enumerate available secrets in ns-ops namespace"
echo "    3. Extract leaked token from leaked-admin-token secret"
echo "    4. kubectl --token=\$TOKEN --server=https://kubernetes.default.svc get secret flag-secret -n ns-admin"
echo "    5. Decode the flag: kubectl ... -o jsonpath='{.data.flag}' | base64 -d"
