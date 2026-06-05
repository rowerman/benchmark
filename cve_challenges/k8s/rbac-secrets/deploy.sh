#!/bin/bash
set -euo pipefail
K8S_ID="k8s-06"
CLUSTER_NAME="cve-k8s-06-rbac"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

# Flag in kube-system as a secret
k8s_create_k8s_secret "flag-secret" "kube-system"

# Create attacker ServiceAccount
kubectl create serviceaccount attacker-sa --namespace=default 2>/dev/null || true

# Create overly-permissive RBAC (read all secrets in all namespaces)
k8s_apply << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: attacker-secrets-binding
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: default
roleRef:
  kind: ClusterRole
  name: secrets-reader
  apiGroup: rbac.authorization.k8s.io
YAML

# Create attacker pod with kubectl
k8s_apply << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: kubectl
      image: bitnami/kubectl:1.27
      command: ["sleep", "3600"]
YAML

k8s_wait_pod "attacker-pod" "default"

k8s_info
echo "[+] To exploit: kubectl exec -it attacker-pod -- /bin/bash"
echo "[+] Then: kubectl get secret flag-secret -n kube-system -o jsonpath='{.data.flag}' | base64 -d"
