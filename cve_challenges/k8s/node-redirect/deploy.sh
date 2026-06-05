#!/bin/bash
set -euo pipefail
K8S_ID="k8s-26"
CLUSTER_NAME="cve-k8s-26-node-redirect"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-26] CVE-2020-8559 Compromised Node API Server Redirect"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Pre-loading container images into KIND..."
k8s_load_images alpine:latest nginx:1.24-alpine

echo "[*] Setting up victim pod with flag..."
k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
---
# Victim pod containing the flag
apiVersion: v1
kind: Pod
metadata:
  name: victim-pod
  namespace: secure-ns
spec:
  containers:
    - name: app
      image: nginx:1.24-alpine
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          echo 'FLAG_PLACEHOLDER' > /flag.txt
          nginx -g 'daemon off;'
      ports:
        - containerPort: 80
---
# Compromised node simulation - attacker pod with node-like access
apiVersion: v1
kind: ServiceAccount
metadata:
  name: node-operator
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-operator
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "patch", "update"]
  - apiGroups: [""]
    resources: ["nodes/proxy"]
    verbs: ["get", "create"]
  - apiGroups: [""]
    resources: ["pods/exec", "pods/attach"]
    verbs: ["create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: node-operator
subjects:
  - kind: ServiceAccount
    name: node-operator
    namespace: default
roleRef:
  kind: ClusterRole
  name: node-operator
  apiGroup: rbac.authorization.k8s.io
---
# Attacker pod simulating a compromised node
apiVersion: v1
kind: Pod
metadata:
  name: compromised-node
  namespace: default
spec:
  serviceAccountName: node-operator
  hostNetwork: true
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        runAsUser: 0
YAML

echo "[*] Injecting flag into victim pod..."
k8s_wait_pod "victim-pod" "secure-ns"
k8s_wait_pod "compromised-node" "default"
sleep 5

kubectl exec -n secure-ns victim-pod -- sh -c "echo '$FLAG' > /flag.txt" 2>/dev/null || true

NODE_NAME=$(kubectl get node -o jsonpath='{.items[0].metadata.name}')
k8s_info
echo "    Victim pod: victim-pod in secure-ns namespace"
echo "    Node name: $NODE_NAME"
echo "    Flag in victim pod: /flag.txt"
echo ""
echo "    Exploitation steps:"
echo "    1. The attacker pod has node-like RBAC (nodes/proxy, pods/exec)"
echo "    2. CVE-2020-8559: API server follows redirects on upgrade requests"
echo "    3. From the compromised-node pod, use the node proxy endpoint:"
echo "       TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "       curl -k -H \"Authorization: Bearer \$TOKEN\" \\"
echo "         https://kubernetes.default.svc/api/v1/nodes/${NODE_NAME}/proxy/pods"
echo "    4. Exploit the redirect to exec into victim-pod:"
echo "       kubectl exec -n secure-ns victim-pod -- cat /flag.txt"
echo ""
echo "    Note: This scenario simulates a compromised node that can redirect"
echo "    API server requests to access other pods."