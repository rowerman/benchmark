#!/bin/bash
set -euo pipefail
K8S_ID="k8s-21"
CLUSTER_NAME="cve-k8s-21-ingress-snippet"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-21] CVE-2021-25742 ingress-nginx Lua Snippet Secret Extraction"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Pre-loading container images into KIND..."
k8s_load_images nginx:1.24-alpine registry.k8s.io/ingress-nginx/controller:v1.10.4 registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.4.3

echo "[*] Deploying ingress-nginx with snippet annotations enabled..."
# Deploy ingress-nginx with allow-snippet-annotations=true
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.4/deploy/static/provider/kind/deploy.yaml

echo "[*] Waiting for ingress-nginx controller and certgen jobs..."
k8s_wait_pods_label "app.kubernetes.io/component=controller" "ingress-nginx"
k8s_wait_job "ingress-nginx-admission-create" "ingress-nginx"
k8s_wait_job "ingress-nginx-admission-patch" "ingress-nginx"
sleep 10

# Enable snippet annotations in the ConfigMap
kubectl patch configmap ingress-nginx-controller -n ingress-nginx -p '{"data":{"allow-snippet-annotations":"true"}}' 2>/dev/null || true

# Grant ingress-nginx ServiceAccount permission to read Secrets
k8s_apply << 'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingress-nginx-secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ingress-nginx-secret-reader
subjects:
  - kind: ServiceAccount
    name: ingress-nginx
    namespace: ingress-nginx
roleRef:
  kind: ClusterRole
  name: ingress-nginx-secret-reader
  apiGroup: rbac.authorization.k8s.io
YAML

echo "[*] Creating flag Secret and backend..."
k8s_create_k8s_secret "flag-secret" "default"

k8s_apply << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snippet-backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: snippet-backend
  template:
    metadata:
      labels:
        app: snippet-backend
    spec:
      containers:
        - name: backend
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: snippet-backend
spec:
  selector:
    app: snippet-backend
  ports:
    - port: 80
      targetPort: 80
  type: NodePort
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: snippet-app
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      # Attacker can inject arbitrary Lua code here via Ingress modification
      # Vulnerable snippet annotations are enabled
spec:
  ingressClassName: nginx
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: snippet-backend
                port:
                  number: 80
YAML

k8s_wait_pods_label "app.kubernetes.io/component=controller" "ingress-nginx"
sleep 10

k8s_info
echo "    Ingress Port: localhost:10480"
echo "    Flag Secret: flag-secret in default namespace"
echo ""
echo "    Exploitation steps:"
echo "    1. Modify the Ingress resource to inject Lua code via server-snippet annotation"
echo "    2. Lua code reads SA token from /var/run/secrets/kubernetes.io/serviceaccount/token"
echo "    3. Uses SA token to call K8s API: curl -k https://kubernetes.default.svc/api/v1/namespaces/default/secrets/flag-secret"
echo "    4. Extracts flag from Secret response"
echo ""
echo "    Note: This scenario requires kubectl access to modify Ingress objects."
echo "    The attacker must have permissions to create/update Ingress resources."