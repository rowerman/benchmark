#!/bin/bash
set -euo pipefail
K8S_ID="k8s-20"
CLUSTER_NAME="cve-k8s-20-ingress-rce"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

echo "[K8S-20] CVE-2025-1974 ingress-nginx Admission Controller RCE"
k8s_init
k8s_create_host_flag
k8s_create_cluster
k8s_wait_ready

echo "[*] Labeling node for ingress-nginx scheduling..."
kubectl label node "${CLUSTER_NAME}-control-plane" ingress-ready=true --overwrite 2>/dev/null || true

echo "[*] Pre-loading container images into KIND..."
# Load base images; report if ingress-nginx images are missing
for img in nginx:1.24-alpine registry.k8s.io/ingress-nginx/controller:v1.11.0 registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.4.1; do
  if docker image inspect "$img" >/dev/null 2>&1; then
    kind load docker-image "$img" --name "$CLUSTER_NAME" 2>/dev/null || echo "  [!] Failed to load $img into KIND"
  else
    echo "  [!] Image $img not found locally — pull it first: docker pull $img"
  fi
done

echo "[*] Deploying vulnerable ingress-nginx v1.11.0 (from local YAML)..."
LOCAL_YAML="$(dirname "$0")/ingress-nginx-deploy.yaml"
if [ ! -f "$LOCAL_YAML" ]; then
  echo "[!] Local deploy YAML not found. Downloading from GitHub..."
  DEPLOY_URL="https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.0/deploy/static/provider/kind/deploy.yaml"
  curl -sL --connect-timeout 10 --max-time 30 "$DEPLOY_URL" -o "$LOCAL_YAML" || {
    echo "[!] ERROR: Cannot download ingress-nginx deploy YAML (GitHub unreachable)"
    echo "[!] Download manually from: $DEPLOY_URL"
    echo "[!] Save as: $LOCAL_YAML"
    echo "[!] Then run: sed -i 's/@sha256:[a-f0-9]\{64\}//g' $LOCAL_YAML"
    exit 1
  }
fi
# Strip @sha256:... digest suffixes so locally-loaded images match
sed -i 's/@sha256:[a-f0-9]\{64\}//g' "$LOCAL_YAML"
kubectl apply -f "$LOCAL_YAML"

echo "[*] Waiting for ingress-nginx controller and certgen jobs to complete..."
k8s_wait_pods_label "app.kubernetes.io/component=controller" "ingress-nginx"
# Also wait for certgen jobs to finish
k8s_wait_job "ingress-nginx-admission-create" "ingress-nginx"
k8s_wait_job "ingress-nginx-admission-patch" "ingress-nginx"
sleep 10

echo "[*] Exposing admission webhook as NodePort 30443..."
# Patch the admission webhook service to NodePort for external access
kubectl patch service ingress-nginx-controller-admission -n ingress-nginx -p '{"spec":{"type":"NodePort","ports":[{"name":"https-webhook","port":443,"targetPort":8443,"nodePort":30443}]}}' 2>/dev/null || true

echo "[*] Creating backend demo app..."
k8s_apply << 'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: demo-backend
  template:
    metadata:
      labels:
        app: demo-backend
    spec:
      containers:
        - name: backend
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              echo 'backend is running' > /usr/share/nginx/html/index.html
              nginx -g 'daemon off;'
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: demo-backend
  namespace: default
spec:
  selector:
    app: demo-backend
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo-ingress
  namespace: default
spec:
  ingressClassName: nginx
  rules:
    - host: demo.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: demo-backend
                port:
                  number: 80
YAML

echo "[*] Placing flag in ingress-nginx controller pod..."
# Wait for the controller pod to be fully running
sleep 5
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx "$CONTROLLER_POD" -- sh -c "echo '$FLAG' > /tmp/flag.txt" 2>/dev/null || {
  echo "[!] Could not write flag to controller pod, trying copy..."
  echo "$FLAG" | kubectl exec -n ingress-nginx -i "$CONTROLLER_POD" -- sh -c "cat > /tmp/flag.txt" 2>/dev/null || true
}

k8s_info
echo "    Admission Webhook: https://localhost:10443/validate"
echo ""
echo "    Exploitation steps:"
echo "    1. Verify webhook access:"
echo "       curl -k https://localhost:10443/validate"
echo "    2. Craft malicious AdmissionReview payload (see docs/k8s-20)"
echo "    3. Send exploit to achieve RCE in ingress-nginx controller"
echo "    4. Read flag: cat /tmp/flag.txt (inside controller pod)"
echo ""
echo "    Note: CVE-2025-1974 allows unauthenticated RCE via the"
echo "    ValidatingWebhookConfiguration admission endpoint."