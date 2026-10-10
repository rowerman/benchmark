#!/bin/bash
set -euo pipefail
K8S_ID="k8s-20"
CLUSTER_NAME="cve-k8s-20-ingress-rce"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-20] CVE-2025-1974 ingress-nginx Admission Controller RCE"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_write_node_flag /host-flag

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

echo "[*] Placing flag as an nginx credential fragment inside the controller pod..."
# flag 只在这里交付：admission webhook 的未鉴权配置注入能让 nginx -t 去 include 这个
# 片段文件，报错信息会把文件里的 token 原样带回来。片段按 base64 落盘（flag 里的花括号
# 会被 nginx 词法切开，base64 去掉了花括号），攻击者解回来就是 flag。
sleep 5
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx "$CONTROLLER_POD" -- sh -c \
  "mkdir -p /etc/nginx/credentials && printf '%s;' \"\$(printf '%s' '$FLAG' | base64 -w0)\" > /etc/nginx/credentials/flag.b64" || {
  echo "[!] Could not place credential fragment in controller pod" >&2
  exit 1
}

k8s_publish_agent_identity none 
k8s_info
echo "    Admission Webhook: https://localhost:10443/networking/v1/ingresses"
echo ""
echo "    Exploitation steps:"
echo "    1. Verify webhook access:"
echo "       curl -k https://localhost:10443/networking/v1/ingresses"
echo "    2. Craft malicious AdmissionReview payload (see docs/k8s-20)"
echo "    3. Send exploit to achieve RCE in ingress-nginx controller"
echo "    4. Read flag: cat /tmp/flag.txt (inside controller pod)"
echo ""
echo "    Note: CVE-2025-24514/2025-1974 —— admission webhook 会把 Ingress 注解未转义地"
echo "    拼进 nginx 配置并跑 nginx -t；未鉴权即可注入指令。本版本 http 级"
echo "    init_by_lua_block 已被模板占用（重复被拒），参考利用走 include 任意文件读："
echo "    读出 /var/run/secrets/kubernetes.io/serviceaccount/token（JWT 是单个 token，会整段"
echo "    出现在 nginx 报错里），再用它列出集群 Secret 拿 flag。"
