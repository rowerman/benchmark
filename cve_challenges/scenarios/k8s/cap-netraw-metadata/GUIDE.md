# K8S-31 CAP_NET_RAW → 元数据服务 MITM

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-31 |
| 名称 | Container Escape via CAP_NET_RAW → Metadata MITM |
| 技术/CVE | N/A (CAP_NET_RAW + ARP spoofing) |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |

## 场景概述
集群中攻击者 pod 被授予 CAP_NET_RAW（可发裸报文），与 victim pod
同节点。攻击者用 ARP 欺骗劫持 victim → 元数据服务的流量，MITM
读取/替换 IMDS 响应，窃取实例凭据（EKS/GKE 元数据 MITM 攻击）。

## 教材锚点
- 案例：CAP_NET_RAW + hostNetwork 元数据 MITM（#019/#036）
- 平面：数据面（网络）→ 控制面凭据；失败边界：网络/宿主
- 六镜头：SHARED（同一节点/二层共享）；DETECTION（ARP 欺骗在
  节点层难以发现）

## 前置知识
- ARP 欺骗；IMDS 元数据协议；容器 capabilities

## 利用步骤
1. 进入 attacker pod（`kubectl exec -it attacker -- sh`），安装
   `dsniff`/`arpspoof` 工具。
2. 对 victim 与 metadata-server 之间做 ARP 欺骗（双向）。
3. 在中间截获 victim 发往元数据服务的请求，返回伪造/转发的凭据响应，
   窃取 `AKIA...` 凭据与 flag。

## Flag
`flag{k8s-31-step1-netraw}` 及窃取到的凭据

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | KIND, CAP_NET_RAW, ARP, and metadata service networking |
| 侦察与前置条件 | Victim/metadata traffic path and L2 neighbor discovery |
| 核心漏洞与利用 | Perform ARP spoofing to MITM IMDS traffic |
| 权限、横向或影响 | Instance credential interception across a shared node network |
| 验证 | Capture the intercepted credential/flag response |

## 修复建议
默认移除 NET_RAW；元数据服务采用 IMDSv2 令牌 + 网络策略限制；
二层隔离（每个节点独立 L2）。

## Kubernetes 专项利用步骤

## Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (CAP_NET_RAW + ARP spoofing) |
| Difficulty | L3 |
| Type | k8s |
| Path | scenarios/k8s/cap-netraw-metadata |

## Attack Path Summary
CAP_NET_RAW capability → ARP spoofing → intercept victim→metadata traffic → steal IMDS credentials

## Prerequisites
### Knowledge
- Linux capabilities (CAP_NET_RAW) and network stack manipulation
- ARP spoofing and man-in-the-middle attack techniques
- EC2 Instance Metadata Service (IMDS) protocol

### Tools
- arpspoof / ettercap: ARP spoofing tools
- tcpdump / wireshark: Network traffic capture and analysis

## Step-by-Step Exploitation
### Step 1: Deploy Attacker Pod with CAP_NET_RAW
**Flag:** `flag{k8s-31-step1-netraw}`

```bash
kubectl get pods
kubectl exec -it attacker -- sh
```

### Step 2: ARP Spoof + Metadata Interception
Use CAP_NET_RAW to redirect victim pod traffic through attacker, capturing IMDS credentials.

```bash
arpspoof -i eth0 -t <victim_ip> <gateway_ip>
tcpdump -i eth0 -A port 5000
```

### Step 3: Use Stolen Credentials
Use captured IMDS credentials to access protected cloud resources.

## Flag Location
- Flag: Environment variable in victim pod

## Verification Commands
```bash
kubectl exec attacker -- cat /proc/1/status | grep Cap
kubectl exec victim -- env | grep FLAG
```
