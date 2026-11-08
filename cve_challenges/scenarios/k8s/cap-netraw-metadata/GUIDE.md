# PRV-27 CAP_NET_RAW → 私有云元数据服务 MITM

## 场景信息

| 字段 | 值 |
|---|---|
| ID | PRV-27 |
| 名称 | CAP_NET_RAW → Private-Cloud Metadata MITM |
| 技术/CVE | N/A (CAP_NET_RAW + ARP spoofing) |
| 难度 | L3 |
| 交付方式 | KIND / Kubernetes |
| 入口 | KIND 集群内入口（无固定宿主端口） |
| 入口身份 | 私有云 KIND 集群内 attacker pod（CAP_NET_RAW，无集群凭据） |
| 终点 | IMDS 凭据响应中的 flag（metadata-server 从集群内 Secret 注入） |

## 场景概述
自建多租户集群中的攻击者 pod 被授予 CAP_NET_RAW，与 victim pod 位于同节点。
攻击者通过 ARP 欺骗劫持 victim 到私有云元数据服务的流量，读取或替换实例凭据响应，
随后取得该工作负载在内部云平面的身份。

## 前置知识

- ARP 欺骗；IMDS 元数据协议；容器 capabilities

### Knowledge
- Linux capabilities (CAP_NET_RAW) and network stack manipulation
- ARP spoofing and man-in-the-middle attack techniques
- EC2 Instance Metadata Service (IMDS) protocol

### Tools
- arpspoof / ettercap: ARP spoofing tools
- tcpdump / wireshark: Network traffic capture and analysis

## 利用步骤

1. 与 victim 同节点、带 CAP_NET_RAW 的攻击者 pod 起一个原始套接字，向 victim 广播 ARP 应答，
   宣称元数据服务的地址在本机 MAC 上（同时向元数据服务侧宣称 victim 在本机 MAC 上，做双向劫持）。
2. 打开发包所在 netns 的转发，让被劫持的流量继续能被真实 IMDS 处理；同时用 AF_PACKET 抓包，
   从帧里取出 IMDS 响应正文（含实例凭据与 flag）。
3. flag 只存在于集群内 Secret `imds-flag`（挂进 metadata-server 的 `/flag`），
   因此明文只会出现在这条被劫持的响应里。

> 当前 KIND 环境（kindnet / Calico 均为点对点 veth）不提供共享二层，第 1 步的 ARP 欺骗
> 在对端不生效，参考利用尚未跑通；详见 `AiReport`/`AiRecord/changes/20261010-4.md` 的环境说明。

## 验证命令

```bash
kubectl exec attacker -- cat /proc/1/status | grep Cap
kubectl exec victim -- cat /tmp/metadata-credentials.json
```

## Flag

- 位置：集群内 Secret `imds-flag`（default），挂载进 `metadata-server` 的 `/flag/flag`；
  IMDS 的凭据响应里带出 flag。
- 形态：`flag{prv-27-<16 位十六进制>}`。
- 验收：`bash scripts/validate-k8s-gate.sh prv-27 <agent-kubeconfig> <flag> <cluster>`（gate）+
  `bash tests/k8s/run.sh prv-27 <agent-kubeconfig> <flag> <cluster>`（参考利用，当前受限）。

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
