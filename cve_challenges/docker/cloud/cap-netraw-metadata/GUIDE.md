# CLOUD-02 CAP_NET_RAW → 元数据服务 MITM

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
`flag{cloud-02-step1-netraw}` 及窃取到的凭据

## 修复建议
默认移除 NET_RAW；元数据服务采用 IMDSv2 令牌 + 网络策略限制；
二层隔离（每个节点独立 L2）。
