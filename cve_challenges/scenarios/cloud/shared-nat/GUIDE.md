# CLOUD-28 共享 NAT 出口：源 IP 白名单绕过

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-28 |
| 名称 | Shared NAT Egress: Source-IP Allowlist Bypass |
| 技术/CVE | N/A (service-tag source-IP trust, case #259) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10639 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | victim-api 经 flag-vault 交付（network-source：受保护接口内网地址（经共享 NAT 出口）） |

## 场景概述
受害者防火墙按源 IP 信任供应商"服务地址段"（Azure service tags 模型）。
攻击者租户与受害者共享供应商托管的 NAT 出口——从该出口发出的流量
源 IP 落在受信段内，直接绕过白名单。攻击者不需要伪造任何 header，
是网络软边界本身的问题。

## 教材锚点
- 案例：Abusing Service Tags to bypass Azure Firewall（#259）
- 平面：数据面（网络）→ 失败边界：网络软边界
- 六镜头：BOUNDARY（源 IP 不是身份）；SHARED（托管 NAT 是共享出口，
  受信地址段被多租户共用）

## 前置知识
- 基于源 IP 的防火墙与"服务标签/地址段"信任模型

## 利用步骤
1. 直接访问受害者 `/flag`——源 IP 不在受信段，403。
2. 调用共享 NAT `/egress` 代理访问受害者 `/flag`——出口源 IP
   落在 168.63.0.0/24 受信段，返回 flag。
3. 终端服务 victim-api 向 flag-vault 出示受保护接口内网地址（经共享 NAT 出口），换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 victim-api 向 flag-vault 出示「受保护接口内网地址（经共享 NAT 出口）」（校验模式 `network-source`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-28-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-28 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-28 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Shared NAT egress, HTTP forwarding, and source-IP allowlists |
| 侦察与前置条件 | Trusted provider address range and target firewall policy |
| 核心漏洞与利用 | Route a request through the shared NAT |
| 权限、横向或影响 | Bypass source-IP-based trust boundary |
| 验证 | Read the protected API response containing the flag |

## 修复建议
防火墙不要基于源 IP/服务标签做信任决策；服务地址段不能与租户
共享出口混用；对敏感服务使用身份级认证。
