# CLOUD-16 ExtraReplica：内部子网绕过防火墙 + 证书 CN 校验缺陷

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-16 |
| 名称 | ExtraReplica: Internal Subnet + CN Regex → Cross-Tenant DB Replication |
| 技术/CVE | N/A (internal subnet + mis-anchored cert regex, case #061) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10627 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | 租户控制台 经 flag-vault 交付（mtls：内部 CA 签发、CN 形如 replication.<id>… 的客户端证书） |

## 场景概述
托管数据库容器共享宿主网络命名空间，位于供应商内部子网 10.0.0.0/24。
受害者数据库的 deny-all 防火墙只覆盖公网路径；同时 replication 用户
在内部子网用客户端证书认证，而证书 CN 校验正则尾部未锚定
（`...database.azure.com(.*)`），攻击者可用带自己域名后缀的 CN 通过。

## 教材锚点
- 案例：ExtraReplica 跨账号数据库漏洞（#061）
- 平面：数据面（复制协议）→ 失败边界：网络 + 身份
- 六镜头：BOUNDARY（防火墙只管公网路径，内部子网是软边界）；
  IDENTITY（CN 正则未锚定）；DETECTION（流复制在数据库审计之外）

## 前置知识
- PostgreSQL 流复制 / pg_basebackup；pg_hba cert 认证
- 内部子网与公网防火墙的边界模型

## 利用步骤

1. Step 1：侦察自己的托管实例网络，确认与受害者共享内部子网 `10.0.0.0/24`，
   公网防火墙不覆盖该路径。
2. Step 2：向内部 CA 申请客户端证书，CN 为
   `replication.<victim-id>.database.azure.com.attacker.example`（尾部后缀，CA 的正则允许）。
3. Step 3：以复制用户身份 `pg_basebackup` 拉走受害者整库——得到的是同租户的轮换令牌，
   不是明文 flag。
4. 用同一张内部 CA 签发的客户端证书（`X-Client-Cert`）向 flag-vault 换取密文：证书是这个
   终点的唯一凭据，pg_basebackup 只证明你已经越过了内网与证书两道边界。

## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 租户控制台 向 flag-vault 出示「内部 CA 签发、CN 形如 replication.<id>… 的客户端证书」（校验模式 `mtls`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-16-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-16 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-16 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | PostgreSQL replication, mutual TLS, internal networks, and X.509 |
| 侦察与前置条件 | Internal subnet trust and CA CN regex behavior |
| 核心漏洞与利用 | Obtain a certificate with a regex-bypass CN and start replication |
| 权限、横向或影响 | Cross-tenant database replication |
| 验证 | Read replicated victim data/flag |

## 修复建议
内部子网也必须有租户级网络隔离；证书 CN 正则必须锚定末尾；复制用户
不应信任"看起来像内部来源"的连接。
