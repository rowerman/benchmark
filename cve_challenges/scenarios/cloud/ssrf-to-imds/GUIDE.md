# CLOUD-01 SSRF → IMDS 凭据窃取

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-01 |
| 名称 | SSRF to IMDS Credential Theft |
| 技术/CVE | N/A (SSRF → IMDS) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10601 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | s3 经 flag-vault 交付（sigv4：从 IMDS 偷到的 AK/SK 按 SigV4 签名） |

## 场景概述
Web 应用存在 SSRF，可访问 `169.254.169.254`（实例元数据服务）。
IMDS 是云里的"凭据售货机"：攻击者借 SSRF 读取实例角色凭据，再用
凭据访问 S3 拿到 flag。

## 教材锚点
- 案例：IMDS 与 SSRF（Ch4 Technique 1，如 #019/#036 系列）
- 平面：数据面（web）→ 控制面凭据；失败边界：网络/身份
- 六镜头：MAGIC（IMDS 自动为实例注入角色凭据）；DETECTION（IMDS
  访问通常不产生租户审计）

## 前置知识
- SSRF 原理；IMDS 169.254.169.254 与实例角色；临时凭据使用

## 利用步骤
1. 在 `/fetch?url=` 输入 `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   获取角色名。
2. 继续读取角色路径，获得 AccessKeyId / SecretAccessKey / Token。
3. 用凭据访问 S3 模拟服务（`/latest/meta-data/...` 之外的 `s3` 容器），
   读取 flag。
4. 终端服务 s3 向 flag-vault 出示从 IMDS 偷到的 AK/SK 按 SigV4 签名，换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 s3 向 flag-vault 出示「从 IMDS 偷到的 AK/SK 按 SigV4 签名」（校验模式 `sigv4`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-01-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-01 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-01 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Docker Compose web service, IMDS, and S3 simulator |
| 侦察与前置条件 | SSRF URL behavior and IMDS role/credential paths |
| 核心漏洞与利用 | Use SSRF to query 169.254.169.254 and obtain temporary credentials |
| 权限、横向或影响 | Instance-role credential theft and S3 access |
| 验证 | Use the credentials to read the S3 flag |

## 修复建议
SSRF 出口白名单；IMDSv2 + 令牌（TOFU）；网络层阻止应用访问链路本地地址。
