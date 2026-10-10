# CLOUD-09 Golden SAML：信任根伪造

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-09 |
| 名称 | Golden SAML → Federation Trust Root Compromise |
| 技术/CVE | N/A (SAML signing key exposure) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10613 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | iam 经 flag-vault 交付（jwt：用 IdP 私钥伪造的 RS256 断言） |

## 场景概述
SAML IdP 的签名私钥泄露（藏在 IdP 容器中）。攻击者拿到私钥后用
任意身份属性签发 SAML 断言，作为任意用户/角色登录云控制面，
完成信任根级伪造。

## 教材锚点
- 案例：Golden SAML（Ch3 T2）
- 平面：控制面（身份联合）→ 失败边界：身份/信任根
- 六镜头：IDENTITY（信任根密钥失陷即一切可伪造）；DETECTION
  （伪造断言与合法登录无异）

## 前置知识
- SAML 断言结构与签名；IdP 私钥保护

## 利用步骤
1. 从 SAML IdP 容器/配置中获取签名私钥。
2. 构造 SAML 断言（NameID=目标管理员），用私钥签名。
3. 提交断言换取控制面会话，读取 flag。
4. 终端服务 iam 向 flag-vault 出示用 IdP 私钥伪造的 RS256 断言，换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 iam 向 flag-vault 出示「用 IdP 私钥伪造的 RS256 断言」（校验模式 `jwt`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-09-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-09 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-09 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | SAML assertions, signing keys, and federation |
| 侦察与前置条件 | SAML IdP key material and role assertion format |
| 核心漏洞与利用 | Forge a signed SAML assertion with the exposed key |
| 权限、横向或影响 | Federation trust-root compromise |
| 验证 | Exchange the forged assertion for the flag-bearing role |

## 修复建议
签名密钥必须 HSM 保护；定期轮换；对断言做 audience/时间窗校验。
