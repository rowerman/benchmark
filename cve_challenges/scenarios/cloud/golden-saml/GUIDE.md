# CLOUD-10 Golden SAML：信任根伪造

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-10 |
| 名称 | Golden SAML → Federation Trust Root Compromise |
| 技术/CVE | N/A (SAML signing key exposure) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10613 |

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

## Flag
`flag{cloud-10-...}`（伪造身份可访问的资源）

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
