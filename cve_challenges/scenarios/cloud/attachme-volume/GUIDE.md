# CLOUD-31 AttachMe：可预测资源 ID + 属主校验缺失

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-31 |
| 名称 | AttachMe: Predictable Volume ID + Missing Ownership Check |
| 技术/CVE | N/A (control-plane ownership check missing) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10631 |

## 场景概述
块存储控制面的资源 ID 可预测（`ocid.vol.<4位>`，从 1000 顺序分配），
而 AttachVolume 接口从不校验调用者是否为卷属主。攻击者猜出受害者
卷 ID，直接附加到自己实例并读取卷内数据——一次控制面"属主校验缺失"
的跨租户攻击。

## 教材锚点
- 案例：AttachMe（可预测 OCID + 缺失授权检查，Ch11 Breakdown 3）
- 平面：控制面（块存储 API）→ 失败边界：账号/属主
- 六镜头：IDENTITY（API 不复检调用者身份）；BOUNDARY（属主校验缺失）；
  DETECTION（控制面调用会产生审计，但属主校验缺陷本身无感知）

## 前置知识
- 控制面 API 的资源 ID 结构与可预测性
- "属主校验"与"认证"是两个不同控制点

## 利用步骤
1. 阅读控制面文档，了解 ID 格式 `ocid.vol.<4位>`。
2. 枚举/猜测 `ocid.vol.1001`，查询详情确认属主是 victim-tenant。
3. 调用 `/attach` 把该卷附加到攻击者实例（无属主校验）。
4. 从实例读取卷数据，得到 flag。

## Flag
`flag{cloud-31-victim-volume}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Cloud volume control plane, volume IDs, and instance attachment |
| 侦察与前置条件 | Predictable volume identifier pattern and ownership validation behavior |
| 核心漏洞与利用 | Request attachment of a victim volume by ID |
| 权限、横向或影响 | Cross-tenant block storage access |
| 验证 | Mount/read the attached volume flag |

## 修复建议
AttachVolume 必须校验卷属主与调用者一致；资源 ID 应不可预测
（足够熵）；控制面 API 默认 deny。
