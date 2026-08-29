# CLOUD-11 全局 S3 命名空间抢占 → 跨租户数据窃取

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-11 |
| 名称 | Global S3 Namespace Squatting → Cross-Tenant Data Theft |
| 技术/CVE | N/A (global namespace resource squatting) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10621 |

## 场景概述
对象存储桶名是全局唯一、先到先得。攻击者预注册（抢占）目标租户
即将使用的桶名，或枚举全局命名空间直接读取其他租户的公开桶，
实现跨租户数据窃取。

## 教材锚点
- 案例：全局命名空间抢占（Ch7；#236 Bucket Monopoly）
- 平面：控制面（全局命名空间）→ 失败边界：命名
- 六镜头：BOUNDARY（命名空间是全局共享的）；MAGIC（供应商自动化
  按名字解析资源）

## 前置知识
- 全局唯一命名空间模型；桶名可预测性

## 利用步骤
1. 列出全局命名空间，发现 victim 预置桶
   （`prod-assets-2024` 等）。
2. 尝试注册未来桶名（PUT）——先到先得。
3. 直接读取其他租户桶中的对象（`GET /buckets/<name>/<key>`），
   拿到 flag。

## Flag
`flag{cloud-11-step2-squatting}`（victim 桶对象）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Global object namespace, bucket ownership, and tenant resources |
| 侦察与前置条件 | Predictable global bucket name and victim resource discovery |
| 核心漏洞与利用 | Pre-register/squat the target bucket name |
| 权限、横向或影响 | Cross-tenant data interception through namespace ownership |
| 验证 | Read the object or workflow-delivered flag |

## 修复建议
桶名不可预测（随机后缀）；默认私有；创建前先声明所有权。
