# CLOUD-11 全局 S3 命名空间抢占 → 跨租户数据窃取

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-11 |
| 名称 | Global S3 Namespace Squatting → Cross-Tenant Data Theft |
| 技术/CVE | N/A (global namespace resource squatting) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10621 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | s3-global 经 flag-vault 交付（header-secret：对象存储内部交付令牌） |

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
4. 终端服务 s3-global 向 flag-vault 出示对象存储内部交付令牌，换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 s3-global 向 flag-vault 出示「对象存储内部交付令牌」（校验模式 `header-secret`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-11-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-11 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-11 <flag>`（参考利用）。

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
