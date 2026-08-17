# CLOUD-40 Dataform：托管数据服务跨租户路径穿越

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-40 |
| 名称 | Dataform: Cross-Tenant Path Traversal in Managed Data Service |
| 技术/CVE | N/A (cross-tenant path traversal, case #267) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10640 |

## 场景概述
托管数据工作流服务把所有租户的工作区放在同一个共享执行器上，而
dataset 引用的路径没有做容器化校验。攻击者提交 `../` 引用即可
读写其他租户工作区的文件（Dataform 跨租户路径穿越）。

## 教材锚点
- 案例：Dataform cross-tenant path traversal（#267）
- 平面：数据面（管线执行）→ 失败边界：命名空间/账号
- 六镜头：SHARED（共享执行器承载所有租户工作区）；BOUNDARY（路径
  规范化未加租户容器约束）

## 前置知识
- 路径穿越；托管数据服务的多租户工作区模型

## 利用步骤
1. 查看控制面文档，确认所有租户在同一共享执行器上。
2. 提交 workflow：`workspace=tenant-a`，
   `dataset_ref=../tenant-b/secret.txt`（从本租户工作区逃逸到相邻租户）。
3. 执行器解析出 `tenant-b/secret.txt`，返回内容与 flag。

## Flag
`flag{cloud-40-cross-tenant-workspace}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Managed data workflows, shared executor, and filesystem paths |
| 侦察与前置条件 | Workspace root construction and dataset_ref normalization behavior |
| 核心漏洞与利用 | Use ../ traversal in a dataset reference |
| 权限、横向或影响 | Cross-tenant workspace file disclosure |
| 验证 | Read the victim workspace secret/flag |

## 修复建议
路径必须先规范化再校验是否仍位于本租户工作区根目录内；执行器
按租户隔离（沙箱/容器）。
