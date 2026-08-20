# CLOUD-20 构建舰队 + 内部镜像仓库供应链

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-20 |
| 名称 | Build Fleet + Internal Registry: Image Supply-Chain Overwrite |
| 技术/CVE | N/A (unauth internal registry, case #260 lineage) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10629 |

## 场景概述
供应商的托管构建服务在共享构建机上执行租户 Dockerfile 的 RUN 指令；
内部镜像仓库没有任何鉴权/租户隔离，任何调用者都能拉取或覆盖任意
租户镜像。攻击者先借构建机执行泄露内部秘密，再覆盖受害者镜像，
受害者下一次拉取即被 RCE。

## 教材锚点
- 案例：内部 ACR 可写（#260）；HF Spaces 构建舰队注册表（Ch10）
- 平面：控制面（构建/注册表）→ 失败边界：命名空间 / 供应链
- 六镜头：MAGIC（构建自动化以高权限运行）；SHARED（构建舰队与内部
  registry 是所有租户共享的）；IDENTITY（registry 不校验调用者身份）

## 前置知识
- 托管 CI 构建模型；镜像供应链（registry 投毒）

## 利用步骤
1. 提交恶意 Dockerfile 到 `/build`，RUN 读取构建机环境变量
   （`$BUILD_SECRET`）证明在供应商构建机上执行。
2. 列出内部 registry（`GET /images`），发现 `victim-app:latest`。
3. `PUT /images/victim-app:latest` 用恶意脚本覆盖（无鉴权），脚本用
   python urllib 把 `/flag.txt` 外发到攻击者 `/exfil`。
4. 触发受害者工作负载 `/pull`——它执行被覆盖的镜像内容，攻击者收到
   外发的 flag。

## Flag
`flag{cloud-20-victim-image}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Build fleet runner, OCI image registry, and tenant pulls |
| 侦察与前置条件 | RUN instruction execution and internal registry authorization model |
| 核心漏洞与利用 | Execute a build job and overwrite a trusted internal image |
| 权限、横向或影响 | Cross-tenant supply-chain execution |
| 验证 | Trigger the tenant pull and capture the resulting flag |

## 修复建议
内部 registry 必须按租户/项目做鉴权与不可变 tag；构建机不得持有
可写内部 registry 的凭据；供应链信任要显式化。
