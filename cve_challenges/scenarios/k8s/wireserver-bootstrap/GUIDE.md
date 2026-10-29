# K8S-26 K8s 宿主代理通道 → 节点引导密钥窃取

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-26 |
| 名称 | K8s Host-Agent Channel → Node Bootstrap Secrets |
| 技术/CVE | N/A (unvalidated transport cert, case #255/#184) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10628 |
| 入口身份 | 宿主侧黑盒起点（无私有云凭据，需自行派生） |
| 终点 | Wireserver / 控制面 经 flag-vault 交付（network-source：两个内部服务地址，各取自己那枚 flag） |

## 场景概述
私有云 K8s 节点上的普通 pod 可以访问宿主代理通道。goalstate 缺少认证，
证书端点信任调用方公钥，扩展配置也可被调用方解密。攻击者据此取得节点引导凭据并伪造节点身份。

## 教材锚点
- 案例：WireServing（#255）；WireServer 扩展设置解密（#184）
- 平面：控制面通道（guest→host agent）→ 失败边界：网络
- 六镜头：MAGIC（引导自动化以高权限运行）；SHARED（host agent 是所有
  VM 的共享组件）；DETECTION（网络策略未覆盖 host-agent IP）

## 前置知识
- private-cloud K8s host agent / HostGAPlugin 协议；VM 扩展 protectedSettings
- Kubernetes TLS bootstrap（CSR 自动签发）

## 利用步骤
1. 从 pod 内 GET `http://168.63.129.16/machine/?comp=goalstate`（无鉴权）。
2. 生成自签传输证书，放入 `x-ms-guest-agent-public-x509-cert` 头请求
   `/certs`；服务端把密钥包加密到该公钥，用自己私钥解密得到
   TenantEncryptionCert。
3. 请求 `/vmSettings`，用 TenantEncryptionCert 解密 protectedSettings，
   得到 `TLS_BOOTSTRAP_TOKEN` 与 flag。
4. 用 bootstrap token 向控制面提交 CSR（CN=system:node:*）——自动签发。
5. 以伪造的 node 身份读取 `/node-secrets`，拿到最终 flag。
6. 终端服务 Wireserver / 控制面 向 flag-vault 出示两个内部服务地址，各取自己那枚 flag，换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 Wireserver / 控制面 向 flag-vault 出示「两个内部服务地址，各取自己那枚 flag」（校验模式 `network-source`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{k8s-26-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py k8s-26 <flag>`（gate）+
  `python3 tests/cloud/run.py k8s-26 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | private-cloud K8s host agent, X.509, RSA-OAEP, and AES-GCM |
| 侦察与前置条件 | Unauthenticated goalstate and caller-supplied transport certificate handling |
| 核心漏洞与利用 | Supply an attacker certificate, unwrap the secret bundle, and decrypt settings |
| 权限、横向或影响 | Node bootstrap secret theft and node identity forgery |
| 验证 | Use the recovered bootstrap material to obtain the node flag |

## 修复建议
网络策略必须阻止 pod 访问 host-agent IP；host agent 必须校验传输证书
归属；扩展密钥按节点短时效轮换。
