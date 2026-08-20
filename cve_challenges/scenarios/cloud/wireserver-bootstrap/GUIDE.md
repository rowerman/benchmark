# CLOUD-19 WireServing：宿主代理通道窃取节点引导密钥

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-19 |
| 名称 | WireServing: Host-Agent Channel → Node Bootstrap Secrets |
| 技术/CVE | N/A (unvalidated transport cert, case #255/#184) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10628 |

## 场景概述
托管 K8s 节点上的普通 pod（无特权、无 hostNetwork）能访问宿主代理
WireServer（168.63.129.16）。goalstate 无鉴权；证书端点不校验调用者
提供的传输公钥；protectedSettings 用可被拉取的 TenantEncryptionCert
加密。攻击者最终拿到节点引导 token，伪造 system:node 身份读取节点
上的 Secret（WireServing，相当于集群管理员）。

## 教材锚点
- 案例：WireServing（#255）；WireServer 扩展设置解密（#184）
- 平面：控制面通道（guest→host agent）→ 失败边界：网络
- 六镜头：MAGIC（引导自动化以高权限运行）；SHARED（host agent 是所有
  VM 的共享组件）；DETECTION（网络策略未覆盖 host-agent IP）

## 前置知识
- Azure WireServer / HostGAPlugin 协议；VM 扩展 protectedSettings
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

## Flag
- `flag{cloud-19-bootstrap}`（引导脚本内）
- `flag{cloud-19-node-secrets}`（节点 Secret）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Azure WireServer-like host agent, X.509, RSA-OAEP, and AES-GCM |
| 侦察与前置条件 | Unauthenticated goalstate and caller-supplied transport certificate handling |
| 核心漏洞与利用 | Supply an attacker certificate, unwrap the secret bundle, and decrypt settings |
| 权限、横向或影响 | Node bootstrap secret theft and node identity forgery |
| 验证 | Use the recovered bootstrap material to obtain the node flag |

## 修复建议
网络策略必须阻止 pod 访问 host-agent IP；WireServer 必须校验传输证书
归属；扩展密钥按节点短时效轮换。
