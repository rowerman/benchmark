# DEF / NET / K8S 场景能力与知识需求分析

本文从理论层面总结解决 DEF（防御规避）、NET（网络攻击）、K8S（Kubernetes）三类单点场景所需的核心能力和领域知识。

---

## 一、DEF — 防御规避场景（5 个）

防御规避场景的核心挑战是：确定的技术行为会触发监控系统，攻击者必须理解检测机制的原理，找到绕过方法。

### 场景概览

| ID | 名称 | 难度 | 核心绕过技术 |
|----|------|:---:|-------------|
| DEF-01 | WAF Bypass SQLi Encoding | L2 | WAF 规则绕过 |
| DEF-02 | Log Clearing | L2 | 日志篡改 |
| DEF-03 | Process Hiding | L2 | 进程名混淆 |
| DEF-04 | Timestomp Recovery | L1 | 时间戳恢复 |
| DEF-05 | Living off the Land | L2 | SUID 命令参数绕过 |

### 需要掌握的能力

#### 1. 输入过滤绕过（WAF Evasion）
- **URL 编码 / 双重编码**：将 SQL 关键字编码为 `%55NION` 等形式绕过基于文本的 WAF 规则
- **大小写变换**：利用 WAF 正则大小写敏感性（`Or` vs `OR` vs `or`）
- **内联注释注入**：`UNION/**/SELECT` 中断关键字匹配但不影响 SQL 解析
- **替代操作符**：`||` 替代 `OR`，`&&` 替代 `AND`
- **核心原则**：理解 WAF 规则是在 SQL 解析之前做文本匹配，找到文本层与解析层的不一致

#### 2. 日志操作与反取证
- **sed / grep -v 精确删除**：从结构化日志中移除特定行
- **touch -t / touch -r 时间戳伪造**：恢复文件的 mtime，使基于 mtime 变更的监控失效
- **/proc 文件系统理解**：系统通过扫描 `/proc/[pid]/status` 和 `/proc/[pid]/cmdline` 检测进程行为
- **核心原则**：防御系统依赖文件系统的"副作用"（日志写入、时间戳更新、proc 信息暴露），攻击者通过消除这些副作用来隐藏痕迹

#### 3. 进程名混淆
- **exec -a 重命名**：`exec -a "httpd" cat /root/flag.txt` 使进程名显示为无害进程
- **非标准工具使用**：用 `head`、`tail`、`dd`、`od`、`xxd`、`base64`、shell built-in 替代被监控的 `cat`/`less`/`grep`/`python`
- **核心原则**：监控系统使用进程名白名单/黑名单，只要使用不在列表中的工具即可绕过

#### 4. SUID / LoTL 二进制利用
- **find -exec vs -execdir**：`-execdir` 在目标目录下执行而非从工作目录 fork 子进程，cmdline 参数模式不同
- **cmdline 监控的局限**：正则 `-exec[^d]` 只匹配 `-exec` 后首个字符非 `d`，`-execdir` 的首字符是 `e`，后续是 `xecd...`
- **核心原则**：防御脚本对 cmdline 做精确模式匹配，使用功能相同但参数形式不同的命令即可绕过

### 所需领域知识总结

| 知识领域 | 对应场景 |
|----------|---------|
| SQL 注入基础（UNION SELECT、注释语法） | DEF-01 |
| WAF 正则匹配原理（Nginx if-block、ModSecurity 规则） | DEF-01 |
| Linux 日志系统（/var/log、syslog） | DEF-02 |
| 定时任务（cron）工作机制 | DEF-02, DEF-03, DEF-04, DEF-05 |
| /proc 文件系统（/proc/[pid]/status、cmdline） | DEF-03, DEF-05 |
| Linux 文件时间戳（mtime、atime、ctime） | DEF-04 |
| sudo 配置（sudoers NOPASSWD、log_output） | DEF-04 |
| SUID 权限位与进程 UID 切换 | DEF-05 |
| find 命令 flags（-exec、-execdir、-perm） | DEF-05 |

---

## 二、NET — 网络攻击场景（3 个）

网络攻击场景的核心挑战是：攻击者处于同一二层网络的容器中，需要利用网络协议层面的漏洞来截获或还原通信数据。

### 场景概览

| ID | 名称 | 难度 | 核心攻击技术 |
|----|------|:---:|-------------|
| NET-01 | ARP Spoofing + Credential Sniffing | L2 | ARP 欺骗 + 流量嗅探 |
| NET-02 | DNS Exfiltration Detection | L2 | DNS 隧道数据还原 |
| NET-03 | Container Network Sniffing | L1 | 网桥流量嗅探 + Token 重放 |

### 需要掌握的能力

#### 1. ARP 欺骗（ARP Spoofing / ARP Cache Poisoning）
- **ARP 协议原理**：理解 ARP 请求/应答机制，MAC-IP 映射关系无状态无认证
- **双向欺骗**：同时欺骗 Client 和 Server，让双方都以为攻击者的 MAC 是对端的 MAC
- **IP 转发**：`echo 1 > /proc/sys/net/ipv4/ip_forward` 确保流量不被黑洞
- **工具链**：arpspoof（dsniff 套件）、tcpdump 抓包
- **核心原则**：ARP 协议基于信任链，二层网络中的任何主机都可以伪造 ARP 应答，成为中间人

#### 2. DNS 数据外泄（DNS Exfiltration）还原
- **DNS 协议结构**：DNS 查询中的子域名以明文传输，可作为隐蔽信道
- **分片编码**：数据被编码为 hex 分片嵌入子域名标签（如 `00-666c6167.exfil.attacker.com`）
- **包捕获与过滤**：`tcpdump -i eth0 -n udp port 53` 捕获 DNS 查询包
- **数据重组**：从多个 DNS 查询中提取索引序号 → 排序 → 拼接 hex → `xxd -r -p` 解码
- **核心原则**：DNS 查询天然穿越防火墙（53/UDP），攻击者利用子域名存储编码数据，防御者需要解析 DNS 查询内容来发现异常

#### 3. 网桥流量嗅探与 Token 重放
- **共享网络命名空间**：同一 Docker bridge 网络中的容器在 Layer 2 直接通信
- **混杂模式**：`tcpdump -i eth0` 可捕获同一网段所有流量（非仅本机）
- **HTTP Header 提取**：通过 ngrep 或 tcpdump -A 提取 `X-Token` 等自定义认证头
- **Token 重放**：将捕获的 token 通过 curl 发送到受保护的 `/secret` 端点
- **核心原则**：Docker bridge 网络不隔离二层流量，同一网络中的任何容器都能看到明文传输的认证凭据

### 所需领域知识总结

| 知识领域 | 对应场景 |
|----------|---------|
| ARP 协议（请求/应答、MAC-IP 映射） | NET-01 |
| 二层网络 MITM 攻击原理 | NET-01 |
| IP 转发与 Linux 网络参数（/proc/sys/net） | NET-01 |
| DNS 协议（A 记录查询、子域名格式） | NET-02 |
| 十六进制编码/解码 | NET-02 |
| tcpdump BPF 过滤器（port、host、udp） | NET-01, NET-02, NET-03 |
| Docker bridge 网络模型 | NET-01, NET-02, NET-03 |
| HTTP 协议结构（请求头、请求体） | NET-01, NET-03 |

---

## 三、K8S — Kubernetes 场景（26 个）

K8S 场景覆盖从容器逃逸到集群控制的全攻击面，按攻击类型可分为 7 大类。

### 大类一：容器逃逸（Container Escape）— 6 个场景

| ID | 技术 | 难度 | 关键知识点 |
|----|------|:---:|-----------|
| K8S-01 | runC CVE-2024-21626 WORKDIR fd 泄露 | L2 | runC 内部机制、/proc/self/fd 语义 |
| K8S-02 | runC CVE-2025-31133 /dev/null 符号链接 | L2 | runC 文件描述符、设备节点 |
| K8S-03 | runC CVE-2025-52881 LSM 绕过 | L3 | Linux LSM (AppArmor/SELinux)、runC 钩子 |
| K8S-11 | privileged: true 容器 nsenter 逃逸 | L2 | Linux namespace、nsenter、主机 PID 命名空间 |
| K8S-14 | CAP_SYS_ADMIN cgroup release_agent | L3 | cgroup v1 机制、release_agent 原理、内核能力模型 |
| K8S-19 | CAP_SYS_PTRACE 主机进程注入 | L3 | ptrace 系统调用、进程注入原理 |

**核心能力需求：**
- Linux namespace（PID、mount、net、user、cgroup）隔离机制
- Linux capabilities 模型（CAP_SYS_ADMIN、CAP_SYS_PTRACE 等）
- cgroup v1 内部机制（notify_on_release、release_agent）
- nsenter 工具的命名空间切换原理
- runC 容器运行时的 OPEN_fd 处理流程

#### 2. 权限提升（RBAC / Privilege Abuse）— 5 个场景

| ID | 技术 | 难度 | 关键知识点 |
|----|------|:---:|-----------|
| K8S-06 | 过度宽松 ClusterRole（get/list secrets） | L1 | RBAC 模型（Role/ClusterRole/RoleBinding） |
| K8S-13 | SA Token 跨命名空间泄露与横向移动 | L2 | ServiceAccount token 机制、跨命名空间认证 |
| K8S-18 | SA Token 直接绑定 cluster-admin | L2 | ClusterRoleBinding 滥用 |
| K8S-25 | Mutating Webhook Sidecar 注入 | L2 | Admission Controller 机制 |
| K8S-10 | Helm v2 Tiller 未授权访问（端口 44134） | L1 | Helm v2 架构、Tiller gRPC API |

**核心能力需求：**
- RBAC 权限模型：理解 subjects → RoleBinding → Role/ClusterRole → verbs + resources
- ServiceAccount token 的挂载、解析和使用（`/var/run/secrets/kubernetes.io/serviceaccount/token`）
- kubectl `--token`、`--as`、`--as-group` 的身份切换
- `kubectl auth can-i` 权限探测
- Admission Webhook（ValidatingWebhookConfiguration、MutatingWebhookConfiguration）

#### 3. 主机资源滥用（Host Resource Abuse）— 5 个场景

| ID | 技术 | 难度 | 关键知识点 |
|----|------|:---:|-----------|
| K8S-12 | hostPath 可写卷 + 符号链接逃逸 | L2 | hostPath 卷安全模型、符号链接攻击 |
| K8S-16 | CRI Socket 挂载 (/run/containerd/containerd.sock) | L2 | CRI 运行时 API（containerd/CRI-O） |
| K8S-17 | Docker Socket 挂载 (/var/run/docker.sock) | L1 | Docker UNIX socket API、docker CLI |
| K8S-23 | hostPID + ProcFS 主机文件系统访问 | L1 | hostPID 模式、/proc 文件系统 |
| K8S-05 | gitRepo Volume 符号链接逃逸（CVE-2024-10220） | L2 | gitRepo volume 类型、git clone 符号链接处理 |

**核心能力需求：**
- Kubernetes Volume 类型（hostPath、gitRepo、emptyDir、projected）
- Docker / CRI socket 的 API 交互：`docker run -v /:/host` 挂载主机根文件系统
- crictl / ctr 操作 containerd 运行时
- Linux 符号链接在容器-主机文件系统边界的行为
- `/proc/[pid]/root` 访问技巧

#### 4. etcd / 集群存储访问 — 2 个场景

| ID | 技术 | 难度 | 关键知识点 |
|----|------|:---:|-----------|
| K8S-08 | etcd 未授权访问（端口 2379） | L3 | etcd v3 API、K8s 数据存储模型 |
| K8S-09 | 私有容器镜像仓库投毒 | L2 | Docker Registry API、镜像 tag 管理 |

**核心能力需求：**
- etcd v3 数据模型（key-value 存储、前缀扫描）
- Kubernetes 在 etcd 中的存储布局（`/registry/secrets/`、`/registry/pods/`、`/registry/deployments/`）
- etcdctl 操作：`get / --prefix --keys-only`、`get /registry/secrets/<ns>/<name> --print-value-only`
- Protobuf 编码的 Secret 数据的 base64 解码

#### 5. 网络攻击（K8s Network Attacks）— 5 个场景

| ID | 技术 | 难度 | 关键知识点 |
|----|------|:---:|-----------|
| K8S-22 | Service ExternalIP 流量拦截（CVE-2020-8554） | L2 | K8s Service 模型、kube-proxy iptables 规则 |
| K8S-24 | kube-proxy localhost 边界绕过（CVE-2020-8558） | L2 | kube-proxy 模式、localhost 绑定语义 |
| K8S-26 | 被入侵节点 API Server 重定向（CVE-2020-8559） | L3 | kubelet 节点信任模型 |
| K8S-27 | NetworkPolicy Label 欺骗绕过 | L2 | NetworkPolicy 规则、pod label 匹配 |
| K8S-21 | ingress-nginx Lua Snippet Secret 提取（CVE-2021-25742） | L2 | NGINX 配置注入、Lua 脚本沙箱 |

**核心能力需求：**
- Kubernetes Service 类型（ClusterIP、NodePort、LoadBalancer、ExternalIPs）
- Service externalIPs 的流量劫持机制：kube-proxy 将 externalIP 的流量 DNAT 到 Service 的后端 Pod
- NetworkPolicy 基于 label selector 的入站/出站规则
- kube-proxy 模式（iptables、IPVS、userspace）
- Kubernetes API Server 的节点认证模型

#### 6. 供应链与配置注入 — 4 个场景

| ID | 技术 | 难度 | 关键知识点 |
|----|------|:---:|-----------|
| K8S-15 | Mutable Image Tag 供应链攻击 | L2 | 镜像 tag 可变性、imagePullPolicy |
| K8S-20 | ingress-nginx Admission Controller RCE（CVE-2025-1974） | L3 | ingress-nginx 准入控制器、ssl_engine 注入 |
| K8S-07 | Kubelet API 匿名访问（端口 10250） | L2 | kubelet API 端点（/pods、/runningpods、/exec） |
| K8S-25 | Mutating Webhook Sidecar 注入 | L2 | Admission Controller 机制 |

**核心能力需求：**
- 容器镜像 tag 的可变性（`:latest` vs 固定 tag）与 imagePullPolicy 的交互
- Docker Registry v2 API（push、pull、tag 操作）
- ingress-nginx Admission Controller 的 AdmissionReview 处理流程
- kubelet API 的端点：`/pods`（列出 Pod 详情）、`/exec`（在容器中执行命令）、`/configz`（查看 kubelet 配置）
- kubelet 的认证模式：`--anonymous-auth`、`--authorization-mode`

---

### K8S 场景工具能力汇总

#### 核心工具链

| 工具 | 用途 | 涉及场景数 |
|------|------|:---:|
| **kubectl** | K8s API 交互（exec、get、describe、auth can-i、apply、create） | 全部 26 |
| **etcdctl** | 直接读写 etcd 键值存储 | K8S-08 |
| **docker CLI** | 通过 Docker socket 操作主机 Docker daemon | K8S-17 |
| **crictl / ctr** | 通过 CRI socket 操作 containerd 运行时 | K8S-16 |
| **nsenter** | 进入主机 namespace 执行命令 | K8S-11 |
| **curl** | HTTP API 调用（kubelet API、ingress webhook） | K8S-07, K8S-20, K8S-24 |
| **tcpdump / ngrep** | 网络流量嗅探 | K8S-22, K8S-24 |
| **Python 3** | exploit 脚本编写（CVE-2025-1974 等复杂利用） | K8S-20 |

#### 核心概念理解

| 概念 | 详细说明 | 涉及场景数 |
|------|---------|:---:|
| **RBAC 模型** | Subject (User/SA/Group) → RoleBinding → Role → verbs + resources | ~8 个 |
| **Linux namespace** | PID、mount、net、user、cgroup、IPC、UTS — 容器隔离的基石 | ~6 个 |
| **Linux capabilities** | CAP_SYS_ADMIN、CAP_SYS_PTRACE、CAP_NET_ADMIN、CAP_DAC_READ_SEARCH | ~6 个 |
| **hostPath Volume** | 将主机路径直接挂载到容器，绕过容器文件系统隔离 | ~5 个 |
| **K8s Service 模型** | ClusterIP、NodePort、ExternalIPs — 流量路由与 iptables 规则 | ~4 个 |
| **kubelet API** | 10250 端口 — pods/runningpods/exec/configz 端点 | ~3 个 |
| **etcd 存储布局** | K8s 将所有资源以 Protobuf 格式存储在 `/registry/` 前缀下 | ~3 个 |
| **Admission Controller** | ValidatingWebhook、MutatingWebhook — API 请求拦截与修改 | ~3 个 |
| **NetworkPolicy** | 基于 label selector 的入站/出站规则，CNI 插件实现 | ~2 个 |
| **cgroup v1** | subsystem（memory/cpu/devices）、release_agent 机制 | ~2 个 |

---

## 跨域能力矩阵

三类场景之间存在重叠的能力要求：

| 能力 | DEF | NET | K8S |
|------|:---:|:---:|:---:|
| Linux 文件系统操作（cat/find/sed/chmod/mount） | ● | | ● |
| /proc 文件系统理解 | ● | | ● |
| 进程与权限管理（SUID/capabilities/sudo） | ● | | ● |
| 网络协议层理解（ARP/DNS/HTTP） | | ● | ● |
| 流量捕获与分析（tcpdump） | | ● | ● |
| 容器隔离机制（namespace/cgroup） | | | ● |
| RBAC 权限模型 | | | ● |
| 防御绕过思维（理解检测逻辑→找绕过点） | ● | | |

---

## 总结：三类场景的难度维度

| 维度 | DEF | NET | K8S |
|------|-----|-----|-----|
| **理论门槛** | 低—需要理解 Linux 基础 | 中—需要理解网络协议 | 高—需要理解 K8s + Linux 内核 |
| **工具复杂度** | 低—标准 Linux 工具 | 中—tcpdump + 网络工具套件 | 高—kubectl + etcdctl + docker + 多工具链 |
| **攻击面广度** | 窄—聚焦防御绕过模式 | 窄—聚焦网络层攻击 | 宽—7 大类 26 场景 |
| **典型 L3 难度因素** | —（无 L3） | —（无 L3） | runC 内核级漏洞利用、内核能力滥用、ingress RCE |
| **最稀缺的知识** | crontab 监控脚本逻辑推理 | ARP 协议+二层网络 MITM | runC 内部实现 + etcd 存储编码 + kubelet API 认证模型 |
