# K8s（私有云）场景变更记录

修改日期：2026-08-20

本文件由负责 K8s 场景的会话维护。本次会话按评审结论对 k8s 域 33 个单点场景与
14 条涉 k8s 攻击链做了全面修复，并落实“对外暴露利用端口必须在 10000–14000”
的硬性规则（越界即错误配置，由校验器强制）。

## 一、端口合规（3 处越界 + 强制校验）

- `scenarios/k8s/mutable-image-tag/registry-compose.yml`：`"5000:5000"` 改为
  `"10501:5000"`，compose 挂到 external `kind` 网络，containerd mirror 端点
  `http://registry:5000` 节点内可解析；deploy.sh 调整为“先建集群、再起
  registry”，并种子化良性镜像（否则 mirror 重定向后初始拉取 404）。
- `scenarios/k8s/registry-poison`：registry 改为 `--network kind -p 10500:5000
  --name k8s-registry`（原 `--network host` 实际落在 5000），pod 镜像引用改为
  节点可解析的 `k8s-registry:5000/backdoored-nginx:latest`，目标改为 Deployment +
  `imagePullPolicy: Always`，flag 放 Secret（`registry-flag`），由投毒镜像 payload
  经 SA 读取；清理了旧 kind-config 中的 mirror 配置。
- ingress-nginx 控制器清单删除 `hostPort: 80/443`（`scenarios/k8s/ingress-nginx-rce/
  ingress-nginx-deploy.yaml`、`scripts/ingress-nginx-deploy.yaml`，以及 k8s-21/
  chain23 远端清单用 sed 剔除），只保留 NodePort 10443/10480。
- `scripts/scenarios.yaml` 为 k8s-08(11379)、k8s-09(10500)、k8s-15(10501) 补注册
  端口；`scripts/fix-nmap-tcpwrapped.sh` 增补 K8S_PORTS。
- `scripts/validate-structure.py` 新增端口断言：注册端口、compose 宿主端口、
  kind-config `extraPortMappings.hostPort` 非 10000–14000 即报错。

## 二、逃逸类场景：flag 不再挂进攻击者 pod

- k8s-11/12/14/16/17/19 删除攻击者 pod 里的 `host-flag` hostPath 挂载，flag 只放
  在节点（kind-config extraMounts 已有），逃逸动作成为唯一取 flag 路径。
- k8s-11/14 补 `hostPID: true`，保证 KIND 下 `nsenter` 兜底路径可用（k8s-14 的
  release_agent 依赖 cgroup v1，另提供 nsenter 备选并在 GUIDE 注明）。
- 各 GUIDE 同步删除“直接 cat /host-flag/flag.txt”快捷路径，flag 读取改为逃逸后
  可达（nsenter /proc/1/root / cgroup 内输出 / 宿主 docker 路径等）。

## 三、etcd 用集群真实 etcd

- k8s-08 删除独立 decoy 容器（`cve-etcd-flag`），kind-config 增加
  `extraPortMappings 2379→11379` 与 `client-cert-auth: "false"`，并让 apiserver
  `--etcd-servers=http://127.0.0.1:2379`；flag 以真实 Secret 存入 kube-system，
  从宿主 11379 读 `/registry/secrets/kube-system/etcd-flag`。

## 四、调度与网络策略语义重构

- k8s-28/29：攻击者移入独立 namespace（attacker-ns），RBAC 仅允许自身 namespace
  内建 pod/exec；GUIDE 明确定位为“平台缺失准入策略（Gatekeeper/Kyverno/PSA）”，
  不再表述为“绕过安全边界”。
- k8s-27/30：deploy.sh 安装 Calico（VXLAN，kind 不支持 IPIP）使 NetworkPolicy
  真实生效；k8s-27 攻击改为“本租户打 `tier=frontend` 标签欺骗
  `namespaceSelector:{}` 策略”；k8s-30 攻击 pod 显式加 `CAP_NET_ADMIN`（配置缺陷
  本身），利用以 iptables SNAT 为主、改源 IP 为辅。

## 五、单点场景语义修正

- k8s-25 webhook-inject 重构：attacker-sa 被授予“可创建 MutatingWebhookConfiguration”
  的越权角色；预置自签 TLS webhook server（CA 存 /shared），攻击者注册 webhook →
  在 attacker-ns 建触发 pod → 注入 sidecar 并把 `serviceAccountName` 改为 victim-sa
  （仅 target-ns secrets 只读）→ 窃 token → 读 flag Secret。
- k8s-26 node-redirect：移除无 PoC 的 CVE-2020-8559 声称，改为“node-operator 过度
  授权（nodes/proxy + pods/exec）→ 跨命名空间 pod 控制”。
- k8s-22 externalip-hijack：新增经过 Service ClusterIP 的 flag-client 流量循环
  （X-Flag 头），删除攻击者无权执行的“直接读 flag Secret”提示。
- k8s-15 mutable-image-tag：删除 Deployment env 中的 FLAG，flag 只在 ConfigMap，
  由投毒镜像 payload 经 SA 读取；GUIDE 注明需推送到 mirror 路径
  `library/nginx:1.24-alpine`。
- k8s-09 registry-poison：见“端口合规”，flag 路径改为 Secret + 投毒 payload。

## 六、攻击链重构（14 条涉 k8s 链）

统一规则：入口单一；每步 flag 只有完成该步技术动作才能到达；RBAC 步一律
namespace-scoped（禁止“get/list 全集群 secrets”的预置 reader）；链内 etcd 不再
宿主暴露，最终 flag 写入**自定义 etcd key**（`k8s_put_etcd_key`，非 /registry 路径，
kubectl 读不到，杜绝跳步）；未实现/不可复现步骤替换为 KIND 可复现的等价逃逸；
跨域链的 web/db 组件移入集群（NodePort 10106/10107/10205 均在区间内）。

- container-to-admin：k8s-06（Role 限定）→ k8s-11 privileged 逃逸 → etcd。
- cri-to-etcd：CRI 逃逸 → 节点 shell（admin.conf）读 kube-system secret → etcd。
- docker-to-etcd：docker.sock 逃逸 → 投毒真实目标 Deployment → etcd。
- hostpath-to-daemonset：更名为“hostPath to Node Control”，k8s-12 → k8s-07 →
  k8s-16；删除未实现的 registry/gitrepo 步（原链名不符且无 DaemonSet）。
- ingress-to-etcd：保留 CVE-2025-1974 真实步；补 ingress-nginx SA 的 secret-reader
  ClusterRoleBinding；etcd 步改为 controller（hostNetwork）直查
  `127.0.0.1:2379`，移除 32379 宿主映射。
- kubelet-to-pod-access：修 kind-config 重复键；改为“kubelet 匿名枚举/exec → 窃 Role 限定
  token 读 secret → kubelet exec 读最终 flag”，不再依赖 etcd，name 更新。
- privilege-to-etcd / caps-to-cluster：逃逸 → 节点 shell → etcd；删除预置 reader。
- sa-lateral-escape：k8s-13 → k8s-06（Role 限定）→ k8s-12 hostPath 逃逸（替换 runC）。
- hostpid-to-node：改为 2 步（hostPID `/proc/1/root` 读节点 flag → 节点最终 flag），不再声称
  存在 seccomp bypass。
- externalip-to-secrets：internal-api 以 secret-reader-sa 运行，循环请求头携带真实
  SA token（X-Cred）；劫持 → 抓 token → 直接读 ns-beta/kube-system flag。
- wp-lfi-to-cluster：WordPress 移入集群（NodePort 10106，SA=chain17-sa），LFI/RCE →
  SA secret → docker.sock 逃逸（curl --unix-socket）→ etcd。
- redis-to-k8s：链内部署 redis:6.2.6（无鉴权 + CVE-2022-0543 Lua 沙箱逃逸），
  redis pod privileged+hostPID → nsenter 节点 shell → etcd。
- pg-sqli-to-node：链内部署 web 应用 + postgres Pod（NodePort 10107），SQLi →
  COPY PROGRAM RCE → 可写 hostPath 逃逸 → kubelet 匿名 exec 最终 flag。

## 七、文档与校验同步

- 所有被改场景的 GUIDE.md 同步更新（入口端口、利用步骤、flag 路径、技术/CVE
  标注），删除过时内容；`scenarios.yaml` 同步 k8s-25/26 名称与技术标注。
- `scripts/k8s-common.sh` 新增 `k8s_install_calico` 与 `k8s_put_etcd_key` 两个
  公共函数。

## 八、验证情况

- 静态：`validate-structure.py` 通过（89 场景 / 37 链 / 59 compose，含新增端口与
  GUIDE 一致性检查）；149 个 `.sh` 全量 `bash -n` 通过；82 个嵌入式 YAML heredoc
  块（引号/未引号）解析通过；`registry-compose.yml` `docker compose config` 通过。
- 端口审计：全仓宿主发布端口均在 10000–14000，无 `5000` 残留。

## 九、未完成事项

- **运行时验证未做（本环境限制）**：沙箱无法拉取 `kindest/node` 与场景镜像
  （Docker Hub 返回 EOF），kind 类 exploit-to-flag 未实际部署验证。需在有网络的
  机器上按更新后的 GUIDE 逐场景/逐链跑通，重点：
  - k8s-08 的 apiserver→HTTP etcd 新配置（kind-config 补丁是否被 kubeadm 接受、
    宿主 11379 是否可读真实 etcd）。
  - k8s-27/30 的 Calico（VXLAN）安装与 NetworkPolicy 真实生效、IP 欺骗是否可行。
  - k8s-25 自签 webhook 的 TLS/caBundle 与注入链路。
  - 跨域链（wp-lfi、redis、pg-sqli）的镜像构建与整链状态传递。
- k8s-14（CAP_SYS_ADMIN cgroup）release_agent 依赖 cgroup v1；若宿主为 v2 需走
  nsenter 备选路径（已写入 GUIDE，未实测）。
- runC 三个 CVE 与 gitRepo（k8s-01/02/03/05）保留原设计，需真机内核验证，KIND
  下未强行改造。
- 链的节点 shell 步骤（安装 kubectl/curl）依赖节点 apt/网络，文档已给 fallback，
  未实测。

## 十、CLOUD K8s 场景迁移

- `CLOUD-03`、`CLOUD-12` 已迁移为 `K8S-32`、`K8S-33`；`CLOUD-02` 保留在
  Cloud 注册表并恢复到 `scenarios/cloud/cap-netraw-metadata/`。
- `CLOUD-02` 的 KIND/IMDS 场景保留 Cloud 定位，注册表、GUIDE、部署脚本和
  flag 前缀均已同步；K8s 单点总数为 32。


修改日期：2026-08-22

## 十一、本次补充修复：CLOUD-02 与攻击链一致性

- 恢复 `CLOUD-02`：目录从 `scenarios/k8s/cap-netraw-metadata/` 移回
  `scenarios/cloud/cap-netraw-metadata/`，注册表、GUIDE、deploy/teardown 和 flag
  前缀统一为 Cloud ID；`check-cloud-consistency.py` 恢复为 31 个活动 Cloud 场景。
- CLOUD-02 部署改为真实可达的模拟 IMDS 流程：新增 metadata Service、victim 周期性
  请求 credentials endpoint、metadata-victim NetworkPolicy，并将 attacker 与 victim
  固定到同一 KIND 节点；flag 仅出现在 metadata 响应，不再直接挂载到攻击者或 victim。
- `docker-to-etcd` 修复 registry seed 顺序：先确认/拉取 `nginx:1.24-alpine`，再 tag/push；
  seed 失败立即退出，避免目标 Deployment 静默进入 ImagePullBackOff。
- `externalip-to-secrets` 修正 internal-api Service 的 `targetPort: 80`，并补齐 attacker
  Pod 的 `app=attacker` selector label，确保 X-Flag/X-Cred 流量实际产生。
- `ingress-to-etcd` 在部署后强制 ingress controller 使用 `hostNetwork` 与
  `ClusterFirstWithHostNet`，并增加节点本地 etcd 可达前置检查。
- `wp-lfi-to-cluster` 的 Docker socket 逃逸容器改为执行最终 etcd 查询后保持运行，替换
  原先执行 `cat /etc/hostname` 后立即退出的命令。
- 将 `kubelet-to-etcd` 重命名为 `kubelet-to-pod-access`，将 `seccomp-to-escape` 重命名
  为 `hostpid-to-node`，同步集群名、flag 和变更说明，删除不成立的 etcd/seccomp 语义。

## 十二、本次验证

- `validate-structure.py`：89 个场景、37 条链、60 个 Compose 文件通过。
- `check-cloud-consistency.py`：31 个活动 Cloud ID、迁移 ID 排除和链引用校验通过。
- 全部 `chain.yaml` 解析通过；修改后的 heredoc YAML 解析通过；全部 `.sh` 使用 Git Bash
  `bash -n` 通过；`git diff --check` 通过。
- Docker/KIND 运行时验证未执行：当前 Docker daemon 返回 `permission denied`，无法连接
  Docker API；因此本次结论仍限于静态与脚本级验证。

## 十三、后续未完成事项

- runC、LSM、gitRepo、CNI、Redis 等强运行时场景仍需在具备 Docker/KIND 和镜像网络的环境中
  逐场景实跑，并验证攻击动作之间的 artifact/flag 状态传递。
