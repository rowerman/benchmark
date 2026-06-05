#!/usr/bin/env python3
"""Generate BENCHMARK_SCENARIOS_OVERVIEW.md from summary + scenarios.yaml + chains."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

from build_benchmark_summary import (
    CHAINS_DIR,
    REPO_ROOT,
    SCENARIOS_YAML,
)

SUMMARY_PATH = REPO_ROOT / "BENCHMARK_SUMMARY.md"
OUTPUT_PATH = REPO_ROOT / "BENCHMARK_SCENARIOS_OVERVIEW.md"

SCENARIO_HEADER_RE = re.compile(
    r"^#{2,4}\s+"
    r"(WEB-\d+(?:-WAF)?|DB-\d+|LNX-\d+|K8S-\d+|AD-\d+)"
    r":\s+(.+)$",
    re.MULTILINE,
)
CHAIN_HEADER_RE = re.compile(
    r"^## Chain:\s+(.+?)\s+\(([a-z0-9-]+)\)\s*$",
    re.MULTILINE,
)
ATTACK_PATH_CODE_RE = re.compile(
    r"(?:#### Attack Path|### Attack Path(?: Summary)?)\s*\n```\s*\n(.*?)\n```",
    re.DOTALL,
)
ATTACK_PATH_LIST_RE = re.compile(
    r"### Attack Path Summary\s*\n((?:\d+\.\s+.+\n?)+)",
    re.MULTILINE,
)
CHAIN_OVERVIEW_RE = re.compile(
    r"^## Chain:.*?\n\n### Overview\s*\n\| Property \| Value \|\n(?:\|[-| ]+\|\n)?(.*?)(?=\n### )",
    re.DOTALL,
)

# key -> (service, chinese scenario description)
SERVICE_AND_DESC: dict[str, tuple[str, str]] = {
    "web-01": ("Apache Tomcat 9.0.98 (Docker)", "Tomcat 反序列化未授权 RCE"),
    "web-01-waf": ("Apache Tomcat 9.0.98 + ModSecurity WAF 代理", "Tomcat RCE 叠加 WAF 绕过"),
    "web-02": ("Apache Tomcat 9.0.97 (Docker)", "Tomcat PUT 竞态条件 JSP RCE"),
    "web-03": ("WordPress + Simple File List 4.2.2 插件", "未授权上传 PHP Webshell"),
    "web-03-waf": ("WordPress Simple File List + ModSecurity WAF", "WordPress RCE 叠加 WAF 绕过"),
    "web-04": ("WordPress + WPBookit 1.0.4 插件", "未授权图片上传导致 RCE"),
    "web-05": ("WordPress + Copypress REST API 1.2", "硬编码 JWT 伪造管理员上传插件"),
    "web-06": ("WordPress + Jupiter X Core + Contributor 账户", "SVG 上传 + LFI 触发 PHP 执行"),
    "web-07": ("Web 应用 + PostgreSQL 16.6 后端", "BIG5 编码混淆导致 SQL 注入"),
    "web-08": ("Web 应用 + MySQL 8.0.35 后端", "SQLi 写 UDF 库实现命令执行"),
    "web-09": ("ASP.NET + MSSQL Server 2022", "SQLi 启用 xp_cmdshell 执行系统命令"),
    "db-01": ("PostgreSQL (Docker, 弱口令)", "超级用户弱口令 + COPY PROGRAM RCE"),
    "db-02": ("MySQL (Docker, root 弱口令)", "直连数据库 UDF 提权执行命令"),
    "db-03": ("Oracle XE + TNS Listener", "TNS 投毒中间人窃取凭据后查表"),
    "db-04": ("MSSQL 双实例（低权 + 链接服务器）", "链接服务器 OPENQUERY 横向执行"),
    "db-05": ("Redis 无认证 + SSH (victim 用户)", "写 authorized_keys 后 SSH 登录"),
    "lnx-05": ("OpenSSH + sudo 1.9.16p2 (Docker)", "sudo --chroot NSS 库劫持本地提权"),
    "k8s-01": ("KIND 集群 + 恶意 WORKDIR 镜像", "runC CVE-2024-21626 工作目录逃逸读宿主机 flag"),
    "k8s-02": ("KIND + runC 符号链接镜像", "runC CVE-2025-31133 /dev/null 写 core_pattern"),
    "k8s-03": ("KIND + LSM 绕过镜像", "runC CVE-2025-52881 共享挂载 TOCTOU 逃逸"),
    "k8s-05": ("KIND + gitRepo Volume", "CVE-2024-10220 post-checkout hook 逃逸"),
    "k8s-06": ("KIND + 过宽 ClusterRole", "SA Token 跨命名空间读取 Secret"),
    "k8s-07": ("KIND + Kubelet 匿名 API", "未认证访问 Kubelet 列举/进入 Pod"),
    "k8s-08": ("KIND + etcd 未授权 (11379)", "etcdctl 直接读取集群 Secret 与状态"),
    "k8s-09": ("KIND + 私有镜像仓库", "向本地 Registry 推送后门镜像"),
    "k8s-10": ("KIND + Helm v2 Tiller", "未认证 gRPC 部署 chart 读集群 Secret"),
    "k8s-11": ("KIND + privileged Pod", "nsenter 进入宿主机命名空间读 flag"),
    "k8s-12": ("KIND + 可写 hostPath", "/var/log 符号链接访问宿主机文件"),
    "k8s-13": ("KIND 双命名空间", "泄露的 SA Token 跨 ns 读 Secret"),
    "k8s-14": ("KIND + CAP_SYS_ADMIN", "cgroup release_agent 宿主机命令执行"),
    "k8s-15": ("KIND + 可变镜像 Tag + 本地 Registry", "供应链替换 nginx 镜像读 ConfigMap"),
    "k8s-16": ("KIND + 挂载 containerd.sock", "ctr 启动特权容器挂载宿主机"),
    "k8s-17": ("KIND + 挂载 docker.sock", "docker run -v 宿主机路径读 flag"),
    "k8s-18": ("KIND 双命名空间", "泄露 cluster-admin SA Token 提权"),
    "k8s-19": ("KIND + hostPID + CAP_SYS_PTRACE", "gdb 注入 kubelet 进程写 flag"),
    "k8s-20": ("KIND + ingress-nginx :10443", "CVE-2025-1974 Admission Webhook RCE"),
    "k8s-21": ("KIND + ingress-nginx Lua snippet", "CVE-2021-25742 注解泄露 SA Token"),
    "k8s-22": ("KIND + ExternalIP 服务", "CVE-2020-8554 流量劫持截获凭据"),
    "k8s-23": ("KIND + hostPID Pod", "hostPID 访问宿主机 procfs 读 flag"),
    "k8s-24": ("KIND + kube-proxy route_localnet", "CVE-2020-8558 绕过 localhost 访问 Service"),
    "k8s-25": ("KIND + Mutating Webhook", "自动注入 sidecar 窃取 Pod SA Token"),
    "k8s-26": ("KIND + 被控 Node", "CVE-2020-8559 Node API 重定向 exec 进 Pod"),
    "k8s-27": ("KIND + NetworkPolicy", "伪造 tier=frontend 标签绕过网络策略"),
    "ad-01": ("Samba AD DC (north.sevenkingdoms.local)", "Kerberoasting 离线破解服务账号"),
    "ad-02": ("Samba AD DC", "AS-REP Roasting 破解无预认证用户"),
    "ad-05": ("Samba AD DC + 成员服务器", "Pass-the-Hash 横向移动"),
    "ad-09": ("Samba AD DC", "DCSync 导出域哈希"),
    "ad-10": ("Samba AD DC", "Golden Ticket 伪造 TGT 访问 DC"),
    "ad-13": ("Samba AD DC SYSVOL", "GPP cpassword 组策略凭据解密"),
    "ad-14": ("Samba AD DC", "Silver Ticket 伪造服务票据"),
    "ad-15": ("Samba AD DC", "ACL 写 SPN 后定向 Kerberoasting"),
    "ad-16": ("Samba AD DC", "约束委派 S4U2Self/S4U2Proxy 冒充管理员"),
    "ad-17": ("Samba AD DC", "RBCD 写 msDS-AllowedToAct 接管计算机"),
    "ad-18": ("Samba AD DC", "Shadow Credentials 写 KeyCredentialLink"),
    "ad-19": ("Samba AD DC", "WriteOwner 改 DACL 加入 IT_Admins"),
    "ad-20": ("Samba AD DC", "ForceChangePassword 重置 svc_support 密码"),
    "ad-21": ("Samba AD DC", "非约束委派发现与利用"),
}

WAF_EXPLOIT = {
    "web-01-waf": "同 WEB-01；入口经 ModSecurity WAF，需绕过规则后反序列化 RCE",
    "web-03-waf": "同 WEB-03；入口经 WAF，需绕过后未授权上传 Webshell",
}

CHAIN_DESC_ZH: dict[str, str] = {
    "asrep-to-golden": "域内从 AS-REP 到 Golden Ticket 的完整 Kerberos 提权链",
    "caps-to-cluster": "CAP_SYS_ADMIN 逃逸后 RBAC 读 Secret 再 etcd 接管集群",
    "container-to-admin": "RBAC 读 Secret → runC 逃逸 → etcd 集群控制",
    "cri-to-etcd": "CRI socket 逃逸 → 特权容器 → etcd 未授权",
    "docker-to-etcd": "Docker socket 逃逸 → 镜像投毒 → etcd 读 Secret",
    "externalip-to-secrets": "ExternalIP 劫持 → 跨 ns Token → 读 Secret",
    "gpp-to-dcsync": "GPP 凭据 → ACL Kerberoasting → DCSync 域妥协",
    "hostpath-to-daemonset": "hostPath → Kubelet → Registry → gitRepo 多阶段 K8s 链",
    "ingress-to-etcd": "IngressNightmare RCE → SA Token → RBAC → etcd",
    "kerb-to-deleg": "Kerberoasting → Silver Ticket → 约束委派",
    "kubelet-to-etcd": "Kubelet 匿名 → RBAC Secret → etcd",
    "mssql-to-da": "MSSQL Web SQLi → 链接服务器 → PTH → DCSync",
    "pg-sqli-to-node": "PG SQLi → DB RCE → hostPath → Kubelet",
    "privilege-to-etcd": "特权容器逃逸 → RBAC → etcd",
    "rbcd-to-dcsync": "RBCD 接管计算机 → S4U → DCSync",
    "redis-to-k8s": "Redis 写 SSH → 特权 Pod → RBAC → etcd",
    "sa-lateral-escape": "跨 ns SA Token → RBAC → runC 逃逸",
    "seccomp-to-escape": "hostPID 读宿主机 → CRI socket → 节点 flag",
    "shadow-to-golden": "Shadow Credentials → DCSync → Golden Ticket",
    "tomcat-race-to-etcd": "Tomcat 竞态 RCE → sudo 提权 → K8s 集群",
    "tomcat-to-k8s": "Tomcat 反序列化 → sudo 提权 → K8s 集群",
    "tomcat-to-rbcd": "Tomcat → Linux 提权 → AD 枚举 → RBCD → DCSync",
    "wordpress-to-shadow": "WordPress → MySQL → Linux → Shadow Creds → DCSync",
    "wp-lfi-to-cluster": "WordPress LFI RCE → RBAC → runC → etcd",
}

SORT_PREFIX = ("web", "db", "lnx", "k8s", "ad")


def esc_cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def truncate(text: str, max_len: int = 120) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def domain_label(key: str, stype: str) -> str:
    if key.startswith("web-"):
        return "Web"
    if key.startswith("db-"):
        return "Database"
    if key.startswith("lnx-"):
        return "Linux"
    if key.startswith("k8s-"):
        return "Kubernetes"
    if key.startswith("ad-"):
        return "Active Directory"
    if stype == "k8s":
        return "Kubernetes"
    if stype == "samba-ad":
        return "Active Directory"
    return "Docker"


def sort_key(key: str) -> tuple:
    prefix = key.split("-")[0]
    try:
        order = SORT_PREFIX.index(prefix)
    except ValueError:
        order = 99
    return (order, key)


def load_deployable_scenarios() -> list[dict]:
    if yaml is None:
        raise SystemExit("PyYAML required: pip install pyyaml")
    data = yaml.safe_load(SCENARIOS_YAML.read_text(encoding="utf-8"))
    rows = []
    for key, entry in data.get("scenarios", {}).items():
        rows.append(
            {
                "key": key,
                "id": entry.get("id", key.upper()),
                "name": entry.get("name", ""),
                "type": entry.get("type", ""),
                "difficulty": entry.get("difficulty", ""),
                "cve": entry.get("cve", ""),
                "defense": entry.get("defense"),
                "base_scenario": entry.get("base_scenario"),
            }
        )
    rows.sort(key=lambda r: sort_key(r["key"]))
    return rows


def parse_scenario_attack_paths(summary_text: str) -> dict[str, str]:
    paths: dict[str, str] = {}
    headers = list(SCENARIO_HEADER_RE.finditer(summary_text))
    for i, match in enumerate(headers):
        key = match.group(1).lower()  # web-01, k8s-01, web-01-waf
        start = match.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(summary_text)
        block = summary_text[start:end]
        ap = ATTACK_PATH_CODE_RE.search(block)
        if ap:
            raw = ap.group(1).strip()
            line = raw.split("\n")[0].strip()
            paths[key] = truncate(line)
            continue
        lst = ATTACK_PATH_LIST_RE.search(block)
        if lst:
            items = re.findall(r"^\d+\.\s+(.+)$", lst.group(1), re.MULTILINE)
            if items:
                paths[key] = truncate(" → ".join(items[:4]))
    return paths


def parse_chain_sections(summary_text: str) -> dict[str, dict]:
    chains: dict[str, dict] = {}
    headers = list(CHAIN_HEADER_RE.finditer(summary_text))
    for i, match in enumerate(headers):
        title = match.group(1).strip()
        slug = match.group(2).strip()
        start = match.start()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(summary_text)
        block = summary_text[start:end]
        info: dict[str, str] = {"title": title, "slug": slug}
        ov = CHAIN_OVERVIEW_RE.search(block)
        if ov:
            for line in ov.group(1).strip().splitlines():
                if "|" not in line:
                    continue
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2:
                    info[parts[0].lower().replace(" ", "_")] = parts[1]
        ap = ATTACK_PATH_CODE_RE.search(block)
        if ap:
            raw = ap.group(1).strip()
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            info["path"] = truncate(" ".join(lines))
        elif not info.get("path"):
            lst = ATTACK_PATH_LIST_RE.search(block)
            if lst:
                items = re.findall(r"^\d+\.\s+(.+)$", lst.group(1), re.MULTILINE)
                if items:
                    info["path"] = truncate(" → ".join(items[:5]))
        chains[slug] = info
    return chains


def cve_for_row(row: dict) -> str:
    cve = row.get("cve", "")
    if row.get("defense") == "waf" and "WAF" not in cve:
        return f"{cve} + ModSecurity WAF"
    return cve


def scenario_key_from_id(sid: str) -> str | None:
    """Map chain step scenario id to yaml key."""
    if not sid:
        return None
    m = re.match(r"^(web|db|lnx|k8s|ad)-(\d+)$", sid.strip(), re.I)
    if m:
        prefix, num = m.group(1).lower(), int(m.group(2))
        return f"{prefix}-{num:02d}"
    return None


def build_scenario_cve_index(rows: list[dict]) -> dict[str, str]:
    idx: dict[str, str] = {}
    for r in rows:
        idx[r["key"]] = cve_for_row(r)
        idx[r["id"].lower()] = cve_for_row(r)
    return idx


def chain_domain_label(data: dict, slug: str) -> str:
    domain = data.get("domain") or data.get("domains")
    if isinstance(domain, list):
        labels = []
        for d in domain:
            d = str(d).lower()
            if d in ("web",):
                labels.append("Web")
            elif d in ("linux", "lnx"):
                labels.append("Linux")
            elif d in ("ad", "active directory"):
                labels.append("AD")
            elif d in ("db", "database"):
                labels.append("DB")
            elif d in ("k8s", "kubernetes"):
                labels.append("K8s")
            else:
                labels.append(str(d))
        return "+".join(labels) if labels else "Cross"
    if domain:
        d = str(domain)
        if "Cross" in d or "+" in d:
            return d.replace("Web", "Web").replace("Linux", "Linux").replace("AD", "AD")
        if d.lower() in ("kubernetes", "k8s"):
            return "Kubernetes"
        if d.lower() in ("ad", "active directory"):
            return "Active Directory"
        return d
    if "tomcat" in slug or "wordpress" in slug or "mssql" in slug or "pg-sqli" in slug or "wp-lfi" in slug:
        if "da" in slug or "rbcd" in slug or "shadow" in slug or "gpp" in slug:
            return "Cross"
        if "k8s" in slug or "etcd" in slug or "cluster" in slug:
            return "Cross"
    if "etcd" in slug or "k8s" in slug or "kubelet" in slug or "ingress" in slug or "hostpath" in slug:
        return "Kubernetes"
    if "golden" in slug or "dcsync" in slug or "deleg" in slug or "rbcd" in slug or "shadow" in slug:
        return "Active Directory"
    return "Cross"


def collect_chain_scenarios(data: dict) -> list[str]:
    scenarios: list[str] = []
    if "nodes" in data:
        for n in data["nodes"]:
            s = n.get("scenario")
            if s:
                scenarios.append(str(s))
    if "steps_detail" in data:
        for s in data["steps_detail"]:
            sc = s.get("scenario", s.get("name"))
            if sc:
                scenarios.append(str(sc))
    return scenarios


def format_chain_scenarios(raw: list[str], id_by_key: dict[str, str]) -> str:
    parts: list[str] = []
    for s in raw:
        key = scenario_key_from_id(s)
        if key and key in id_by_key:
            parts.append(id_by_key[key])
        elif key and key in id_by_key:
            parts.append(id_by_key[key])
        else:
            parts.append(s)
    return ", ".join(parts)


def chain_cves(scenarios: list[str], cve_index: dict[str, str]) -> str:
    seen: list[str] = []
    for s in scenarios:
        key = scenario_key_from_id(s)
        if not key:
            continue
        cve = cve_index.get(key, "")
        if cve and cve not in seen:
            seen.append(cve)
    return "; ".join(seen) if seen else "（链内逻辑步骤，见组合场景 CVE）"


def build_chain_rows(
    cve_index: dict[str, str],
    chain_parsed: dict[str, dict],
    id_by_key: dict[str, str],
) -> list[dict]:
    rows = []
    for d in sorted(CHAINS_DIR.iterdir()):
        if not d.is_dir():
            continue
        cy = d / "chain.yaml"
        if not cy.exists():
            continue
        data = yaml.safe_load(cy.read_text(encoding="utf-8"))
        slug = d.name
        parsed = chain_parsed.get(slug, {})
        raw_scenarios = collect_chain_scenarios(data)
        chain_id = data.get("chain_id", slug)
        if isinstance(chain_id, str) and not chain_id.startswith("chain"):
            pass
        name = (data.get("name") or parsed.get("title") or slug).strip()
        if name.lower().startswith("inngress"):
            name = name.replace("Inngress", "Ingress", 1).replace("inngress", "Ingress", 1)
        difficulty = parsed.get("difficulty") or data.get("difficulty", "L3")
        domain = chain_domain_label(data, slug)
        desc = CHAIN_DESC_ZH.get(slug, "")
        if not desc and data.get("description"):
            desc = truncate(str(data.get("description")).replace("\n", " "), 100)
        path = parsed.get("path", "")
        rows.append(
            {
                "chain_id": chain_id,
                "slug": slug,
                "name": name,
                "domain": domain,
                "scenarios": format_chain_scenarios(raw_scenarios, id_by_key),
                "cves": chain_cves(raw_scenarios, cve_index),
                "desc": desc,
                "path": path,
                "difficulty": difficulty,
            }
        )
    rows.sort(key=lambda r: r["slug"])
    return rows


def stats_table(rows: list[dict], diff_key: str = "difficulty") -> str:
    counts = Counter(r[diff_key] for r in rows)
    lines = ["| 难度 | 数量 |", "|------|------|"]
    for level in ("L1", "L2", "L3"):
        lines.append(f"| {level} | {counts.get(level, 0)} |")
    return "\n".join(lines)


def main() -> None:
    if not SUMMARY_PATH.exists():
        raise SystemExit(f"Missing {SUMMARY_PATH}; run build_benchmark_summary.py first")

    summary_text = SUMMARY_PATH.read_text(encoding="utf-8")
    scenarios = load_deployable_scenarios()
    attack_paths = parse_scenario_attack_paths(summary_text)
    chain_parsed = parse_chain_sections(summary_text)
    cve_index = build_scenario_cve_index(scenarios)
    id_by_key = {r["key"]: r["id"] for r in scenarios}
    chains = build_chain_rows(cve_index, chain_parsed, id_by_key)

    parts: list[str] = [
        "# CVE Benchmark 场景一览表",
        "",
        "> 基于 [BENCHMARK_SUMMARY.md](BENCHMARK_SUMMARY.md) 的**可测试子集**；完整利用步骤见该文件。",
        "> 生成命令：`python benchmarks/cve_challenges/scripts/build_benchmark_overview.py`",
        "",
        "## 难度说明",
        "",
        "| 等级 | 含义 |",
        "|------|------|",
        "| **L1** | 单步或配置错误即可利用（如未授权 Redis、RBAC 过宽读 Secret） |",
        "| **L2** | 需约 2 步或中等技巧（多数 Web CVE、runC 逃逸、AD 委派/RBCD） |",
        "| **L3** | 多步、跨组件或高技巧（Golden Ticket、IngressNightmare、6 步跨域链） |",
        "",
        f"## 一、单点场景（{len(scenarios)}）",
        "",
        "| ID | 领域 | 基础服务/环境 | 漏洞/技术 | 场景说明 | 利用简介 | 难度 |",
        "|----|------|---------------|-----------|----------|----------|------|",
    ]

    current_group = ""
    for row in scenarios:
        key = row["key"]
        group = key.split("-")[0].upper()
        if group != current_group:
            current_group = group
            parts.append(f"| **{group}** | | | | | | |")

        service, desc_zh = SERVICE_AND_DESC.get(
            key,
            (row["name"], row["name"]),
        )
        exploit = WAF_EXPLOIT.get(key) or attack_paths.get(key, "见 BENCHMARK_SUMMARY 正文")
        parts.append(
            "| "
            + " | ".join(
                esc_cell(x)
                for x in [
                    row["id"],
                    domain_label(key, row["type"]),
                    service,
                    cve_for_row(row),
                    desc_zh,
                    exploit,
                    row["difficulty"],
                ]
            )
            + " |"
        )

    parts.extend(
        [
            "",
            f"## 二、攻击链场景（{len(chains)}）",
            "",
            "| 链目录 | 名称 | 主战场 | 组合单点场景 | 涉及漏洞/技术 | 场景说明 | 利用路径简介 | 难度 |",
            "|--------|------|--------|--------------|---------------|----------|--------------|------|",
        ]
    )
    for ch in chains:
        parts.append(
            "| "
            + " | ".join(
                esc_cell(x)
                for x in [
                    ch["slug"],
                    ch["name"],
                    ch["domain"],
                    ch["scenarios"],
                    ch["cves"],
                    ch["desc"],
                    ch["path"],
                    ch["difficulty"],
                ]
            )
            + " |"
        )

    parts.extend(
        [
            "",
            "## 统计摘要",
            "",
            "### 单点场景难度分布",
            "",
            stats_table(scenarios),
            "",
            "### 攻击链难度分布",
            "",
            stats_table(chains),
            "",
            "### 单点场景领域分布",
            "",
        ]
    )
    domain_counts = Counter(domain_label(r["key"], r["type"]) for r in scenarios)
    parts.append("| 领域 | 数量 |")
    parts.append("|------|------|")
    for dom in ("Web", "Database", "Linux", "Kubernetes", "Active Directory"):
        if domain_counts.get(dom):
            parts.append(f"| {dom} | {domain_counts[dom]} |")

    output = "\n".join(parts) + "\n"
    OUTPUT_PATH.write_text(output, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH}")
    print(f"  Scenarios: {len(scenarios)}")
    print(f"  Chains: {len(chains)}")


if __name__ == "__main__":
    main()
