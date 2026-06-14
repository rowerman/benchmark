#!/usr/bin/env python3
"""Merge deployable CVE benchmark exploitation docs into BENCHMARK_SUMMARY.md."""

from __future__ import annotations

import re
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

SCRIPT_DIR = Path(__file__).resolve().parent
CVE_ROOT = SCRIPT_DIR.parent
DOCS_DIR = CVE_ROOT / "docs"
REPO_ROOT = CVE_ROOT.parent
OUTPUT_PATH = REPO_ROOT / "BENCHMARK_SUMMARY.md"
SCENARIOS_YAML = SCRIPT_DIR / "scenarios.yaml"
CHAINS_DIR = CVE_ROOT / "chains"

# --- Ordering: scenarios grouped by attack type within each domain ---

WEB_ORDER = [
    "web-03", "web-04",   # RCE — file upload
    "web-01", "web-02",   # RCE — deserialization
    "web-12",             # RCE — template injection (SSTI)
    "web-07", "web-08", "web-09",  # SQL injection
    "web-06",             # LFI
    "web-10", "web-11",   # SSRF
    "web-13", "web-14",   # XXE
    "web-05", "web-15", "web-17",  # auth bypass (JWT / PHP deser)
    "web-16",             # API attack (GraphQL)
    "web-18",             # client-side injection (XSS)
]

DB_ORDER = [
    "db-05", "db-06",     # no-auth access
    "db-01", "db-02",     # weak credentials
    "db-03", "db-04",     # protocol-level attacks
    "db-07", "db-08",     # script / view injection
    "db-09",              # NoSQL injection
]

LNX_ORDER = [
    "lnx-06", "lnx-07",   # SUID abuse
    "lnx-08",             # container escape (docker.sock)
    "lnx-09",             # capability abuse
    "lnx-10",             # cron hijack
    "lnx-11",             # kernel CVE (Polkit)
    "lnx-12",             # environment injection (LD_PRELOAD)
    "lnx-13",             # filesystem permission abuse
    "lnx-05",             # chroot escape
]

DEF_ORDER = [
    "def-01",             # WAF bypass
    "def-02",             # log tampering
    "def-03", "def-05",   # process hiding / LoTL
    "def-04",             # anti-forensics (timestomp)
]

NET_ORDER = [
    "net-01",             # ARP spoofing (L2)
    "net-03",             # container sniffing (app-layer)
    "net-02",             # DNS exfiltration (covert channel)
]

CI_ORDER = [
    "ci-01",              # poisoned pipeline
    "ci-02", "ci-03",     # credential leaks
    "ci-04",              # unprotected webhook
    "ci-05",              # build arg injection
]

K8S_ORDER = [
    # container escape
    "k8s-01", "k8s-02", "k8s-03", "k8s-11", "k8s-14", "k8s-19",
    # host resource abuse
    "k8s-12", "k8s-16", "k8s-17", "k8s-23", "k8s-05",
    # RBAC privilege escalation
    "k8s-06", "k8s-10", "k8s-13", "k8s-18",
    # cluster storage
    "k8s-08", "k8s-09",
    # network attacks
    "k8s-22", "k8s-24", "k8s-26", "k8s-27", "k8s-21",
    # admission control
    "k8s-20", "k8s-25",
    # node scheduling
    "k8s-28", "k8s-29", "k8s-30",
    # supply chain
    "k8s-15",
    # node auth
    "k8s-07",
]

AD_ORDER = [
    # credential theft
    "ad-01", "ad-02", "ad-13", "ad-15",
    # credential lateral movement
    "ad-05",
    # ticket forgery
    "ad-10", "ad-14",
    # delegation abuse
    "ad-16", "ad-17", "ad-21",
    # ACL abuse
    "ad-19", "ad-20", "ad-23",
    # certificate / key attacks
    "ad-18",
    # DCSync
    "ad-09",
    # cross-forest
    "ad-22",
]

LKX_ORDER = [
    "lkx-01", "lkx-02",   # kernel module exploits
    "lkx-03", "lkx-04",   # eBPF abuse
    "lkx-05",             # kernel CVE (conditional)
]

# Chain ordering by domain group, then by step count within each group
CHAIN_ORDER_BY_DOMAIN = [
    # pure K8s (11)
    "container-to-admin", "caps-to-cluster", "cri-to-etcd", "docker-to-etcd",
    "externalip-to-secrets", "hostpath-to-daemonset", "ingress-to-etcd",
    "kubelet-to-etcd", "privilege-to-etcd", "sa-lateral-escape", "seccomp-to-escape",
    # pure AD (5)
    "asrep-to-golden", "gpp-to-dcsync", "kerb-to-deleg", "rbcd-to-dcsync", "shadow-to-golden",
    # pure Cloud (Phase 4 + Phase 6)
    "ssrf-to-cross-account", "lambda-to-cross-account", "ci-to-oidc",
    "db-to-cross-account", "s3-to-cf", "gateway-to-deputy",
    "notebook-to-scp", "ssrf-to-oidc", "db-to-passrole", "cf-to-scp",
    "loggap-to-s3-stealth", "svctag-to-imds-to-deputy",
    # Web + Cloud (Phase 6)
    "web-to-db-to-cross-account",
    # Web + DB (2)
    "xxe-to-es", "php-to-mongo",
    # DB + K8s (1)
    "redis-to-k8s",
    # Web + K8s (2)
    "wp-lfi-to-cluster", "tomcat-to-k8s",
    # Web + DB + K8s (1)
    "pg-sqli-to-node",
    # Web + Linux + K8s (2)
    "tomcat-race-to-etcd", "graphql-to-root",
    # DB + Linux + K8s (1)
    "db-to-cluster",
    # Web + Linux + AD (3)
    "web-to-admin", "tomcat-to-rbcd", "cross-forest-ad",
    # multi-domain (2)
    "mssql-to-da", "wordpress-to-shadow",
]

CLOUD_ORDER = [
    # Data Plane (Phase 2)
    "cloud-01",             # SSRF → IMDS
    "cloud-04",             # Lambda → PassRole
    "cloud-06",             # DB → IMDS
    "cloud-05",             # CF Injection
    "cloud-07",             # S3 Monopoly
    "cloud-08",             # CI/CD Poisoning
    "cloud-09",             # Notebook Escape
    "cloud-10",             # Gateway Smuggling
    # Control Plane (Phase 3)
    "cloud-11",             # OIDC Federation
    "cloud-12",             # Cross-Account Trust
    "cloud-13",             # Golden SAML
    "cloud-14",             # PassRole Abuse
    "cloud-15",             # SCP Bypass
    "cloud-16",             # Logging Gap
    "cloud-17",             # Confused Deputy
    "cloud-18",             # Service Tag Spoofing
    # Multi-Tenant (Phase 5 + Phase 6)
    "cloud-19",             # Multi-Tenant K8s
    "cloud-20",             # Shared Metadata Proxy
    "cloud-21",             # Global S3 Squatting
    "cloud-22",             # Shared AI Inference
]

ALL_DOCKER_ORDER = WEB_ORDER + DB_ORDER + LNX_ORDER + CLOUD_ORDER + DEF_ORDER + NET_ORDER + CI_ORDER + LKX_ORDER

DOCKER_DOC = DOCS_DIR / "scenarios" / "docker-scenarios-exploitation.md"


def demote_headings(text: str, levels: int = 1) -> str:
    if levels <= 0:
        return text
    def repl(line: str) -> str:
        m = re.match(r"^(#{1,6})(\s)", line)
        if not m:
            return line
        hashes = m.group(1)
        new_len = min(len(hashes) + levels, 6)
        return "#" * new_len + line[len(hashes):]
    return "\n".join(repl(line) for line in text.splitlines())


def slugify(text: str) -> str:
    s = text.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    return re.sub(r"-+", "-", s).strip("-")


def k8s_doc_path(scenario_id: str) -> Path | None:
    folder = DOCS_DIR / "scenarios" / "k8s"
    matches = sorted(folder.glob(f"{scenario_id}-*-exploitation.md"))
    return matches[0] if matches else None


def ad_doc_path(scenario_id: str) -> Path | None:
    folder = DOCS_DIR / "scenarios" / "ad"
    matches = sorted(folder.glob(f"{scenario_id}-*-exploitation.md"))
    return matches[0] if matches else None


def chain_doc_paths() -> list[Path]:
    """Return chain doc paths ordered by domain group (CHAIN_ORDER_BY_DOMAIN)."""
    doc_dir = DOCS_DIR / "chains"
    path_by_name = {}
    for p in sorted(doc_dir.glob("*-exploitation.md")):
        name = p.stem.replace("-exploitation", "")
        path_by_name[name] = p

    result = []
    for name in CHAIN_ORDER_BY_DOMAIN:
        if name in path_by_name:
            result.append(path_by_name.pop(name))
    # append any remaining chains not in the ordered list
    for name in sorted(path_by_name):
        result.append(path_by_name[name])
    return result


def load_scenarios_registry() -> list[dict]:
    if yaml is None:
        raise SystemExit("PyYAML required: pip install pyyaml")
    data = yaml.safe_load(SCENARIOS_YAML.read_text(encoding="utf-8"))
    rows = []
    for key, entry in sorted(data.get("scenarios", {}).items(), key=lambda x: x[0]):
        rows.append({
            "key": key, "id": entry.get("id", key.upper()),
            "name": entry.get("name", ""), "type": entry.get("type", ""),
            "difficulty": entry.get("difficulty", ""), "cve": entry.get("cve", ""),
            "port": entry.get("port", ""), "path": entry.get("path", ""),
        })
    return rows


def parse_docker_sections(text: str) -> dict[str, str]:
    """Split docker-scenarios-exploitation.md into per-scenario sections."""
    sections: dict[str, str] = {}
    pattern = re.compile(r"^#{2,3}\s+(WEB-\d+|DB-\d+|LNX-\d+|CLOUD-\d+|DEF-\d+|NET-\d+|CI-\d+|LKX-\d+):", re.MULTILINE)
    parts = pattern.split(text)
    # parts[0] = content before first scenario heading
    # parts[1] = id, parts[2] = content, parts[3] = id, parts[4] = content, ...
    if len(parts) < 2:
        return sections
    for i in range(1, len(parts), 2):
        sec_id = parts[i].strip()
        sec_content = parts[i + 1] if i + 1 < len(parts) else ""
        # find the end of this section (next "---" or end)
        sections[sec_id.lower()] = f"## {sec_id}:{sec_content}"
    return sections


def append_section(parts: list[str], source_rel: str, content: str, extra_comment: str = "") -> None:
    comment = f"<!-- source: {source_rel} -->"
    if extra_comment:
        comment += f"\n<!-- {extra_comment} -->"
    parts.append(comment)
    parts.append("")
    parts.append(demote_headings(content.rstrip(), levels=1))
    parts.append("")
    parts.append("---")
    parts.append("")


def build_toc(included_sources: list[tuple[str, str]], n_chains: int) -> str:
    lines = ["## 目录", ""]
    lines.append("- [一、单点场景](#一单点场景)")
    lines.append("  - [1.1 Docker：Web / 数据库 / Linux / DEF / NET / CI / LKX](#11-dockerweb--数据库--linux--def--net--ci--lkx)")
    lines.append("  - [1.2 Kubernetes 单点场景](#12-kubernetes-单点场景)")
    lines.append("  - [1.3 Active Directory 单点场景](#13-active-directory-单点场景)")
    lines.append(f"- [二、攻击链场景（{n_chains}）](#chains-section)")
    for _, anchor in included_sources:
        if anchor.startswith("chain-"):
            lines.append(f"  - [{anchor[6:]}](#{anchor})")
    lines.append("- [附录 A：可部署场景注册表](#附录-a可部署场景注册表)")
    lines.append("- [附录 B：源文件索引](#附录-b源文件索引)")
    lines.append("")
    return "\n".join(lines)


def build_appendix_a(rows: list[dict]) -> str:
    lines = ["## 附录 A：可部署场景注册表", ""]
    lines.append("来源：`benchmarks/cve_challenges/scripts/scenarios.yaml`。")
    lines.append("")
    lines.append("| Key | ID | 名称 | 类型 | 难度 | CVE/技术 | 端口 | 路径 |")
    lines.append("|-----|-----|------|------|------|----------|------|------|")
    for r in rows:
        port = r["port"] if r["port"] else "—"
        lines.append(f"| {r['key']} | {r['id']} | {r['name']} | {r['type']} | "
                     f"{r['difficulty']} | {r['cve']} | {port} | `{r['path']}` |")
    lines.append("")
    return "\n".join(lines)


def build_appendix_b(index: list[tuple[str, str]]) -> str:
    lines = ["## 附录 B：源文件索引", ""]
    lines.append(f"共 **{len(index)}** 个源文件纳入本汇总。")
    lines.append("")
    lines.append("| 源文件 | 汇总章节 |")
    lines.append("|--------|----------|")
    for rel, section in index:
        lines.append(f"| `{rel}` | {section} |")
    lines.append("")
    return "\n".join(lines)


def render_chain_pivot(chain_data: dict) -> str:
    """Render chain logic and pivot table from chain.yaml data.
    Handles both 'nodes' (compact format) and 'steps_detail' (verbose format).
    """
    nodes = chain_data.get("nodes") or chain_data.get("steps_detail")
    if not nodes:
        return ""

    lines = ["", "### 攻击路径衔接逻辑", ""]

    # Build map: step_num -> description (may come from 'description' or 'name'+'description')
    step_info: dict[int, dict] = {}
    for n in nodes:
        sn = n.get("step", 0)
        step_info[sn] = {
            "desc": n.get("description", "") or n.get("name", ""),
            "hint": n.get("next_hint", ""),
        }

    if len(step_info) < 2:
        return ""

    lines.append("| 步骤 | 输出 / 发现 | → 如何作用于下一步 |")
    lines.append("|:---:|------|------|")
    for i in sorted(step_info):
        cur = step_info[i]
        nxt = step_info.get(i + 1, {})
        hint = cur.get("hint", "")
        # If no explicit hint, derive from next step's description
        if not hint and nxt:
            hint = "利用此处获得的信息进入下一步: " + nxt.get("desc", "")[:120]
        if i < max(step_info):
            lines.append(f"| {i}→{i+1} | {cur['desc'][:150]} | {hint[:200]} |")
    lines.append("")
    return "\n".join(lines)


def load_chain_yaml(chain_name: str) -> dict | None:
    """Load chain.yaml, returning parsed data or None."""
    if yaml is None:
        return None
    yaml_path = CHAINS_DIR / chain_name / "chain.yaml"
    if not yaml_path.exists():
        return None
    try:
        return yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> None:
    parts: list[str] = []
    index: list[tuple[str, str]] = []
    chain_anchors: list[tuple[str, str]] = []

    parts.append("# CVE Benchmark 利用说明总览（BENCHMARK_SUMMARY）")
    parts.append("")
    parts.append("> **范围**：仅包含当前环境可部署、可端到端测试的场景与攻击链（Docker / KIND / Samba AD）。")
    parts.append("> **源目录**：[benchmarks/cve_challenges/docs/](benchmarks/cve_challenges/docs/)")
    parts.append("> **生成**：运行 `python benchmarks/cve_challenges/scripts/build_benchmark_summary.py` 可复现。")

    for path in chain_doc_paths():
        chain_name = path.stem.replace("-exploitation", "")
        chain_anchors.append((chain_name, f"chain-{slugify(chain_name)}"))

    chain_paths_for_toc = chain_doc_paths()
    parts.append(build_toc(chain_anchors, len(chain_paths_for_toc)))

    parts.append("## 一、单点场景")
    parts.append("")

    # 1.1 Docker — output in ordered sequence
    parts.append("### 1.1 Docker：Web / 数据库 / Linux / Cloud / DEF / NET / CI / LKX")
    parts.append("")
    docker_text = DOCKER_DOC.read_text(encoding="utf-8")
    docker_sections = parse_docker_sections(docker_text)
    rel = "benchmarks/cve_challenges/docs/scenarios/docker-scenarios-exploitation.md"
    section_count = 0
    for key in ALL_DOCKER_ORDER:
        if key in docker_sections:
            append_section(parts, rel, docker_sections[key])
            index.append((rel, f"1.1 Docker / {key.upper()}"))
            section_count += 1
    # append any remaining sections not in ALL_DOCKER_ORDER
    for key in sorted(docker_sections):
        if key not in ALL_DOCKER_ORDER:
            append_section(parts, rel, docker_sections[key])
            index.append((rel, f"1.1 Docker / {key.upper()}"))
            section_count += 1

    # 1.2 K8s
    k8s_count = 0
    parts.append("### 1.2 Kubernetes 单点场景")
    parts.append("")
    for kid in K8S_ORDER:
        doc = k8s_doc_path(kid)
        if doc is None:
            continue
        rel = f"benchmarks/cve_challenges/docs/scenarios/k8s/{doc.name}"
        append_section(parts, rel, doc.read_text(encoding="utf-8"))
        index.append((rel, f"1.2 K8s / {kid.upper()}"))
        k8s_count += 1

    # 1.3 AD
    ad_count = 0
    parts.append("### 1.3 Active Directory 单点场景")
    parts.append("")
    for aid in AD_ORDER:
        doc = ad_doc_path(aid)
        if doc is None:
            continue
        rel = f"benchmarks/cve_challenges/docs/scenarios/ad/{doc.name}"
        append_section(parts, rel, doc.read_text(encoding="utf-8"))
        index.append((rel, f"1.3 AD / {aid.upper()}"))
        ad_count += 1

    # II Chains
    parts.append('<a id="chains-section"></a>')
    parts.append("")
    parts.append(f"## 二、攻击链场景（{len(chain_paths_for_toc)}）")
    parts.append("")
    for path in chain_paths_for_toc:
        chain_name = path.stem.replace("-exploitation", "")
        rel = f"benchmarks/cve_challenges/docs/chains/{path.name}"
        yaml_path = CHAINS_DIR / chain_name / "chain.yaml"
        extra = f"chain.yaml: benchmarks/cve_challenges/chains/{chain_name}/chain.yaml"
        if not yaml_path.exists():
            extra = ""

        content = path.read_text(encoding="utf-8")

        # Inject pivot table from chain.yaml if available
        chain_data = load_chain_yaml(chain_name)
        if chain_data and (chain_data.get("nodes") or chain_data.get("steps_detail")):
            pivot_text = render_chain_pivot(chain_data)
            # insert after the first "## Step-by-Step" or "## Attack Path Summary"
            if "## Attack Path Summary" in content or "## Step-by-Step" in content:
                # insert before "## Step-by-Step Exploitation" or "## Prerequisites"
                m = re.search(r"\n(?=## Step-by-Step|## Prerequisites)", content)
                if m:
                    idx = m.start()
                    content = content[:idx] + f"\n{pivot_text}\n" + content[idx:]

        anchor = f"chain-{slugify(chain_name)}"
        parts.append(f"<a id=\"{anchor}\"></a>")
        parts.append("")
        append_section(parts, rel, content, extra_comment=extra)
        index.append((rel, f"二、攻击链 / {chain_name}"))

    registry = load_scenarios_registry()
    parts.append(build_appendix_a(registry))
    parts.append(build_appendix_b(index))

    output = "\n".join(parts)
    output = output.rstrip() + "\n"
    OUTPUT_PATH.write_text(output, encoding="utf-8")

    total_scenarios = section_count + k8s_count + ad_count
    print(f"Wrote {OUTPUT_PATH}")
    print(f"  Docker scenarios: {section_count}")
    print(f"  K8s scenarios: {k8s_count}")
    print(f"  AD scenarios: {ad_count}")
    print(f"  Total scenarios: {total_scenarios}")
    print(f"  Chains: {len(chain_paths_for_toc)}")
    print(f"  Source files merged: {len(index)}")
    print(f"  Lines: {len(output.splitlines())}")
    print(f"To generate Chinese version: python {SCRIPT_DIR / 'translate_benchmark_summary.py'}")


if __name__ == "__main__":
    main()
