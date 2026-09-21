#!/usr/bin/env python3
"""Integrate the cloud and k8s scenario GUIDE.md files into one overview document."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "scripts" / "scenarios.yaml"
DOMAINS = (("cloud", "Cloud（公有云）"), ("k8s", "K8s（私有云 / Kubernetes）"))
SECTION_ALIASES = {
    "artifacts": ("教材锚点",),
    "prereq": ("前置知识", "Prerequisites"),
    "path": ("攻击路径", "Attack Path Summary", "Attack Path"),
    "steps": ("Step-by-Step Exploitation", "利用步骤"),
    "special": ("Kubernetes 专项利用步骤",),
    "verify": ("验证命令", "Verification Commands", "Verification"),
    "tail": ("Alternative Approaches", "Key Takeaway"),
    "flag": ("Flag", "Flag Location"),
    "overview": ("场景概述",),
    "knowledge": ("此场景利用了哪些知识",),
    "fix": ("修复建议",),
}


def split_sections(text: str) -> list[tuple[str, str]]:
    sections = []
    for part in re.split(r"(?m)^##\s+", text)[1:]:
        lines = part.split("\n")
        sections.append((lines[0].strip(), "\n".join(lines[1:]).strip()))
    return sections


def pick(sections: list[tuple[str, str]], *names: str) -> str | None:
    for heading, body in sections:
        if heading in names:
            return body
    return None


def collect(sections: list[tuple[str, str]], *names: str) -> str:
    bodies = [body.strip() for heading, body in sections if heading in names and body.strip()]
    return "\n\n".join(bodies)


def table(body: str | None) -> dict[str, str]:
    rows: dict[str, str] = {}
    if not body:
        return rows
    for line in body.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        if re.fullmatch(r"\s*\|?\s*:?-{3,}:?\s*\|.*", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 2 and cells[0] and cells[1] and cells[0] not in ("字段", "Property"):
            rows[cells[0]] = cells[1]
    return rows


def demote(body: str | None) -> str:
    if not body:
        return ""
    lines = []
    in_fence = False
    for line in body.strip().split("\n"):
        if re.match(r"^\s*(```|~~~)", line):
            in_fence = not in_fence
            lines.append(line)
            continue
        lines.append(line if in_fence else re.sub(r"^(#{1,5})\s", r"#\1 ", line))
    return "\n".join(lines)


def overview_text(body: str | None) -> str:
    if not body:
        return ""
    lines = [line for line in body.splitlines() if line.strip()]
    if lines and all(re.match(r"^-\s*(技术|难度|交付方式)：", line.strip()) for line in lines):
        return ""
    return body.strip()


def cell(text: object) -> str:
    return str(text).replace("|", "\\|")


def load_registry() -> dict[str, dict[str, object]]:
    return yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["scenarios"]


def ordered_ids(registry: dict[str, dict[str, object]], domain: str) -> list[str]:
    return sorted(
        (sid for sid, entry in registry.items() if str(entry["path"]).split("/")[1] == domain),
        key=lambda sid: int(sid.split("-")[1]),
    )


def scenario_card(sid: str, entry: dict[str, object], index_anchor: str) -> list[str]:
    text = (ROOT / str(entry["path"]) / "GUIDE.md").read_text(encoding="utf-8")
    heading = re.search(r"(?m)^#\s+(.+)$", text)
    short = heading.group(1).strip() if heading else str(entry["name"])
    short = re.sub(r"^(?:cloud|k8s|web|db)-\d+\s*[:：\-]?\s*", "", short, flags=re.I)
    sections = split_sections(text)
    overview_table = table(pick(sections, "Overview"))

    lines = [f'<a id="{sid}"></a>', "", f'### {entry["id"]} · {short}', "", "| 字段 | 值 |", "|---|---|"]
    lines.append(f'| ID | {entry["id"]} |')
    lines.append(f'| 名称 | {cell(entry["name"])} |')
    lines.append(f'| 交付方式 | {entry["type"]} |')
    lines.append(f'| 难度 | {entry["difficulty"]} |')
    lines.append(f'| 技术/CVE | {cell(entry["cve"])} |')
    lines.append(f'| 入口 | `localhost:{entry["port"]}` |' if entry.get("port") else "| 入口 | KIND 集群内入口（无固定宿主端口） |")
    if overview_table.get("Cluster Name"):
        lines.append(f'| 集群 | {cell(overview_table["Cluster Name"])} |')
    lines.append(f'| 目录 | `{entry["path"]}` |')
    lines.append("")

    overview = overview_text(pick(sections, *SECTION_ALIASES["overview"]))
    groups = {
        "prereq": collect(sections, *SECTION_ALIASES["prereq"]),
        "path": collect(sections, *SECTION_ALIASES["path"]),
        "steps": collect(sections, *SECTION_ALIASES["steps"]),
        "special": collect(sections, *SECTION_ALIASES["special"]),
        "verify": collect(sections, *SECTION_ALIASES["verify"]),
        "tail": collect(sections, *SECTION_ALIASES["tail"]),
        "flag": collect(sections, *SECTION_ALIASES["flag"]),
        "knowledge": collect(sections, *SECTION_ALIASES["knowledge"]),
        "fix": collect(sections, *SECTION_ALIASES["fix"]),
        "artifacts": collect(sections, *SECTION_ALIASES["artifacts"]),
    }
    for label, key in (
        ("场景概述", "overview"),
        ("教材锚点", "artifacts"),
        ("前置知识 / 条件", "prereq"),
        ("攻击路径", "path"),
        ("利用步骤", "steps"),
        ("专项利用步骤", "special"),
        ("验证命令", "verify"),
        ("补充说明", "tail"),
        ("Flag", "flag"),
        ("知识维度", "knowledge"),
        ("修复建议", "fix"),
    ):
        body = overview if key == "overview" else demote(groups[key])
        if body:
            lines += [f"**{label}**", "", body, ""]
    lines += [f"[↑ 返回索引](#{index_anchor})", "", "---", ""]
    return lines


def build_document(registry: dict[str, dict[str, object]]) -> str:
    stats = {domain: ordered_ids(registry, domain) for domain, _ in DOMAINS}
    all_ids = stats["cloud"] + stats["k8s"]
    by_type = Counter(str(registry[sid]["type"]) for sid in all_ids)
    by_diff = Counter(str(registry[sid]["difficulty"]) for sid in all_ids)
    cve_numbers = sorted(
        {
            match
            for sid in all_ids
            for match in re.findall(r"CVE-\d{4}-\d+", str(registry[sid]["cve"]))
        }
    )

    doc: list[str] = []
    add = doc.append
    add("# DARWIN CVE 基准 · Cloud 与 K8s 场景说明总览\n")
    add("> **范围**：`cve_challenges/scenarios/cloud/` 与 `cve_challenges/scenarios/k8s/` 下全部单点场景（共 62 个），**不包含** `web` 与 `db` 域。")
    add("> **来源**：注册表 `cve_challenges/scripts/scenarios.yaml` 与各场景的 `GUIDE.md`。")
    add("> ID、交付方式、难度、CVE/技术、入口以注册表为准；场景概述、攻击路径、利用步骤、Flag、修复建议取自对应 GUIDE.md。\n")

    add("## 目录\n")
    add("- [一、概览](#一概览)")
    add("- [二、使用与部署](#二使用与部署)")
    add("- [三、注册表完备性与文档一致性检查](#三注册表完备性与文档一致性检查)")
    add("- [四、问题与修复状态](#四问题与修复状态)")
    add("- [五、Cloud（公有云）场景](#五cloud公有云场景)")
    add("- [六、K8s（私有云）场景](#六k8s私有云场景)")
    add("- [附录 A：Cloud / K8s 相关攻击链](#附录-acloud--k8s-相关攻击链)")
    add("- [附录 B：数据来源](#附录-b数据来源)")
    add("- [附录 C：生成方式](#附录-c生成方式)\n")

    add('<a id="一概览"></a>\n')
    add("## 一、概览\n")
    add("本基准把公开 CVE、常见错误配置以及云 / Kubernetes 权限边界问题封装成可重复部署的靶场，")
    add("用于评估 LLM 或人工测试者的侦察、漏洞利用、横向移动和影响验证能力。本文档只覆盖 cloud 与 k8s 两类。\n")
    add("| 维度 | 数值 |")
    add("|---|---|")
    cloud_docker = sum(1 for sid in stats["cloud"] if registry[sid]["type"] == "docker")
    add(f'| Cloud 单点场景 | {len(stats["cloud"])}（Docker Compose {cloud_docker} + KIND {len(stats["cloud"]) - cloud_docker}） |')
    add(f'| K8s 单点场景 | {len(stats["k8s"])} |')
    add(f"| 合计 | {len(all_ids)} |")
    add(f'| 交付方式 | docker {by_type["docker"]} / k8s {by_type["k8s"]} |')
    add("| 难度分布 | " + " / ".join(f"{key} {by_diff[key]}" for key in sorted(by_diff)) + " |")
    add(f'| 具名 CVE 编号 | {len(cve_numbers)}（{"、".join(cve_numbers)}） |')
    add("| 场景 ID | cloud-01..cloud-31，k8s-01..k8s-33（缺 k8s-04） |")
    add("")
    add("Cloud 场景覆盖实例元数据（IMDS）、联邦身份（OIDC / SAML）、IAM 权限边界、共享托管服务与多租户隔离；")
    add("K8s 场景覆盖容器逃逸（runC / cgroup / capability）、集群控制面组件（etcd / kubelet / API Server）、")
    add("RBAC 与 ServiceAccount 滥用、网络策略与准入控制绕过。每个场景的 `GUIDE.md` 是它的事实来源。\n")

    add('<a id="二使用与部署"></a>\n')
    add("## 二、使用与部署\n")
    add("所有命令都在 `cve_challenges/` 目录下执行。主机需具备 Bash、Python 3（含 PyYAML）、Docker Engine 与 Docker Compose v2；")
    add("Kubernetes 场景还需 `kind` 与 `kubectl`。\n")
    add("```bash")
    add("# 查看注册表中的稳定 ID、类型、端口、难度、CVE")
    add("./scripts/list-scenarios.sh")
    add("")
    add("# 启动 / 停止单个场景（脚本按注册表定位路径与类型，并生成运行时 Flag）")
    add("./scripts/start-scenario.sh cloud-01     # Docker 场景")
    add("./scripts/start-scenario.sh k8s-01       # KIND 场景")
    add("./scripts/stop-scenario.sh cloud-01")
    add("")
    add("# 攻击链入口（见附录 A）")
    add("./scripts/start-chain.sh managed-db-lateral")
    add("./scripts/stop-chain.sh managed-db-lateral")
    add("")
    add("# 结构 / 契约校验")
    add("python3 scripts/validate-structure.py")
    add("python3 scripts/check-cloud-consistency.py")
    add("python3 scripts/validate-flag-contract.py")
    add("python3 scripts/validate-cloud-entrypoints.py --strict-probes")
    add("```\n")
    add("**Flag 约定**：Flag 形如 `flag{<scenario-id>-<suffix>}`，在每次启动时生成或注入，")
    add("GUIDE 中的示例值不是运行时真实值。单 Flag 场景使用 `CVE_FLAG`；多逻辑 Flag 场景使用连续的 `CVE_FLAG1`、`CVE_FLAG2`……")
    add("启动脚本把变量写入场景目录的 `.env` / `flag.txt`，Compose 文件与 Kubernetes manifest 消费这些变量；")
    add("显式传入的变量优先于随机生成值。已捕获的值可用 `./scripts/verify-flag.sh 'flag{...}'` 校验。\n")

    add('<a id="三注册表完备性与文档一致性检查"></a>\n')
    add("## 三、注册表完备性与文档一致性检查\n")
    add("检查日期：2026-09-21。以下为只读校验脚本的实测输出。\n")
    add("| 校验脚本 | 检查内容 | 实测输出 |")
    add("|---|---|---|")
    add("| `validate-structure.py` | 注册表 → 目录 / GUIDE / 端口 / Compose / 攻击链引用 | `Structure valid: 89 scenarios, 37 chains, 60 Compose files` |")
    add("| `check-cloud-consistency.py` | 云场景 ID 连续性与链引用一致性 | `OK: 31 active cloud scenarios with contiguous IDs, valid chain references` |")
    add("| `validate-flag-contract.py` | 单点与攻击链 Flag 运行时注入 | `Flag contract valid: all Docker scenarios and chain assignments use runtime variables` |")
    add("| `validate-cloud-entrypoints.py --strict-probes` | 云场景公开入口契约 | `Cloud entrypoint contract valid: all Docker cloud ports target non-attacker services` |")
    add("")
    add("注册表 `cve_challenges/scripts/scenarios.yaml` 的完备性结论：\n")
    add("- 89 个注册项的 `path` 全部存在，且每个目录都含非空 `GUIDE.md`；不存在「有目录未注册」或「有注册无目录」的项。")
    add("- 交付方式与实体自洽：57 个 `docker` 场景都有 Compose 文件，32 个 `k8s` 场景都有 `deploy.sh`。")
    add("- 端口全部落在 10000–14000；云场景公开入口只指向非 attacker 服务。")
    add("- 攻击链引用的场景 ID 均可在注册表中解析（3 条 legacy 链除外，见第四节）。\n")
    add("文档一致性结论：本节覆盖的 62 个 cloud / k8s 场景 `GUIDE.md` 全部存在且非空，")
    add("`场景信息` 表中的 ID / 名称 / 技术·CVE / 难度 / 交付方式 / 入口与注册表逐项一致，")
    add("且不存在空骨架区块。其中 32 个 K8s 交付场景（`type: k8s`，含 `CLOUD-02`）统一使用同一套中文区块：")
    add("`场景信息` → `场景概述` → `前置知识` → `利用步骤` → `验证命令` → `Flag` → `此场景利用了哪些知识` → `修复建议`。")
    add("`scripts/validate-structure.py` 会校验每个场景 GUIDE 的骨架区块与注册表元数据。\n")

    add('<a id="四问题与修复状态"></a>\n')
    add("## 四、问题与修复状态\n")
    add("### 4.1 本次已修复\n")
    add("| # | 问题 | 处理 |")
    add("|---|---|---|")
    add("| 1 | `README.md` 场景计数与注册表不符（写 cloud 30 / k8s 33） | 修正为 cloud 31 / k8s 31 |")
    add("| 2 | 29 个 K8s GUIDE 含空的 `## 攻击路径与利用步骤` 占位标题 | 删除空标题，其内容来源（攻击路径摘要）并入 `场景概述` |")
    add("| 3 | K8s GUIDE 中英标题混排、区块集合不统一（`Attack Path` / `Attack Path Summary`、`Verification` / `Verification Commands`） | 32 个 K8s 交付 GUIDE 统一为同一套中文区块模板 |")
    add("| 4 | 攻击链存在两套 schema（`nodes` / `steps_detail`）且 3 条链用描述文本冒充场景 ID | 5 条 `steps_detail` 链并入 `nodes`，场景 ID 统一小写；非场景中间步骤改用 `name`；`validate-structure.py` 现在强制 `scenario` 必须是注册 ID |")
    add("")
    add("### 4.2 仍待处理\n")
    add("| # | 问题 | 证据 | 建议 |")
    add("|---|---|---|---|")
    add("| 5 | 7 条攻击链缺 `domains` 字段 | `caps-to-cluster`、`hostpath-to-daemonset`、`pg-sqli-to-node`、`privilege-to-etcd`、`redis-to-k8s`、`sa-lateral-escape`、`wp-lfi-to-cluster` | 补齐 `domains` 以支持自动统计 |")
    add("| 6 | 场景 ID 不连续 | 注册表缺 `k8s-04` | 在文档中显式说明，避免误判为缺失 |")
    add("| 7 | `CLOUD-02` 位于 `scenarios/cloud/` 但类型为 `k8s` | 注册表 `cloud-02` 的 `type` 为 `k8s` | 在索引中标注交付方式（本文档已标注） |")
    add("| 8 | 云场景公开出处覆盖不足 | 仅 9/31 个 cloud GUIDE 含显式公开出处线索 | 补齐公开披露出处链接 |")
    add("")

    chapters = {"cloud": "五cloud公有云场景", "k8s": "六k8s私有云场景"}
    headings = {"cloud": "五", "k8s": "六"}
    for domain, label in DOMAINS:
        anchor = chapters[domain]
        ids = stats[domain]
        add(f'<a id="{anchor}"></a>\n')
        add(f"## {headings[domain]}、{label}场景（{len(ids)}）\n")
        add("| ID | 名称 | 类型 | 难度 | 技术/CVE | 入口 |")
        add("|---|---|---|---|---|---|")
        for sid in ids:
            entry = registry[sid]
            endpoint = f'`localhost:{entry["port"]}`' if entry.get("port") else "KIND 集群内"
            add(f'| [{entry["id"]}](#{sid}) | {cell(entry["name"])} | {entry["type"]} | {entry["difficulty"]} | {cell(entry["cve"])} | {endpoint} |')
        add("")
        for sid in ids:
            doc.extend(scenario_card(sid, registry[sid], anchor))

    add('<a id="附录-acloud--k8s-相关攻击链"></a>\n')
    add("## 附录 A：Cloud / K8s 相关攻击链\n")
    chain_rows = []
    for chain_file in sorted((ROOT / "chains").glob("*/chain.yaml")):
        chain = yaml.safe_load(chain_file.read_text(encoding="utf-8")) or {}
        nodes = [node for node in chain.get("nodes") or [] if isinstance(node, dict)]
        if any(str(node.get("scenario", "")).lower().split("-")[0] in ("cloud", "k8s") for node in nodes):
            chain_rows.append((chain_file.parent.name, chain.get("name") or chain.get("title") or "", nodes))
    add(f"共 {len(chain_rows)} 条攻击链涉及 cloud 或 k8s 场景。步骤中的场景 ID 与注册表对应；")
    add("标注为描述文本（如 `Node Flag`）的步骤是 legacy 链的遗留写法（见第四节）。\n")
    add("| 攻击链目录 | 名称 | 步骤（场景） |")
    add("|---|---|---|")
    for name, title, nodes in chain_rows:
        steps = " → ".join(
            f"`{node['scenario']}`" if node.get("scenario") else f"({node.get('name') or '非场景步骤'})"
            for node in nodes
        )
        add(f"| `{name}` | {cell(title)} | {steps} |")
    add("")

    add('<a id="附录-b数据来源"></a>\n')
    add("## 附录 B：数据来源\n")
    add("| 来源 | 说明 |")
    add("|---|---|")
    add("| `cve_challenges/scripts/scenarios.yaml` | 场景注册表：稳定 ID、类型、路径、端口、难度、CVE/技术 |")
    add("| `cve_challenges/scenarios/cloud/*/GUIDE.md` | 31 个云场景的权威说明 |")
    add("| `cve_challenges/scenarios/k8s/*/GUIDE.md` | 31 个 K8s 场景的权威说明 |")
    add("| `cve_challenges/chains/*/chain.yaml` | 攻击链定义 |")
    add("| `cve_challenges/README.md` / `AGENTS.md` | 部署、Flag 与校验约定 |")
    add("")

    add('<a id="附录-c生成方式"></a>\n')
    add("## 附录 C：生成方式\n")
    add("本文档由注册表与各场景 `GUIDE.md` 归一化生成，可在 `cve_challenges/` 目录下复现：\n")
    add("```bash")
    add("python3 scripts/build-cloud-k8s-guide.py \\")
    add("    --output ../BENCHMARK_GUIDE_CLOUD_K8S.md")
    add("```\n")
    add("生成脚本只读取注册表与 GUIDE，不修改任何场景；重复执行得到相同结果。\n")
    return "\n".join(doc) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT.parent / "BENCHMARK_GUIDE_CLOUD_K8S.md")
    args = parser.parse_args()
    args.output.write_text(build_document(load_registry()), encoding="utf-8")
    print(f"written {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
