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


K8S_ORDER = [f"k8s-{i:02d}" for i in list(range(1, 4)) + list(range(5, 28))]

AD_ORDER = [
    "ad-01",
    "ad-02",
    "ad-05",
    "ad-09",
    "ad-10",
    "ad-13",
    "ad-14",
    "ad-15",
    "ad-16",
    "ad-17",
    "ad-18",
    "ad-19",
    "ad-20",
    "ad-21",
]

DOCKER_DOC = DOCS_DIR / "scenarios" / "docker-scenarios-exploitation.md"


def demote_headings(text: str, levels: int = 1) -> str:
    """Increase markdown heading level by `levels` (e.g. # -> ##)."""
    if levels <= 0:
        return text

    def repl(line: str) -> str:
        m = re.match(r"^(#{1,6})(\s)", line)
        if not m:
            return line
        hashes = m.group(1)
        new_len = min(len(hashes) + levels, 6)
        return "#" * new_len + line[len(hashes) :]

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
    chain_docs = sorted((DOCS_DIR / "chains").glob("*-exploitation.md"))
    result = []
    for path in chain_docs:
        result.append(path)
    return result


def load_scenarios_registry() -> list[dict]:
    if yaml is None:
        raise SystemExit("PyYAML required: pip install pyyaml")
    data = yaml.safe_load(SCENARIOS_YAML.read_text(encoding="utf-8"))
    rows = []
    for key, entry in sorted(data.get("scenarios", {}).items(), key=lambda x: x[0]):
        rows.append(
            {
                "key": key,
                "id": entry.get("id", key.upper()),
                "name": entry.get("name", ""),
                "type": entry.get("type", ""),
                "difficulty": entry.get("difficulty", ""),
                "cve": entry.get("cve", ""),
                "port": entry.get("port", ""),
                "path": entry.get("path", ""),
            }
        )
    return rows


def append_section(
    parts: list[str],
    source_rel: str,
    content: str,
    extra_comment: str = "",
) -> None:
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
    lines.append("  - [1.1 Docker：Web / 数据库 / Linux（LNX-05）](#11-dockerweb--数据库--linuxlnx-05)")
    lines.append("  - [1.2 Kubernetes 单点场景（26）](#12-kubernetes-单点场景26)")
    lines.append("  - [1.3 Active Directory 单点场景（14）](#13-active-directory-单点场景14)")
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
    lines.append("来源：`benchmarks/cve_challenges/scripts/scenarios.yaml`（已过滤阻塞项）。")
    lines.append("")
    lines.append("| Key | ID | 名称 | 类型 | 难度 | CVE/技术 | 端口 | 路径 |")
    lines.append("|-----|-----|------|------|------|----------|------|------|")
    for r in rows:
        port = r["port"] if r["port"] else "—"
        lines.append(
            f"| {r['key']} | {r['id']} | {r['name']} | {r['type']} | "
            f"{r['difficulty']} | {r['cve']} | {port} | `{r['path']}` |"
        )
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


def main() -> None:
    parts: list[str] = []
    index: list[tuple[str, str]] = []
    chain_anchors: list[tuple[str, str]] = []

    parts.append("# CVE Benchmark 利用说明总览（BENCHMARK_SUMMARY）")
    parts.append("")
    parts.append(
        "> **范围**：仅包含当前环境可部署、可端到端测试的场景与攻击链（Docker / KIND / Samba AD）。"
    )
    parts.append(
        "> **源目录**：[benchmarks/cve_challenges/docs/](benchmarks/cve_challenges/docs/)"
    )
    parts.append(
        "> **生成**：运行 `python benchmarks/cve_challenges/scripts/build_benchmark_summary.py` 可复现。"
    )
    # Collect chain names for TOC (before body)
    for path in chain_doc_paths():
        chain_name = path.stem.replace("-exploitation", "")
        chain_anchors.append((chain_name, f"chain-{slugify(chain_name)}"))

    chain_paths_for_toc = chain_doc_paths()
    parts.append(build_toc(chain_anchors, len(chain_paths_for_toc)))

    parts.append("## 一、单点场景")
    parts.append("")

    # 1.1 Docker
    parts.append("### 1.1 Docker：Web / 数据库 / Linux（LNX-05）")
    parts.append("")
    rel = "benchmarks/cve_challenges/docs/scenarios/docker-scenarios-exploitation.md"
    docker_text = DOCKER_DOC.read_text(encoding="utf-8")
    append_section(parts, rel, docker_text)
    index.append((rel, "1.1 Docker"))

    # 1.2 K8s
    parts.append("### 1.2 Kubernetes 单点场景（26）")
    parts.append("")
    for kid in K8S_ORDER:
        doc = k8s_doc_path(kid)
        if doc is None:
            raise FileNotFoundError(f"Missing K8s doc for {kid}")
        rel = f"benchmarks/cve_challenges/docs/scenarios/k8s/{doc.name}"
        append_section(parts, rel, doc.read_text(encoding="utf-8"))
        index.append((rel, f"1.2 K8s / {kid.upper()}"))

    # 1.3 AD
    parts.append("### 1.3 Active Directory 单点场景（14）")
    parts.append("")
    for aid in AD_ORDER:
        doc = ad_doc_path(aid)
        if doc is None:
            raise FileNotFoundError(f"Missing AD doc for {aid}")
        rel = f"benchmarks/cve_challenges/docs/scenarios/ad/{doc.name}"
        append_section(parts, rel, doc.read_text(encoding="utf-8"))
        index.append((rel, f"1.3 AD / {aid.upper()}"))

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
        anchor = f"chain-{slugify(chain_name)}"
        parts.append(f"<a id=\"{anchor}\"></a>")
        parts.append("")
        append_section(parts, rel, path.read_text(encoding="utf-8"), extra_comment=extra)
        index.append((rel, f"二、攻击链 / {chain_name}"))

    registry = load_scenarios_registry()
    parts.append(build_appendix_a(registry))
    parts.append(build_appendix_b(index))

    output = "\n".join(parts)
    # Trim trailing separators noise
    output = output.rstrip() + "\n"
    OUTPUT_PATH.write_text(output, encoding="utf-8")

    print(f"Wrote {OUTPUT_PATH}")
    print(f"  Source files merged: {len(index)}")
    print(f"  Lines: {len(output.splitlines())}")


if __name__ == "__main__":
    main()
