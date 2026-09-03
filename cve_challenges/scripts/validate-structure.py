#!/usr/bin/env python3
"""Validate the benchmark registry, scenario documentation, and chain links."""

from __future__ import annotations

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "scripts" / "scenarios.yaml"
SCENARIOS_ROOT = ROOT / "scenarios"
INFRA_ROOT = ROOT / "infra"
CHAINS_ROOT = ROOT / "chains"
SCENARIO_ID = re.compile(r"^(?:web|db|cloud|k8s)-\d+$", re.IGNORECASE)
TABLE_SPLIT = re.compile(r"(?<!\\)\|")
PORT_MIN = 10000
PORT_MAX = 14000


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def compose_files() -> list[Path]:
    return sorted(
        list(SCENARIOS_ROOT.glob("*/*/docker-compose.yml"))
        + list(SCENARIOS_ROOT.glob("*/*/docker-compose.yaml"))
        + list(SCENARIOS_ROOT.glob("*/*/registry-compose.yml"))
        + list(SCENARIOS_ROOT.glob("*/*/registry-compose.yaml"))
        + list(CHAINS_ROOT.glob("*/docker-compose.yml"))
        + list(CHAINS_ROOT.glob("*/docker-compose.yaml"))
    )


def kind_config_paths() -> list[Path]:
    return sorted(SCENARIOS_ROOT.glob("*/k8s-*/kind-config.yaml"))


def check_ports_in_range(errors: list[str], ports: set[int], source: str) -> None:
    for port in sorted(ports):
        if not PORT_MIN <= port <= PORT_MAX:
            fail(
                errors,
                f"{source}: published/exposed port {port} is outside required range {PORT_MIN}-{PORT_MAX}",
            )


def section_count(text: str, heading: str) -> int:
    return len(re.findall(rf"^## {re.escape(heading)}\s*$", text, re.MULTILINE))


def section_text(text: str, heading: str) -> str | None:
    match = re.search(
        rf"^## {re.escape(heading)}\s*$\n(.*?)(?=^##\s|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1) if match else None


def table_rows(text: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|") or re.fullmatch(r"\s*\|?\s*:?-{3,}:?\s*\|.*", line):
            continue
        cells = [cell.strip() for cell in TABLE_SPLIT.split(line.strip())]
        if len(cells) < 4 or cells[0] or cells[-1]:
            continue
        key, value = cells[1], cells[2]
        if key and value and key not in {"字段", "规划维度"}:
            rows[key] = value.replace(r"\|", "|").replace(r"\\", "\\")
    return rows


def expected_metadata(entry: dict[str, object]) -> dict[str, str]:
    delivery = "Docker Compose" if entry["type"] == "docker" else "KIND / Kubernetes"
    endpoint = (
        f"localhost:{entry['port']}"
        if entry.get("port")
        else "KIND 集群内入口（无固定宿主端口）"
    )
    return {
        "ID": str(entry["id"]),
        "名称": str(entry["name"]),
        "技术/CVE": str(entry["cve"]),
        "难度": str(entry["difficulty"]),
        "交付方式": delivery,
        "入口": endpoint,
    }


def validate_guide(errors: list[str], scenario_id: str, entry: dict[str, object], text: str) -> None:
    for heading in ("场景信息", "此场景利用了哪些知识"):
        count = section_count(text, heading)
        if count != 1:
            fail(errors, f"{scenario_id}: GUIDE.md must contain exactly one ## {heading} section (found {count})")

    metadata_text = section_text(text, "场景信息")
    if metadata_text is not None:
        actual = table_rows(metadata_text)
        for key, expected in expected_metadata(entry).items():
            if actual.get(key) != expected:
                fail(
                    errors,
                    f"{scenario_id}: GUIDE.md metadata {key!r} is {actual.get(key)!r}, expected {expected!r}",
                )

    knowledge_text = section_text(text, "此场景利用了哪些知识")
    if knowledge_text is not None:
        rows = table_rows(knowledge_text)
        for label in ("环境与访问", "侦察与前置条件", "核心漏洞与利用", "权限、横向或影响", "验证"):
            if not rows.get(label):
                fail(errors, f"{scenario_id}: GUIDE.md knowledge table missing {label}")


def published_ports(config: dict[str, object]) -> set[int]:
    ports: set[int] = set()
    items = config.get("ports", [])
    if not isinstance(items, list):
        items = [items]
    for item in items:
        if isinstance(item, dict):
            published = item.get("published")
            if published is not None and str(published).isdigit():
                ports.add(int(published))
            continue
        value = str(item).split("/", 1)[0]
        parts = value.split(":")
        if len(parts) < 2:
            continue
        host = parts[-2]
        if host.isdigit():
            ports.add(int(host))
            continue
        match = re.fullmatch(r"(\d+)-(\d+)", host)
        if match:
            ports.update(range(int(match.group(1)), int(match.group(2)) + 1))
    return ports


def value_text(value: object) -> str:
    if isinstance(value, list):
        return " ".join(value_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(value_text(item) for item in value.values())
    return str(value)


def has_host_proxy_port(config: dict[str, object], port: int) -> bool:
    if config.get("network_mode") != "host":
        return False
    command = value_text(config.get("command", ""))
    return re.search(rf"(?<!\d){port}(?!\d)", command) is not None


def validates_registered_port(entry: dict[str, object], compose: Path) -> bool:
    if not entry.get("port"):
        return True
    services = (yaml.safe_load(compose.read_text(encoding="utf-8")) or {}).get("services", {})
    attacker = services.get("attacker")
    if isinstance(attacker, dict) and published_ports(attacker):
        return False
    registered_port = int(entry["port"])
    public_service = entry.get("public_service")
    if public_service is None:
        return any(
            isinstance(config, dict)
            and (registered_port in published_ports(config) or has_host_proxy_port(config, registered_port))
            for config in services.values()
        )
    if not isinstance(public_service, str) or public_service == "attacker" or public_service not in services:
        return False
    return any(
        isinstance(config, dict)
        and service_name == public_service
        and (registered_port in published_ports(config) or has_host_proxy_port(config, registered_port))
        for service_name, config in services.items()
    )


def main() -> None:
    errors: list[str] = []
    data = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    scenarios: dict[str, dict[str, object]] = data["scenarios"]

    if not SCENARIOS_ROOT.is_dir():
        fail(errors, "missing scenarios/ root")
    if not INFRA_ROOT.is_dir():
        fail(errors, "missing infra/ root")
    for retired in (ROOT / "docker", ROOT / "k8s", ROOT / "docs"):
        if retired.exists():
            fail(errors, f"retired directory still exists: {retired.relative_to(ROOT)}")

    for scenario_id, entry in scenarios.items():
        if entry.get("port") and not PORT_MIN <= int(entry["port"]) <= PORT_MAX:
            fail(
                errors,
                f"{scenario_id}: registered port {entry['port']} is outside required range {PORT_MIN}-{PORT_MAX}",
            )
        path = Path(str(entry["path"]))
        if path.parts[0] != "scenarios":
            fail(errors, f"{scenario_id}: path must start with scenarios/: {path}")
        scenario_dir = ROOT / path
        if not scenario_dir.is_dir():
            fail(errors, f"{scenario_id}: missing scenario directory: {path}")
            continue

        guide = scenario_dir / "GUIDE.md"
        guide_text = guide.read_text(encoding="utf-8") if guide.is_file() else ""
        if not guide_text.strip():
            fail(errors, f"{scenario_id}: missing or empty GUIDE.md")
        else:
            for section in ("场景概述", "利用", "Flag"):
                if section not in guide_text:
                    fail(errors, f"{scenario_id}: GUIDE.md missing {section}")
            validate_guide(errors, scenario_id, entry, guide_text)

        if entry["type"] == "docker":
            compose = next(
                ((scenario_dir / name) for name in ("docker-compose.yml", "docker-compose.yaml") if (scenario_dir / name).is_file()),
                None,
            )
            if compose is None:
                fail(errors, f"{scenario_id}: Docker scenario has no Compose file")
            elif not validates_registered_port(entry, compose):
                fail(errors, f"{scenario_id}: registered port {entry['port']} is not published by its Compose deployment")
        if entry["type"] == "k8s" and not (scenario_dir / "deploy.sh").is_file():
            fail(errors, f"{scenario_id}: Kubernetes scenario has no deploy.sh")

    for config_file in kind_config_paths():
        try:
            config = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            fail(errors, f"{config_file.relative_to(ROOT)}: invalid YAML: {exc}")
            continue
        exposed: set[int] = set()
        for node in config.get("nodes", []) or []:
            for mapping in node.get("extraPortMappings", []) or []:
                host_port = mapping.get("hostPort")
                if host_port is not None:
                    exposed.add(int(host_port))
        check_ports_in_range(errors, exposed, config_file.relative_to(ROOT).as_posix())

    for chain_file in sorted(CHAINS_ROOT.glob("*/chain.yaml")):
        chain = yaml.safe_load(chain_file.read_text(encoding="utf-8")) or {}
        nodes = chain.get("nodes") or chain.get("steps_detail") or []
        steps = chain.get("steps")
        if isinstance(steps, int) and steps != len(nodes):
            fail(errors, f"{chain_file.parent.name}: steps does not match node count")
        for node in nodes:
            if not isinstance(node, dict):
                continue
            scenario_id = node.get("scenario")
            if (
                scenario_id
                and SCENARIO_ID.fullmatch(str(scenario_id))
                and str(scenario_id).lower() not in scenarios
            ):
                fail(errors, f"{chain_file.parent.name}: unknown scenario {scenario_id}")

        domains = chain.get("domains", [])
        if isinstance(domains, str):
            domains = [domains]
        if "cloud" in domains and chain.get("chain_id") != "Chain-32":
            runtime = chain.get("runtime") or {}
            if runtime.get("console") is not True:
                fail(errors, f"{chain_file.parent.name}: cloud chain must enable runtime console")
            if runtime.get("artifact_api") != "/artifacts/<key>":
                fail(errors, f"{chain_file.parent.name}: cloud chain artifact API contract missing")
            artifacts = runtime.get("artifacts") or []
            if isinstance(steps, int) and len(artifacts) != max(0, steps - 1):
                fail(errors, f"{chain_file.parent.name}: artifact count must equal steps - 1")
            for artifact in artifacts:
                if not isinstance(artifact, dict) or not all(key in artifact for key in ("key", "from_step", "to_step", "format")):
                    fail(errors, f"{chain_file.parent.name}: artifact must declare key/from_step/to_step/format")
            deploy = (chain_file.parent / "deploy.sh").read_text(encoding="utf-8") if (chain_file.parent / "deploy.sh").is_file() else ""
            if "_runtime/deploy_chain.py" not in deploy:
                fail(errors, f"{chain_file.parent.name}: cloud chain must use shared runtime deployer")

    for compose in compose_files():
        try:
            services = (yaml.safe_load(compose.read_text(encoding="utf-8")) or {}).get("services", {})
        except yaml.YAMLError as exc:
            fail(errors, f"{compose.relative_to(ROOT)}: invalid YAML: {exc}")
            continue
        exposed: set[int] = set()
        for service, config in services.items():
            if isinstance(config, dict):
                exposed.update(published_ports(config))
            build = config.get("build") if isinstance(config, dict) else None
            context = build.get("context") if isinstance(build, dict) else build
            if isinstance(context, str) and "${" not in context:
                target = (compose.parent / context).resolve()
                if not target.is_dir():
                    fail(errors, f"{compose.relative_to(ROOT)}:{service}: missing build context {context}")
        check_ports_in_range(errors, exposed, compose.relative_to(ROOT).as_posix())

    if errors:
        print("Structure validation failed:")
        for error in errors:
            print(f"- {error}")
        raise SystemExit(1)
    print(
        f"Structure valid: {len(scenarios)} scenarios, "
        f"{len(list(CHAINS_ROOT.glob('*/chain.yaml')))} chains, "
        f"{len(compose_files())} Compose files"
    )


if __name__ == "__main__":
    main()
