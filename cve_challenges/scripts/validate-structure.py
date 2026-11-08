#!/usr/bin/env python3
"""Validate the benchmark registry, scenario documentation, and chain links."""

from __future__ import annotations

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "scripts" / "scenarios.yaml"
CATEGORIES = ROOT / "scripts" / "scenario-categories.yaml"
SCENARIOS_ROOT = ROOT / "scenarios"
INFRA_ROOT = ROOT / "infra"
CHAINS_ROOT = ROOT / "chains"
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
    return sorted(SCENARIOS_ROOT.glob("k8s/*/kind-config.yaml"))


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


def validate_private_cloud_taxonomy(
    errors: list[str],
    scenarios: dict[str, dict[str, object]],
    taxonomy: dict[str, object],
) -> None:
    private_ids = {sid for sid in scenarios if sid.startswith("prv-")}
    expected_ids = {f"prv-{index:02d}" for index in range(1, 61)}
    if private_ids != expected_ids:
        fail(errors, "scenario-categories.yaml: private-cloud registry must contain prv-01..prv-60 exactly once")

    if taxonomy.get("taxonomy_version") != 3:
        fail(errors, "scenario-categories.yaml: taxonomy_version must be 3")
    prefix = taxonomy.get("scenario_prefix") or {}
    if not isinstance(prefix, dict) or prefix.get("stable") != "prv" or prefix.get("uppercase") != "PRV":
        fail(errors, "scenario-categories.yaml: scenario_prefix must declare prv/PRV")

    boundaries = taxonomy.get("first_level_boundaries") or {}
    primary = taxonomy.get("primary_scenarios") or {}
    reserve = taxonomy.get("reserve_scenarios") or {}
    migration = (taxonomy.get("migration") or {}).get("current_to_v3") or {}
    if not isinstance(boundaries, dict) or len(boundaries) != 5:
        fail(errors, "scenario-categories.yaml: first_level_boundaries must contain exactly five boundaries")
        return
    expected_primary = {f"prv-{index:02d}" for index in range(1, 41)}
    expected_reserve = {f"prv-{index:02d}" for index in range(41, 61)}
    if not isinstance(primary, dict) or set(primary) != expected_primary:
        fail(errors, "scenario-categories.yaml: primary_scenarios must contain prv-01..prv-40 exactly once")
    if not isinstance(reserve, dict) or set(reserve) != expected_reserve:
        fail(errors, "scenario-categories.yaml: reserve_scenarios must contain prv-41..prv-60 exactly once")
    expected_migration = {
        "k8s-01": "prv-01", "k8s-02": "prv-04", "k8s-03": "prv-02",
        "k8s-04": "prv-03", "k8s-05": "prv-05", "k8s-06": "prv-06",
        "k8s-07": "prv-07", "k8s-08": "prv-08", "k8s-09": "prv-09",
        "k8s-10": "prv-10", "k8s-11": "prv-11", "k8s-12": "prv-26",
        "k8s-13": "prv-12", "k8s-14": "prv-13", "k8s-15": "prv-14",
        "k8s-16": "prv-22", "k8s-17": "prv-24", "k8s-18": "prv-16",
        "k8s-19": "prv-15", "k8s-20": "prv-17", "k8s-21": "prv-20",
        "k8s-22": "prv-18", "k8s-23": "prv-27", "k8s-24": "prv-19",
        "k8s-25": "prv-21", "k8s-26": "prv-23", "k8s-27": "prv-25",
        "k8s-28": "prv-28", "k8s-29": "prv-30", "k8s-30": "prv-31",
        "k8s-31": "prv-32", "k8s-32": "prv-29", "k8s-33": "prv-33",
        "k8s-34": "prv-34", "k8s-35": "prv-35", "k8s-36": "prv-36",
        "k8s-37": "prv-37", "k8s-38": "prv-38", "k8s-39": "prv-39",
        "k8s-40": "prv-40", "k8s-41": "prv-41", "k8s-42": "prv-42",
        "k8s-43": "prv-43", "k8s-44": "prv-44", "k8s-45": "prv-45",
        "k8s-46": "prv-46", "k8s-47": "prv-47", "k8s-48": "prv-48",
        "k8s-49": "prv-49", "k8s-50": "prv-50", "k8s-51": "prv-51",
        "k8s-52": "prv-52", "k8s-53": "prv-53", "k8s-54": "prv-54",
        "k8s-55": "prv-55", "k8s-56": "prv-56", "k8s-57": "prv-57",
        "k8s-58": "prv-58", "k8s-59": "prv-59", "k8s-60": "prv-60",
    }
    if migration != expected_migration:
        fail(errors, "scenario-categories.yaml: migration.current_to_v3 must bijectively map k8s-01..60 to prv-01..60")

    boundary_ids: list[str] = []
    mechanism_parent: dict[str, str] = {}
    mechanism_scenarios: dict[str, list[str]] = {}
    for boundary_code, boundary in boundaries.items():
        if not isinstance(boundary, dict):
            fail(errors, f"scenario-categories.yaml: malformed boundary {boundary_code!r}")
            continue
        for field in ("code", "label_zh", "label_en", "scenario_range", "mechanisms"):
            if not boundary.get(field):
                fail(errors, f"scenario-categories.yaml: boundary {boundary_code} missing {field}")
        scenario_range = boundary.get("scenario_range") or {}
        try:
            start = int(scenario_range["start"])
            end = int(scenario_range["end"])
        except (KeyError, TypeError, ValueError):
            fail(errors, f"scenario-categories.yaml: boundary {boundary_code} has invalid scenario_range")
            continue
        boundary_ids.extend(f"prv-{index:02d}" for index in range(start, end + 1))
        mechanisms = boundary.get("mechanisms") or {}
        if not isinstance(mechanisms, dict):
            fail(errors, f"scenario-categories.yaml: boundary {boundary_code} mechanisms must be a mapping")
            continue
        for mechanism_code, mechanism in mechanisms.items():
            if mechanism_code in mechanism_parent:
                fail(errors, f"scenario-categories.yaml: duplicate mechanism {mechanism_code}")
            mechanism_parent[mechanism_code] = boundary_code
            if not isinstance(mechanism, dict) or not mechanism.get("label_zh") or not mechanism.get("label_en"):
                fail(errors, f"scenario-categories.yaml: malformed mechanism {mechanism_code}")
                continue
            ids = [str(sid) for sid in mechanism.get("scenarios") or []]
            mechanism_scenarios[mechanism_code] = ids
            for sid in ids:
                if sid not in expected_primary or int(sid.split("-")[1]) not in range(start, end + 1):
                    fail(errors, f"scenario-categories.yaml: {sid} is outside parent boundary {boundary_code}")
                attribution = primary.get(sid)
                if attribution != {"first_level": boundary_code, "mechanism": mechanism_code}:
                    fail(errors, f"scenario-categories.yaml: inconsistent primary attribution for {sid}")

    if boundary_ids != [f"prv-{index:02d}" for index in range(1, 41)]:
        fail(errors, "scenario-categories.yaml: boundary ranges must cover prv-01..prv-40 in order without overlap")
    if len(mechanism_parent) != 24:
        fail(errors, "scenario-categories.yaml: taxonomy must define exactly 24 secondary mechanisms")
    flattened_mechanisms = [
        sid
        for mechanism in mechanism_scenarios.values()
        for sid in mechanism
    ]
    duplicates = {sid for sid in flattened_mechanisms if flattened_mechanisms.count(sid) > 1}
    if duplicates:
        fail(errors, f"scenario-categories.yaml: scenarios assigned to multiple mechanisms: {sorted(duplicates)}")
    if set(flattened_mechanisms) != expected_primary:
        fail(errors, "scenario-categories.yaml: mechanisms must cover prv-01..prv-40 exactly once")
    for sid, attribution in primary.items():
        if not isinstance(attribution, dict):
            fail(errors, f"scenario-categories.yaml: malformed primary attribution for {sid}")
            continue
        mechanism = str(attribution.get("mechanism"))
        if mechanism_parent.get(mechanism) != attribution.get("first_level"):
            fail(errors, f"scenario-categories.yaml: {sid} points to a mechanism under the wrong boundary")


def main() -> None:
    errors: list[str] = []
    data = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    scenarios: dict[str, dict[str, object]] = data["scenarios"]
    category_data = yaml.safe_load(CATEGORIES.read_text(encoding="utf-8"))
    validate_private_cloud_taxonomy(errors, scenarios, category_data)

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
        nodes = chain.get("nodes") or []
        steps = chain.get("steps")
        if isinstance(steps, int) and steps != len(nodes):
            fail(errors, f"{chain_file.parent.name}: steps does not match node count")
        for node in nodes:
            if not isinstance(node, dict):
                continue
            scenario_id = node.get("scenario")
            if scenario_id is not None and str(scenario_id).lower() not in scenarios:
                fail(
                    errors,
                    f"{chain_file.parent.name}: step {node.get('step')} references unknown scenario {scenario_id!r}",
                )
            if not scenario_id and not node.get("name"):
                fail(errors, f"{chain_file.parent.name}: step {node.get('step')} has neither a scenario nor a name")

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
