#!/usr/bin/env python3
"""Deploy a cloud chain behind one console and one shared network."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(__file__).resolve().parent
STATE_ROOT = Path(tempfile.gettempdir()) / "cve-cloud-chains"

import yaml

sys.path.insert(0, str(ROOT / "scripts"))
from flag_contract import scenario_flag_count


def run(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(args, text=True, env=env).strip()


def compose_file(path: Path) -> Path | None:
    for name in ("docker-compose.yml", "docker-compose.yaml"):
        candidate = path / name
        if candidate.is_file():
            return candidate
    return None


def services(compose: Path) -> list[str]:
    data = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
    return list((data.get("services") or {}).keys())


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print("usage: deploy_chain.py <chain-dir> <chain-number> [--dry-run]", file=sys.stderr)
        return 2
    chain_dir = Path(sys.argv[1]).resolve()
    chain_number = int(sys.argv[2])
    dry_run = len(sys.argv) == 4 and sys.argv[3] == "--dry-run"
    chain = yaml.safe_load((chain_dir / "chain.yaml").read_text(encoding="utf-8")) or {}
    registry = yaml.safe_load((ROOT / "scripts" / "scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]
    network = f"chain-{chain_number}-net"
    if dry_run:
        nodes = chain.get("nodes") or chain.get("steps_detail") or []
        for index, node in enumerate(nodes, 1):
            scenario = str(node.get("scenario", "")).lower()
            entry = registry.get(scenario)
            if not entry:
                raise RuntimeError(f"{scenario}: scenario is not registered")
            scenario_dir = ROOT / str(entry["path"])
            compose = compose_file(scenario_dir)
            if compose is None:
                raise RuntimeError(f"{scenario}: no Docker Compose deployment")
            print(f"step {index}: {scenario} -> {compose.relative_to(ROOT)}")
        print(f"console: http://localhost:{11600 + chain_number}")
        return 0
    state_dir = STATE_ROOT / str(chain_number)
    if state_dir.exists():
        shutil.rmtree(state_dir)
    state_dir.mkdir(parents=True)
    subprocess.run(["docker", "network", "rm", network], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run("docker", "network", "create", network)

    projects: list[dict[str, str]] = []
    step_urls: dict[str, str] = {}
    nodes = chain.get("nodes") or chain.get("steps_detail") or []
    flag_index = 1
    for index, node in enumerate(nodes, 1):
        scenario = str(node.get("scenario", "")).lower()
        entry = registry.get(scenario)
        if not entry:
            continue
        scenario_dir = ROOT / str(entry["path"])
        compose = compose_file(scenario_dir)
        if compose is None:
            raise RuntimeError(f"{scenario}: no Docker Compose deployment")
        local_flag_count = scenario_flag_count(scenario)
        compose_env = os.environ.copy()
        for local_index in range(1, local_flag_count + 1):
            global_name = f"CVE_FLAG{flag_index + local_index - 1}"
            local_name = f"CVE_FLAG{local_index}"
            value = compose_env.get(global_name)
            if not value:
                raise RuntimeError(f"missing {global_name} for chain step {index}")
            compose_env[local_name] = value
            if local_index == 1:
                compose_env["CVE_FLAG"] = value
        flag_index += local_flag_count
        project = f"chain-{chain_number}-step-{index}-{scenario}"
        override = state_dir / f"{index}-override.yml"
        override.write_text(
            "services:\n" + "".join(f"  {service}:\n    ports: []\n" for service in services(compose)),
            encoding="utf-8",
        )
        run("docker", "compose", "--profile", "debug", "-p", project, "-f", str(compose), "-f", str(override), "up", "-d", "--build", env=compose_env)
        service_names = services(compose)
        requested = node.get("entry_service")
        selected = requested or ("attacker" if "attacker" in service_names else entry.get("public_service"))
        if selected not in service_names:
            raise RuntimeError(f"{scenario}: chain entry service {selected!r} is not defined")
        container_ids = run("docker", "compose", "-p", project, "-f", str(compose), "-f", str(override), "ps", "-q").splitlines()
        selected_id = run("docker", "compose", "--profile", "debug", "-p", project, "-f", str(compose), "-f", str(override), "ps", "-q", selected)
        if not selected_id:
            raise RuntimeError(f"{scenario}: chain entry service {selected!r} did not start")
        for container in container_ids:
            aliases = ["--alias", f"{project}-{container[:12]}"]
            if container == selected_id:
                aliases.extend(["--alias", f"step-{index}"])
            run("docker", "network", "connect", *aliases, network, container)
        step_urls[str(index)] = f"http://step-{index}:5000"
        projects.append({"project": project, "compose": str(compose), "override": str(override)})

    env = os.environ.copy()
    env.update({
        "CHAIN_NETWORK": network,
        "CHAIN_PORT": str(11600 + chain_number),
        "CHAIN_KEY": f"chain-{chain_number}-key",
        "STEP_URLS": json.dumps(step_urls),
    })
    run("docker", "compose", "-p", f"chain-{chain_number}-runtime", "-f", str(RUNTIME / "docker-compose.yml"), "up", "-d", "--build", env=env)
    (state_dir / "state.json").write_text(json.dumps({"network": network, "projects": projects}, indent=2), encoding="utf-8")
    print(f"Chain-{chain_number} ready on http://localhost:{11600 + chain_number}")
    print(f"Artifact key: chain-{chain_number}-key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
