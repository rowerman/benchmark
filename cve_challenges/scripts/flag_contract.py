#!/usr/bin/env python3
"""Flag variable contracts shared by scenario and chain launchers."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MULTI_FLAG_SCENARIOS = {
    "cloud-13": 2,
    "cloud-17": 2,
    "k8s-32": 2,
}


def scenario_flag_count(scenario_id: str) -> int:
    return MULTI_FLAG_SCENARIOS.get(scenario_id.lower(), 1)


def chain_nodes(chain_dir: Path) -> list[dict[str, object]]:
    data = yaml.safe_load((chain_dir / "chain.yaml").read_text(encoding="utf-8")) or {}
    return data.get("nodes") or []


def chain_flag_count(chain_dir: Path) -> int:
    return sum(
        scenario_flag_count(str(node.get("scenario", "")))
        for node in chain_nodes(chain_dir)
        if isinstance(node, dict)
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: flag_contract.py scenario|chain <id-or-path>")
    if sys.argv[1] == "scenario":
        print(scenario_flag_count(sys.argv[2]))
    elif sys.argv[1] == "chain":
        print(chain_flag_count(Path(sys.argv[2])))
    else:
        raise SystemExit("unknown contract type")
