#!/usr/bin/env python3
"""列出要验收的单点场景：scenario-id、交付类型、场景目录。"""
from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    scope = sys.argv[1] if len(sys.argv) > 1 else "all"
    only = {item.strip() for item in (sys.argv[2] if len(sys.argv) > 2 else "").split(",") if item.strip()}
    registry = yaml.safe_load((ROOT / "scripts" / "scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]
    for scenario_id, entry in registry.items():
        if not (scenario_id.startswith("cloud-") or scenario_id.startswith("k8s-")):
            continue
        if only and scenario_id not in only:
            continue
        if scope == "cloud" and not scenario_id.startswith("cloud-"):
            continue
        if scope == "k8s" and not scenario_id.startswith("k8s-"):
            continue
        kind = "k8s" if scenario_id == "cloud-02" else entry["type"]
        print(f"{scenario_id}\t{kind}\t{entry['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
