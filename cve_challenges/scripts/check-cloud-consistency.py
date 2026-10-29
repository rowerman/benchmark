#!/usr/bin/env python3
"""Validate public-cloud and private-cloud registrations and chain references."""

from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scripts" / "scenarios.yaml"
CLOUD_ROOT = ROOT / "scenarios" / "cloud"
K8S_ROOT = ROOT / "scenarios" / "k8s"
CHAINS_ROOT = ROOT / "chains"


def fail(message: str) -> None:
    print(f"ERROR: {message}")
    raise SystemExit(1)


def main() -> int:
    data = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))
    scenarios = data.get("scenarios", {})
    domains = {
        "cloud": [(key, value) for key, value in scenarios.items() if key.startswith("cloud-")],
        "k8s": [(key, value) for key, value in scenarios.items() if key.startswith("k8s-")],
    }
    expected_counts = {"cloud": 2, "k8s": 60}
    for domain, entries in domains.items():
        upper = domain.upper()
        if len(entries) != expected_counts[domain]:
            fail(f"{domain} must contain {expected_counts[domain]} scenarios, got {len(entries)}")
        ids = sorted(str(value.get("id")) for _, value in entries)
        expected = [f"{upper}-{index:02d}" for index in range(1, len(entries) + 1)]
        if ids != expected:
            fail(f"{domain} registry IDs must be contiguous {upper}-01..{upper}-{len(entries):02d}: {ids}")
        for key, value in entries:
            relative_path = Path(value["path"])
            path = ROOT / relative_path
            if relative_path.parts[:2] != ("scenarios", domain) or not path.is_dir():
                fail(f"{key} must use a {domain} scenario path, got {value['path']}")

    for chain_file in CHAINS_ROOT.glob("*/chain.yaml"):
        text = chain_file.read_text(encoding="utf-8")
        for ref in re.findall(r"scenario:\s*((?:cloud|k8s)-\d+)", text, re.I):
            if ref.lower() not in {key.lower() for key in scenarios}:
                fail(f"{chain_file}: unknown scenario reference {ref}")

    by_path = {Path(value["path"]).as_posix(): value["id"] for value in scenarios.values()}
    for root in (CLOUD_ROOT, K8S_ROOT):
        for guide in root.glob("*/GUIDE.md"):
            rel = guide.parent.relative_to(ROOT).as_posix()
            expected_id = by_path.get(rel)
            match = re.search(r"^#\s+((?:CLOUD|K8S)-\d{2})\b", guide.read_text(encoding="utf-8"), re.M)
            if expected_id and (not match or match.group(1) != expected_id):
                fail(f"{guide}: GUIDE ID does not match registry ({expected_id})")

    print(
        f"OK: {len(domains['cloud'])} public cloud and "
        f"{len(domains['k8s'])} private cloud scenarios, valid chain references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
