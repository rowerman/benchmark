#!/usr/bin/env python3
"""Validate public-cloud registrations after K8s scenario migration."""

from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scripts" / "scenarios.yaml"
CLOUD_ROOT = ROOT / "scenarios" / "cloud"
CHAINS_ROOT = ROOT / "chains"


def fail(message: str) -> None:
    print(f"ERROR: {message}")
    raise SystemExit(1)


def main() -> int:
    data = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))
    cloud = data.get("scenarios", {})
    entries = [(key, value) for key, value in cloud.items()
               if key.startswith("cloud-")]
    ids = [value.get("id") for _, value in entries]
    retired = {"CLOUD-02", "CLOUD-03", "CLOUD-12"}
    expected = [f"CLOUD-{i:02d}" for i in range(1, 34) if f"CLOUD-{i:02d}" not in retired]
    if sorted(ids) != expected:
        fail(f"cloud registry IDs do not match the 30 active IDs after K8s migration: {sorted(ids)}")
    if len(ids) != len(set(ids)):
        fail("duplicate cloud registry ID")

    for key, value in entries:
        path = ROOT / value["path"]
        if not path.is_dir():
            fail(f"{key} points to missing directory {path}")

    for chain_file in CHAINS_ROOT.glob("*/chain.yaml"):
        text = chain_file.read_text(encoding="utf-8")
        for ref in re.findall(r"scenario:\s*(cloud-\d+)", text, re.I):
            if ref.lower() not in {key.lower() for key, _ in entries}:
                fail(f"{chain_file}: unknown scenario reference {ref}")
        for ref in re.findall(r"scenario:\s*(cloud-(?:02|03|12))\b", text, re.I):
            fail(f"{chain_file}: migrated K8s scenario still referenced as {ref}")

    # Each GUIDE must agree with the registry entry for its directory.  This
    # catches stale IDs without confusing a valid new ID (for example CLOUD-09)
    # with the old number that occupied the same token before migration.
    by_path = {Path(value["path"]).as_posix(): value["id"]
               for _, value in entries}
    for guide in CLOUD_ROOT.glob("*/GUIDE.md"):
        rel = guide.parent.relative_to(ROOT).as_posix()
        expected_id = by_path.get(rel)
        match = re.search(r"^#\s+(CLOUD-\d{2})\b", guide.read_text(encoding="utf-8"), re.M)
        if expected_id and (not match or match.group(1) != expected_id):
            fail(f"{guide}: GUIDE ID does not match registry ({expected_id})")

    print(f"OK: {len(entries)} active cloud scenarios, migrated IDs excluded, valid chain references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
