#!/usr/bin/env python3
"""Check that deployed Flags have a runtime variable contract."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scripts" / "scenarios.yaml"
FLAG = re.compile(r"flag\{[^}]+\}")
FALLBACK = re.compile(r"\$\{[^}]*:-flag\{[^}]+\}\}")


def unbound_flags(text: str) -> list[str]:
    remaining = FALLBACK.sub("", text)
    return FLAG.findall(remaining)


def main() -> int:
    errors: list[str] = []
    registry = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    for scenario_id, entry in registry.items():
        if entry.get("type") != "docker":
            continue
        path = ROOT / str(entry["path"])
        compose = next((path / name for name in ("docker-compose.yml", "docker-compose.yaml") if (path / name).is_file()), None)
        if compose is None:
            continue
        text = compose.read_text(encoding="utf-8")
        if "${CVE_FLAG" not in text:
            errors.append(f"{scenario_id}: Compose has no CVE_FLAG reference")
        for value in unbound_flags(text):
            errors.append(f"{compose.relative_to(ROOT)}: unbound Flag {value}")

    for script in sorted((ROOT / "chains").glob("*/deploy.sh")):
        text = script.read_text(encoding="utf-8")
        for line in text.splitlines():
            if re.search(r"(?:FLAG\d*|CVE_FLAG\d*)=\s*['\"]?flag\{", line):
                errors.append(f"{script.relative_to(ROOT)}: hardcoded Flag assignment")
    if errors:
        print("Flag contract validation failed:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("Flag contract valid: all Docker scenarios and chain assignments use runtime variables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
