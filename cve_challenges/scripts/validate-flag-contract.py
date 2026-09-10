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

    # Shell parameter expansion closes the default word at an unescaped '}', so
    # "${VAR:-flag{x}}" silently appends a stray '}' when VAR is set and the
    # runtime Flag becomes malformed. The closing brace must be escaped.
    shell_scripts = (
        sorted((ROOT / "scripts").glob("*.sh"))
        + sorted((ROOT / "scenarios").glob("*/*/deploy.sh"))
        + sorted((ROOT / "scenarios").glob("*/*/teardown.sh"))
        + sorted((ROOT / "chains").glob("*/deploy.sh"))
        + sorted((ROOT / "chains").glob("*/teardown.sh"))
    )
    for script in shell_scripts:
        for number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
            if ":-flag{" in line and not re.search(r":-flag\{.*\\\}", line):
                errors.append(
                    f"{script.relative_to(ROOT)}:{number}: unescaped closing brace in "
                    f"Flag default (use \\}} before the closing quote)"
                )
    if errors:
        print("Flag contract validation failed:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("Flag contract valid: all Docker scenarios and chain assignments use runtime variables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
