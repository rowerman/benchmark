#!/usr/bin/env python3
"""Run one or more host-side cloud black-box cases.

用法：run.py <scenario-id> [<expected-flag>]...
验收侧显式传入本轮 flag；不给时退化为从 start-scenario.sh 的输出里取（需 CVE_SHOW_FLAGS=1）。
"""

from __future__ import annotations

import sys

from cases import CASES
from runner import run_case


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: run.py <scenario-id> [<expected-flag>]", file=sys.stderr)
        return 2
    scenario = argv[0].lower()
    if scenario not in CASES:
        print(f"unknown scenario: {scenario}", file=sys.stderr)
        return 2
    expected = argv[1] if len(argv) > 1 else ""
    run_case(scenario, CASES[scenario][0], CASES[scenario][1], expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
