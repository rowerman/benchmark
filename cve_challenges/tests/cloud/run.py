#!/usr/bin/env python3
"""Run one or more host-side cloud black-box cases."""

from __future__ import annotations

import sys

from cases import CASES
from runner import run_case


def main() -> int:
    requested = [item.lower() for item in sys.argv[1:]] or list(CASES)
    unknown = [item for item in requested if item not in CASES]
    if unknown:
        print(f"unknown scenarios: {', '.join(unknown)}", file=sys.stderr)
        return 2
    for scenario in requested:
        port, case = CASES[scenario]
        run_case(scenario, port, case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
