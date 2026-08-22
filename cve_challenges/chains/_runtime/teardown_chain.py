#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

STATE_ROOT = Path(tempfile.gettempdir()) / "cve-cloud-chains"


def run(*args: str) -> None:
    subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: teardown_chain.py <chain-number>", file=sys.stderr)
        return 2
    number = int(sys.argv[1])
    state_dir = STATE_ROOT / str(number)
    state_file = state_dir / "state.json"
    state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.is_file() else {"projects": [], "network": f"chain-{number}-net"}
    runtime_compose = Path(__file__).resolve().parent / "docker-compose.yml"
    run("docker", "compose", "-p", f"chain-{number}-runtime", "-f", str(runtime_compose), "down", "-v")
    for project in state.get("projects", []):
        run("docker", "compose", "-p", project["project"], "-f", project["compose"], "-f", project["override"], "down", "-v")
    run("docker", "network", "rm", state["network"])
    shutil.rmtree(state_dir, ignore_errors=True)
    print(f"Chain-{number} torn down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
