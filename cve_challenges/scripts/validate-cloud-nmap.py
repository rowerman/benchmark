#!/usr/bin/env python3
"""Feature-driven nmap regression for Docker cloud scenarios.

Starts each requested scenario, runs nmap -sV with the merged project probe
database against its registered (and protocol-auxiliary) ports, and asserts
the detected product matches cloud-service-identities.yaml.  `--running-only`
scans scenarios that are already up without start/stop lifecycle.
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "scripts" / "scenarios.yaml"
IDENTITIES = ROOT / "scripts" / "cloud-service-identities.yaml"


def wait_port(port: int, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(1)
    raise AssertionError(f"port {port} did not become reachable")


def run_nmap(datadir: Path, ports: list[int]) -> str:
    command = ["nmap", "--datadir", str(datadir), "-sV", "--version-all", "-Pn",
               "-p", ",".join(str(p) for p in ports), "127.0.0.1"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    return result.stdout + result.stderr


def parse_results(output: str) -> dict[int, tuple[str, str]]:
    found: dict[int, tuple[str, str]] = {}
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)/tcp\s+open\s+(\S+)\s+(.*)$", line)
        if match:
            found[int(match.group(1))] = (match.group(2), match.group(3).strip())
    return found


def check_products(results: dict[int, tuple[str, str]], expectations: list[tuple[int, str, str]]) -> list[str]:
    failures = []
    for port, expected, probe in expectations:
        if port not in results:
            failures.append(f"port {port}: not open / no service result")
            continue
        service, version = results[port]
        if "tcpwrapped" in version.lower() or service == "unknown" or "unknown" in version.lower():
            failures.append(f"port {port}: indeterminate result service={service!r} version={version!r}")
            continue
        if probe == "standard":
            if "postgres" not in (service + " " + version).lower():
                failures.append(f"port {port}: expected PostgreSQL wire protocol, got {service} {version}")
            continue
        accepted = [part.strip() for part in expected.split("|") if part.strip()]
        if not any(part and part in version for part in accepted):
            failures.append(f"port {port}: expected {accepted!r}, got {service} {version}")
    return failures


def scenario_env_backup(scenario_dir: Path) -> tuple[bytes | None, Path]:
    env_file = scenario_dir / ".env"
    original = env_file.read_bytes() if env_file.exists() else None
    return original, env_file


def restore_env(original: bytes | None, env_file: Path) -> None:
    if original is None:
        env_file.unlink(missing_ok=True)
    else:
        env_file.write_bytes(original)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenarios", nargs="*", help="cloud-XX ids; default: all 30")
    parser.add_argument("--datadir", required=True, help="merged nmap data directory")
    parser.add_argument("--running-only", action="store_true",
                        help="scan already-running scenarios (no start/stop)")
    parser.add_argument("--include-aux", action="store_true",
                        help="also scan protocol-auxiliary ports declared in the manifest")
    args = parser.parse_args()

    datadir = Path(args.datadir)
    if not (datadir / "nmap-service-probes").exists():
        print(f"missing merged probe database: {datadir}/nmap-service-probes", file=sys.stderr)
        print("run: bash scripts/setup-cloud-nmap.sh (or merge manually)", file=sys.stderr)
        return 2

    registry = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["scenarios"]
    identities = yaml.safe_load(IDENTITIES.read_text(encoding="utf-8"))
    main_by_id = {item["id"]: item for item in identities["main"]}
    aux = identities.get("aux", [])
    requested = [s.lower() for s in args.scenarios] or sorted(
        sid for sid, entry in registry.items()
        if entry.get("type") == "docker" and sid.startswith("cloud-") and sid in main_by_id)
    unknown = [s for s in requested if s not in main_by_id]
    if unknown:
        print(f"unknown scenarios: {', '.join(unknown)}", file=sys.stderr)
        return 2

    failed = False
    for scenario in requested:
        entry = registry[scenario]
        scenario_dir = ROOT / entry["path"]
        main_port = int(entry["port"])
        expectations = [(main_port, main_by_id[scenario]["product"], main_by_id[scenario]["probe"])]
        aux_ports: list[int] = []
        if args.include_aux:
            for item in aux:
                if scenario in [part.strip() for part in str(item.get("scenario", "")).split("|")]:
                    if item.get("probe") == "manual":
                        continue
                    aux_ports.append(int(item["port"]))
                    expectations.append((int(item["port"]), item["product"], item["probe"]))

        original_env = None
        env_file = scenario_dir / ".env"
        started = False
        try:
            if not args.running_only:
                original_env, env_file = scenario_env_backup(scenario_dir)
                start = subprocess.run(["bash", str(ROOT / "scripts" / "start-scenario.sh"), scenario],
                                       cwd=ROOT, capture_output=True, text=True, timeout=240)
                if start.returncode:
                    raise AssertionError(f"{scenario} failed to start:\n{start.stdout}\n{start.stderr}")
                started = True
                wait_port(main_port)
            else:
                wait_port(main_port)
            # give Flask apps a moment to accept requests after TCP connect
            time.sleep(2)
            ports = [main_port] + aux_ports
            output = run_nmap(datadir, ports)
            results = parse_results(output)
            failures = check_products(results, expectations)
            if failures:
                failed = True
                print(f"FAIL {scenario}:")
                for message in failures:
                    print(f"  - {message}")
                print(output)
            else:
                print(f"PASS {scenario}: " + ", ".join(
                    f"{port}={results[port][1].split(' (')[0]}" for port in ports if port in results))
        except Exception as error:  # lifecycle failures are also test failures
            failed = True
            print(f"FAIL {scenario}: {error}")
        finally:
            if started:
                subprocess.run(["bash", str(ROOT / "scripts" / "stop-scenario.sh"), scenario],
                               cwd=ROOT, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                restore_env(original_env, env_file)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
