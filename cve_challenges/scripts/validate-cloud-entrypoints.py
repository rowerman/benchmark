#!/usr/bin/env python3
"""Validate the public entrypoint contract for Docker cloud scenarios."""
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "scripts" / "scenarios.yaml"
PROBES = ROOT / "scripts" / "nmap-cloud-probes.txt"
IDENTITIES = ROOT / "scripts" / "cloud-service-identities.yaml"


def published_ports(service: dict) -> list[str]:
    values = service.get("ports", []) or []
    return [str(value) for value in values]


def host_ports(services: dict) -> set[int]:
    ports: set[int] = set()
    for service in services.values():
        for value in published_ports(service or {}):
            head = value.split(":", 1)[0]
            if head.isdigit():
                ports.add(int(head))
    return ports


def main() -> int:
    errors: list[str] = []
    scenarios = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["scenarios"]
    probe_text = PROBES.read_text(encoding="utf-8")
    registered_ports: set[str] = set()
    for key, entry in scenarios.items():
        if entry.get("type") != "docker" or not key.startswith("cloud-"):
            continue
        compose = ROOT / entry["path"] / "docker-compose.yml"
        data = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
        services = data.get("services", {})
        public = entry.get("public_service")
        if not public or public == "attacker" or public not in services:
            errors.append(f"{key}: invalid public_service {public!r}")
            continue
        attacker_ports = published_ports(services.get("attacker", {}))
        if attacker_ports:
            errors.append(f"{key}: attacker still publishes {attacker_ports}")
        expected = str(entry["port"])
        registered_ports.add(expected)
        public_ports = published_ports(services[public])
        if not any(value.split(":", 1)[0] == expected for value in public_ports):
            errors.append(f"{key}: {public} does not publish host port {expected}")

        # Documented entries must be reachable: every localhost port named in the
        # GUIDE has to be published by this scenario's compose.
        reachable = host_ports(services)
        guide = ROOT / entry["path"] / "GUIDE.md"
        documented = {int(match) for match in re.findall(r"localhost:(\d+)", guide.read_text(encoding="utf-8"))}
        for port in sorted(documented - reachable):
            errors.append(f"{key}: GUIDE.md documents localhost:{port} but the compose never publishes it")

        # Fallback flag literals must carry the scenario's own number.
        number = key.split("-", 1)[1]
        for path in sorted((ROOT / entry["path"]).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.name != "Dockerfile" and not path.name.startswith("Dockerfile.") \
                    and path.name not in {"docker-compose.yml", "docker-compose.yaml"}:
                continue
            for literal in re.findall(r"flag\{cloud-(\d+)", path.read_text(encoding="utf-8")):
                if literal.lstrip("0") != number.lstrip("0"):
                    errors.append(f"{key}: {path.relative_to(ROOT)} fallback flag references cloud-{literal}, expected cloud-{number}")
    if "--strict-probes" in sys.argv:
        identities = yaml.safe_load(IDENTITIES.read_text(encoding="utf-8"))
        manifest_main = {str(item["port"]): item for item in identities["main"]}
        for port in sorted(registered_ports):
            if port not in manifest_main:
                errors.append(f"cloud port {port}: missing entry in cloud-service-identities.yaml")
        for port in sorted(registered_ports):
            standard = re.search(rf"^#\s*standard-protocol:\s*{re.escape(port)}\s*$", probe_text, re.MULTILINE)
            if not standard and not any(re.search(rf"^ports\s+.*\b{re.escape(port)}\b", line) for line in probe_text.splitlines()):
                errors.append(f"cloud port {port}: no explicit custom probe; declare standard protocol or add a port-bound probe")
        for item in identities.get("aux", []):
            port = int(item["port"])
            if item.get("probe") == "manual":
                continue
            standard = re.search(rf"^#\s*standard-protocol:\s*{re.escape(str(port))}\s*$", probe_text, re.MULTILINE)
            if not standard and not any(re.search(rf"^ports\s+.*\b{re.escape(str(port))}\b", line) for line in probe_text.splitlines()):
                errors.append(f"aux port {port} ({item['id']}): no probe rule or standard-protocol declaration")
    if errors:
        print("Cloud entrypoint validation failed:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("Cloud entrypoint contract valid: all Docker cloud ports target non-attacker services")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
