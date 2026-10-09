#!/usr/bin/env python3
"""校验云场景的宿主暴露面：只有登记为 public 的入口/服务可以发布端口。

规则：
  1. registry 的 public_service 必须发布该场景的 `port`；
  2. 任何发布到宿主机的端口都必须能在 cloud-service-identities.yaml 里找到
     exposure: public 的登记项（main 或 aux）；
  3. 登记为 exposure: internal 的服务不得发布宿主端口；
  4. 场景里其它服务不应再发布端口（历史遗留的 socat 代理属于这一类）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = yaml.safe_load((ROOT / "scripts" / "scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]
IDENTITIES = yaml.safe_load((ROOT / "scripts" / "cloud-service-identities.yaml").read_text(encoding="utf-8"))


def published_ports(service: dict) -> list[int]:
    ports = []
    for value in (service or {}).get("ports", []) or []:
        head = str(value).split(":", 1)[0]
        if head.isdigit():
            ports.append(int(head))
    return ports


def main() -> int:
    errors: list[str] = []
    public_by_scenario: dict[str, set[int]] = {}
    internal_ports: dict[str, set[int]] = {}
    for entry in IDENTITIES.get("main", []):
        public_by_scenario.setdefault(entry.get("scenario") or entry["id"], set()).add(int(entry["port"]))
    for entry in IDENTITIES.get("aux", []):
        scenario = str(entry.get("scenario", ""))
        for sid in scenario.split("|"):
            sid = sid.strip()
            if not sid:
                continue
            bucket = public_by_scenario if entry.get("exposure") == "public" else internal_ports
            bucket.setdefault(sid, set()).add(int(entry["port"]))

    checked = 0
    for sid, entry in sorted(REGISTRY.items()):
        if entry.get("type") != "docker" or not sid.startswith("cloud-"):
            continue
        compose = ROOT / entry["path"] / "docker-compose.yml"
        if not compose.is_file():
            errors.append(f"{sid}: missing docker-compose.yml")
            continue
        services = (yaml.safe_load(compose.read_text(encoding="utf-8")) or {}).get("services", {})
        checked += 1
        allowed = set(public_by_scenario.get(sid, set())) | {int(entry["port"])} if entry.get("port") else set(public_by_scenario.get(sid, set()))
        for name, service in services.items():
            for port in published_ports(service):
                if port in internal_ports.get(sid, set()):
                    errors.append(f"{sid}: {name} publishes internal-only port {port}")
                elif port not in allowed:
                    errors.append(f"{sid}: {name} publishes unregistered host port {port}")
        public_service = entry.get("public_service")
        if not public_service:
            errors.append(f"{sid}: missing public_service in registry")
        elif public_service not in services:
            errors.append(f"{sid}: public_service {public_service!r} not found in compose")
        elif entry.get("port") and int(entry["port"]) not in published_ports(services[public_service]):
            errors.append(f"{sid}: public_service {public_service} does not publish {entry['port']}")

    if errors:
        print(f"FAIL: {len(errors)} 处暴露面问题（检查了 {checked} 个 Docker 云场景）")
        for item in errors:
            print("  -", item)
        return 1
    print(f"OK: {checked} 个 Docker 云场景的宿主暴露面与登记一致")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
