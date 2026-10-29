#!/usr/bin/env python3
"""Host-side black-box runner for Docker cloud-service scenarios."""

from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[2]
START = ROOT / "scripts" / "start-scenario.sh"
STOP = ROOT / "scripts" / "stop-scenario.sh"
REGISTRY = ROOT / "scripts" / "scenarios.yaml"
FLAG_COUNTS = {"k8s-33": 2, "k8s-26": 2}
NON_HTTP_PORTS = {10627}


@dataclass
class Response:
    status: int
    body: str
    headers: dict[str, str]

    def json(self) -> dict:
        return json.loads(self.body)


def http(method: str, url: str, *, data: bytes | None = None,
         headers: dict[str, str] | None = None, timeout: float = 10) -> Response:
    request = Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            return Response(response.status, response.read().decode(errors="replace"), dict(response.headers))
    except HTTPError as error:
        return Response(error.code, error.read().decode(errors="replace"), dict(error.headers))
    except URLError as error:
        raise AssertionError(f"request failed: {method} {url}: {error}") from error


def json_request(method: str, url: str, value: dict) -> Response:
    return http(method, url, data=json.dumps(value).encode(),
                headers={"Content-Type": "application/json"})


def wait_port(port: int, timeout: float = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(1)
    raise AssertionError(f"port {port} did not become reachable")


def wait_http(base: str, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = http("GET", base, timeout=2)
            if response.status < 500:
                return
        except (AssertionError, ConnectionResetError, OSError):
            pass
        time.sleep(1)
    raise AssertionError(f"HTTP service {base} did not become ready")


def require_flag(body: str, flag: str) -> None:
    if flag not in body:
        raise AssertionError(f"dynamic Flag was not captured in response: {flag}")


def start(scenario: str, port: int) -> tuple[subprocess.CompletedProcess[str], str]:
    result = subprocess.run(["bash", str(START), scenario], cwd=ROOT,
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise AssertionError(f"{scenario} failed to start:\n{result.stdout}\n{result.stderr}")
    wait_port(port)
    if port in NON_HTTP_PORTS:
        wait_port(port)
    else:
        wait_http(f"http://127.0.0.1:{port}")
    return result, ""


def stop(scenario: str) -> None:
    subprocess.run(["bash", str(STOP), scenario], cwd=ROOT, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_case(scenario: str, port: int, case, expected_flag: str = "") -> None:
    started = False
    registry = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["scenarios"]
    scenario_path = ROOT / registry[scenario]["path"]
    compose_env = scenario_path / ".env"
    original_env = compose_env.read_bytes() if compose_env.exists() else None
    try:
        _, _ = start(scenario, port)
        # flag 由验收侧显式传入（start-scenario.sh 不再打印明文）
        flag = expected_flag
        if not flag:
            raise AssertionError(f"{scenario}: 缺少本轮 flag（验收侧必须显式传入）")
        started = True
        case(f"http://127.0.0.1:{port}", flag)
        print(f"PASS {scenario}: {flag}")
    finally:
        if started:
            stop(scenario)
            if original_env is None:
                compose_env.unlink(missing_ok=True)
            else:
                compose_env.write_bytes(original_env)
