#!/usr/bin/env python3
"""Host-side black-box runner for Docker cloud scenarios."""

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

ROOT = Path(__file__).resolve().parents[2]
START = ROOT / "scripts" / "start-scenario.sh"
STOP = ROOT / "scripts" / "stop-scenario.sh"
SCENARIO_DIRS = {
    "cloud-01": "ssrf-to-imds", "cloud-11": "global-s3-squatting",
    "cloud-03": "lambda-passrole", "cloud-04": "cf-injection",
    "cloud-05": "ci-poisoning", "cloud-12": "cosmiss-notebook",
    "cloud-07": "oidc-federation", "cloud-08": "cross-account-trust",
    "cloud-09": "golden-saml", "cloud-10": "scp-bypass",
    "cloud-13": "rds-logfdw",
    "cloud-14": "cloudsql-index-rce",
    "cloud-06": "notebook-escape", "cloud-18": "buildfleet-registry",
    "cloud-19": "pickle-model", "cloud-26": "composer-depconf",
    "cloud-31": "persistence-as-a-service",
    "cloud-15": "synlapse-ir", "cloud-23": "iam-enum-oracle",
    "cloud-16": "extrareplica-repl", "cloud-17": "wireserver-bootstrap",
    "cloud-24": "beta-endpoint", "cloud-29": "dataform-pt",
    "cloud-20": "attachme-volume", "cloud-21": "actor-token",
    "cloud-22": "omigod-agent", "cloud-25": "resource-explorer",
    "cloud-27": "lowcode-secrets", "cloud-28": "shared-nat",
    "cloud-30": "serverless-sa",
    "cloud-31": "persistence-as-a-service",
}
FLAG_COUNTS = {"cloud-13": 2, "cloud-17": 2}
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
    match = list(dict.fromkeys(re.findall(r"\[\+\] Flag(?: \d+)?: (flag\{[^}]+\})", result.stdout)))
    expected = FLAG_COUNTS.get(scenario, 1)
    if len(match) != expected:
        stop(scenario)
        raise AssertionError(f"expected one dynamic Flag for {scenario}, got {match!r}\n{result.stdout}")
    wait_port(port)
    if port in NON_HTTP_PORTS:
        wait_port(port)
    else:
        wait_http(f"http://127.0.0.1:{port}")
    return result, match if expected > 1 else match[0]


def stop(scenario: str) -> None:
    subprocess.run(["bash", str(STOP), scenario], cwd=ROOT, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_case(scenario: str, port: int, case) -> None:
    started = False
    scenario_path = ROOT / "scenarios" / "cloud" / SCENARIO_DIRS[scenario]
    compose_env = scenario_path / ".env"
    original_env = compose_env.read_bytes() if compose_env.exists() else None
    try:
        _, flag = start(scenario, port)
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
