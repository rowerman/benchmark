#!/usr/bin/env python3
"""云场景负向门禁：证明 flag 只能从场景声明的语义路径拿到。

用法：validate-cloud-gate.py <scenario-id> <expected-flag>

检查项：
  1. flag 必须已经落在 flag-vault 容器里（否则场景无法交付）；
  2. 除 flag-vault 外，任何容器都不得出现明文 flag（环境变量、常见落点、容器日志）；
  3. 入口端口对常见"直读"路径不得返回 flag；
  4. 未通过校验时 flag-vault 的 /flag 必须 403。
"""
from __future__ import annotations

import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = yaml.safe_load((ROOT / "scripts" / "scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]
VAULT_SERVICE = "flag-vault"
# 旧约定里的 flag 直读落点，出现即视为捷径通道仍在
LEGACY_SINK_PATHS = ("/run/flag", "/flag.txt", "/tmp/flag", "/tmp/flag.txt")
# 容器内值得扫一遍的目录（都是 mock 服务的小镜像）
SCAN_DIRS = ("/tmp", "/run", "/app", "/srv", "/opt", "/var/www", "/usr/share/nginx/html",
             "/root", "/home", "/etc", "/data", "/workspaces")


def compose(workdir: Path, *args: str, check: bool = False) -> str:
    result = subprocess.run(["docker", "compose", *args], cwd=workdir,
                            capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise SystemExit(f"docker compose {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def container_id(workdir: Path, service: str) -> str:
    ids = compose(workdir, "ps", "-q", "--all", service).split()
    return ids[0] if ids else ""


def services(workdir: Path) -> list[str]:
    data = yaml.safe_load((workdir / "docker-compose.yml").read_text(encoding="utf-8")) or {}
    return list((data.get("services") or {}).keys())


def http_get(url: str, timeout: float = 5) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")
    except Exception:
        return 0, ""


def http_get_ready(url: str, timeout: float = 5, attempts: int = 20) -> tuple[int, str]:
    """容器刚起时 Flask 可能还没监听，先等出响应（含 4xx）再判定。"""
    status, body = 0, ""
    for _ in range(attempts):
        status, body = http_get(url, timeout=timeout)
        if status:
            return status, body
        time.sleep(1)
    return status, body


def docker_inspect(vault_cid: str, template: str) -> str:
    result = subprocess.run(
        ["docker", "inspect", "--format", template, vault_cid],
        capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def vault_probe_networks(vault_cid: str) -> list[tuple[str, str]]:
    """返回 vault 所在的 Compose 网络及对应地址。"""
    output = docker_inspect(
        vault_cid,
        "{{range $name, $network := .NetworkSettings.Networks}}{{println $name $network.IPAddress}}{{end}}")
    networks: list[tuple[str, str]] = []
    for line in output.splitlines():
        pieces = line.split()
        if len(pieces) == 2 and pieces[1]:
            networks.append((pieces[0], pieces[1]))
    return networks


def probe_vault_without_credentials(vault_cid: str) -> tuple[int, str]:
    """从同一 Compose 网络启动一次性容器，检查未授权访问是否返回 403。"""
    image = docker_inspect(vault_cid, "{{.Config.Image}}")
    if not image:
        return 0, "无法获取 flag-vault 镜像"

    probe = """import sys, urllib.error, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=5)
    print(200)
except urllib.error.HTTPError as exc:
    print(exc.code)
except Exception as exc:
    print(f\"probe error: {exc}\", file=sys.stderr)
    print(0)
"""
    last_error = ""
    for network, address in vault_probe_networks(vault_cid):
        result = subprocess.run([
            "docker", "run", "--rm",
            "--network", network,
            "--entrypoint", "python",
            "--env", "HTTP_PROXY=", "--env", "HTTPS_PROXY=",
            "--env", "http_proxy=", "--env", "https_proxy=",
            "--env", "NO_PROXY=*", "--env", "no_proxy=*",
            image, "-c", probe, f"http://{address}:5000/flag",
        ], capture_output=True, text=True, check=False)
        lines = result.stdout.strip().splitlines()
        if result.returncode == 0 and lines:
            try:
                return int(lines[-1]), result.stderr.strip()
            except ValueError:
                pass
        last_error = (result.stderr or result.stdout).strip()
    return 0, last_error


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: validate-cloud-gate.py <scenario-id> <expected-flag>")
    scenario_id, flag = sys.argv[1], sys.argv[2]
    entry = REGISTRY[scenario_id]
    workdir = ROOT / entry["path"]

    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)
        print(f"  [FAIL] {message}")

    def ok(message: str) -> None:
        print(f"  [ok]   {message}")

    print(f"[gate] {scenario_id}")

    all_services = services(workdir)
    if VAULT_SERVICE not in all_services:
        fail(f"compose 里没有 {VAULT_SERVICE} 服务（flag 终点缺失）")
        print(f"[gate] {scenario_id} FAIL（{len(failures)} 项）")
        return 1

    vault_cid = container_id(workdir, VAULT_SERVICE)
    if not vault_cid:
        fail("flag-vault 容器未运行")
        print(f"[gate] {scenario_id} FAIL（{len(failures)} 项）")
        return 1

    # 1. flag 确实落在 vault 里
    stored = subprocess.run(["docker", "exec", vault_cid, "cat", "/vault/flag"],
                            capture_output=True, text=True, check=False)
    if stored.returncode == 0 and stored.stdout.strip() == flag:
        ok("flag 已落在 flag-vault 容器内（root-only 文件）")
    else:
        fail(f"flag-vault 内没读到本轮 flag（stdout={stored.stdout.strip()!r}）")

    # 2. 其它容器里不得有明文 flag
    leaks: list[str] = []
    for service in all_services:
        if service == VAULT_SERVICE:
            continue
        cid = container_id(workdir, service)
        if not cid:
            continue
        env = compose(workdir, "exec", "-T", service, "env")
        if flag in env:
            leaks.append(f"{service}: 环境变量")
        inspect = subprocess.run(
            ["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", cid],
            capture_output=True, text=True, check=False).stdout
        if flag in inspect:
            leaks.append(f"{service}: 容器配置")
        paths = [*SCAN_DIRS, *LEGACY_SINK_PATHS]
        grep_cmd = "grep -rlsI -- {} {} 2>/dev/null".format(
            shlex.quote(flag), " ".join(shlex.quote(path) for path in paths))
        scan = subprocess.run(["docker", "exec", cid, "sh", "-c", grep_cmd],
                              capture_output=True, text=True, check=False)
        if flag in scan.stdout:
            leaks.append(f"{service}: 容器文件系统")
        logs = subprocess.run(["docker", "logs", cid], capture_output=True, text=True, check=False)
        if flag in (logs.stdout + logs.stderr):
            leaks.append(f"{service}: 容器日志")
    if leaks:
        fail("除 flag-vault 外仍有明文 flag：" + "、".join(leaks))
    else:
        ok("除 flag-vault 外没有明文 flag（环境变量/文件/日志）")

    # 3. 入口端口不能直接读到 flag
    port = entry.get("port")
    if port:
        # 等入口真正开始应答（否则会把"还没起来"当成"没有 flag"）
        http_get_ready(f"http://127.0.0.1:{port}/", attempts=30)
        bodies = []
        for path in ("/", "/flag", "/flag.txt", "/run/flag"):
            status, body = http_get(f"http://127.0.0.1:{port}{path}")
            bodies.append((path, status, body))
        hit = [path for path, _, body in bodies if flag in body]
        if hit:
            fail(f"入口端口 {port} 直读就到了 flag：{hit}")
        else:
            ok(f"入口端口 {port} 的直读路径没有 flag")
    else:
        ok("该场景无固定宿主入口端口")

    # 4. 未校验时 vault 必须拒绝。检查必须从同一 Compose 网络发起，
    # 宿主网络无法可靠访问场景自定义网段。
    status, probe_error = probe_vault_without_credentials(vault_cid)
    if status == 403:
        ok("未带凭据访问 flag-vault 被 403")
    else:
        detail = f"：{probe_error}" if probe_error else ""
        fail(f"同网络探测未带凭据访问 flag-vault 返回 {status}（应 403）{detail}")

    if failures:
        print(f"[gate] {scenario_id} FAIL（{len(failures)} 项）")
        return 1
    print(f"[gate] {scenario_id} PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
