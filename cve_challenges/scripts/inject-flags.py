#!/usr/bin/env python3
"""把本轮 flag 注入到目标容器内部（宿主不留副本）。

用法：在场景目录里执行 `python3 scripts/inject-flags.py <scenario-id>`；
flag 值来自环境变量 CVE_FLAG / CVE_FLAG1..N，投递位置来自 scripts/flag-sinks.yaml。
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SINKS = ROOT / "scripts" / "flag-sinks.yaml"
REGISTRY = ROOT / "scripts" / "scenarios.yaml"
SEEDS = yaml.safe_load((ROOT / "scripts" / "flag-sinks.yaml").read_text(encoding="utf-8")).get("seeds", {})


def flag_value(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing {name} in environment; start-scenario.sh must pass it")
    return value


def scenario_dir(scenario_id: str) -> Path:
    registry = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))["scenarios"]
    return ROOT / registry[scenario_id]["path"]


def container_id(service: str, workdir: Path) -> str:
    """取容器 ID：--all 让"已创建未启动"的容器也能被注入。"""
    result = subprocess.run(["docker", "compose", "ps", "-q", "--all", service], cwd=workdir,
                            capture_output=True, text=True, check=False)
    cid = result.stdout.strip().splitlines()
    if not cid:
        return ""
    return cid[0]


def flag_tar(name: str, value: str) -> bytes:
    """把 flag 按目标路径打包成 tar 流，供 docker cp 直接写进容器（宿主不留文件）。"""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        payload = value.encode()
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def write_into_container(cid: str, path: str, value: str) -> None:
    """经 stdin+tar 注入容器内路径；容器已创建即可，无需处于运行状态。"""
    subprocess.run(["docker", "cp", "-", f"{cid}:/"],
                   input=flag_tar(path.lstrip("/"), value), check=True)


def seed(scenario_id: str, entries: list, workdir: Path) -> int:
    """启动后把 flag 经 stdin 播种进容器内的数据库/配置文件等运行时结构。"""
    count = 0
    for entry in entries:
        cid = container_id(entry["service"], workdir)
        if not cid:
            print(f"[inject-flags] seed {entry['service']}: 容器未运行，跳过", file=sys.stderr)
            continue
        # 结尾补换行：脚本里的 read 在无换行的 EOF 上会返回非零，配合 set -e 会直接失败
        result = subprocess.run(["docker", "exec", "-i", cid, "sh", "-c", entry["command"]],
                                input=flag_value(entry["flag"]) + "\n", text=True, check=False)
        if result.returncode != 0:
            raise SystemExit(f"seed {entry['service']} failed with {result.returncode}")
        count += 1
    return count


def main() -> int:
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: inject-flags.py [--seed] <scenario-id>")
    seeding = "--seed" in sys.argv
    scenario_id = sys.argv[-1]
    payload = yaml.safe_load(SINKS.read_text(encoding="utf-8"))
    sinks = payload["sinks"]
    mapping = sinks.get(scenario_id)
    if mapping is None:
        print(f"[inject-flags] {scenario_id}: 没有 flag 投递配置，跳过")
        return 0
    workdir = scenario_dir(scenario_id)
    if seeding:
        seeds = SEEDS.get(scenario_id, [])
        print(f"[inject-flags] {scenario_id}: 已播种 {seed(scenario_id, seeds, workdir)} 个运行时数据点")
        return 0
    injected = 0
    for entry in mapping:
        service = entry["service"]
        cid = container_id(service, workdir)
        if not cid:
            print(f"[inject-flags] {service}: 容器未运行，跳过", file=sys.stderr)
            continue
        for item in entry["flags"]:
            value = flag_value(item["flag"])
            for path in item["paths"]:
                write_into_container(cid, path, value)
                injected += 1
        print(f"[inject-flags] {service}: {len(entry['flags'])} 枚 flag 注入完成")
    print(f"[inject-flags] {scenario_id}: 共 {injected} 个注入点")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
