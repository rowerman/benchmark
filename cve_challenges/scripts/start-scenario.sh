#!/bin/bash
# Usage: ./start-scenario.sh <scenario-id>
#
# Flag 值由调用方经 CVE_FLAG / CVE_FLAG1..N 显式传入（缺失时才随机生成），并且
# 只注入到目标环境内部：Docker 场景由 inject-flags.py 写进容器内文件，K8s 场景由
# deploy.sh 写进节点/集群。flag 不写进场景目录，也不出现在启动输出里——需要明文
# 调试时设 CVE_SHOW_FLAGS=1。
set -euo pipefail

SCENARIO_ID="${1:?Usage: $0 <scenario-id>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

FLAG_COUNT=$(python3 "$SCRIPT_DIR/flag_contract.py" scenario "$SCENARIO_ID")
if [ "$FLAG_COUNT" -eq 1 ]; then
  FLAG="${CVE_FLAG:-$(python3 "$SCRIPT_DIR/flag_manager.py" "$SCENARIO_ID")}"
  export CVE_FLAG="$FLAG"
else
  for i in $(seq 1 "$FLAG_COUNT"); do
    name="CVE_FLAG$i"
    if [ -z "${!name:-}" ]; then
      value=$(python3 "$SCRIPT_DIR/flag_manager.py" "$SCENARIO_ID-step$i")
      export "$name=$value"
    fi
  done
  CVE_FLAG="${CVE_FLAG:-$CVE_FLAG1}"
  export CVE_FLAG
fi

echo "[*] Starting scenario: $SCENARIO_ID"
if [ "${CVE_SHOW_FLAGS:-0}" = "1" ]; then
  if [ "$FLAG_COUNT" -eq 1 ]; then
    echo "[+] Flag: $FLAG"
  else
    for i in $(seq 1 "$FLAG_COUNT"); do
      name="CVE_FLAG$i"
      printf '[+] Flag %s: %s\n' "$i" "${!name}"
    done
  fi
else
  echo "[+] Flag 已生成，仅注入目标环境（明文调试请设 CVE_SHOW_FLAGS=1）"
fi

# Determine scenario type from registry
SCENARIO_PATH="$ROOT_DIR/$(python3 -c "
import yaml
with open('$SCRIPT_DIR/scenarios.yaml') as f:
    data = yaml.safe_load(f)
print(data['scenarios']['$SCENARIO_ID']['path'])
")"

TYPE=$(python3 -c "
import yaml
with open('$SCRIPT_DIR/scenarios.yaml') as f:
    data = yaml.safe_load(f)
print(data['scenarios']['$SCENARIO_ID']['type'])
")

case "$TYPE" in
  docker)
    cd "$SCENARIO_PATH"
    echo "[+] Starting Docker Compose..."
    # 非 cloud 场景（web/db）沿用旧的卷挂载约定：仍写场景目录下的 flag.txt。
    # cloud 场景已改为运行时注入，不在这里落盘。
    case "$SCENARIO_ID" in
      cloud-*) ;;
      *)
        if [ "$FLAG_COUNT" -eq 1 ] && [ -f flag.txt ]; then echo "$FLAG" > flag.txt; fi
        for f in */flag.txt; do [ -f "$f" ] && echo "$FLAG" > "$f"; done 2>/dev/null || true
        ;;
    esac
    if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then
      # 先创建容器（不启动）→ 经 stdin/tar 把 flag 注入容器内 → 再启动，
      # 这样应用启动时就能读到 flag，而宿主机上不留任何明文副本。
      docker compose up -d --build --no-start --remove-orphans
      python3 "$SCRIPT_DIR/inject-flags.py" "$SCENARIO_ID"
      docker compose up -d --remove-orphans
      python3 "$SCRIPT_DIR/inject-flags.py" --seed "$SCENARIO_ID"
    else
      echo "[!] no compose file in $SCENARIO_PATH" >&2
      exit 1
    fi
    echo "[+] Scenario $SCENARIO_ID started (Docker)"
    ;;

  k8s)
    cd "$SCENARIO_PATH"
    echo "[+] Starting K8s scenario..."
    if [ -f deploy.sh ]; then
      bash deploy.sh
    else
      echo "[!] deploy.sh not found in $SCENARIO_PATH"
      exit 1
    fi
    echo "[+] Scenario $SCENARIO_ID started (K8s)"
    ;;

  *)
    echo "[!] Unknown scenario type: $TYPE"
    exit 1
    ;;
esac
