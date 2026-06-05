#!/bin/bash
set -euo pipefail
echo "[Chain-28] Teardown — stop individual components:"
echo "  cd ../../docker/web/tomcat-deserialization && docker compose down -v"
echo "  cd ../../docker/linux/sudo-chroot && docker compose down -v"
echo "  cd ../../ad && docker compose down"
echo "[+] Chain-28 teardown advisory complete"