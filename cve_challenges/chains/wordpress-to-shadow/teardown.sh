#!/bin/bash
set -euo pipefail
echo "[Chain-29] Teardown — stop individual components:"
echo "  cd ../../docker/web/wordpress-simple-file-list && docker compose down -v"
echo "  cd ../../docker/db/mysql-weak-auth && docker compose down -v"
echo "  cd ../../docker/linux/sudo-chroot && docker compose down -v"
echo "  cd ../../ad && docker compose down"
echo "[+] Chain-29 teardown advisory complete"