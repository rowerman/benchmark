#!/bin/sh
set -eu
# /app/memory.json 只保留同租户凭据：flag 已迁到 flag-vault，容器内不留明文
exec python3 /app/app.py
