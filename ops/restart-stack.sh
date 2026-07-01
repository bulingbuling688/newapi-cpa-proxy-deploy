#!/usr/bin/env bash
set -euo pipefail
ROOT="${PROXY_ROOT:-/opt/proxy}"
cd "$ROOT"
mkdir -p "$ROOT/logs"
{
  echo "[$(date -Is)] restarting proxy stack"
  docker compose up -d
  docker compose ps
  echo "[$(date -Is)] running health check"
  "$ROOT/ops/health-check.sh"
} 2>&1 | tee -a "$ROOT/logs/restart-stack.log"
