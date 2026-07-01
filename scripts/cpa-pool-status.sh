#!/usr/bin/env bash
set -euo pipefail
ROOT="${PROXY_ROOT:-/opt/proxy}"
cd "$ROOT"
echo "== CPA account files =="
find "$ROOT/cpa/auths" -maxdepth 1 -type f -name "*.json" -printf "%f %s bytes\n" | sort || true
echo
echo "== CPA loaded clients from latest logs =="
docker logs --tail 80 proxy-cpa 2>&1 | grep -E "server clients and configuration updated|API server started|Version" || true
echo
echo "== CPA models =="
if [ -z "${CPA_API_KEY:-}" ]; then
  echo "Set CPA_API_KEY before running this script."
  exit 1
fi
docker exec proxy-new-api wget -q -O - --header="Authorization: Bearer ${CPA_API_KEY}" http://cpa:8317/v1/models
echo
