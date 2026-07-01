#!/usr/bin/env bash
set -u
ROOT="${PROXY_ROOT:-/opt/proxy}"
cd "$ROOT" || exit 1

ok=1
log() { printf "[%s] %s\n" "$(date -Is)" "$*"; }
fail() { ok=0; log "FAIL: $*"; }
pass() { log "OK: $*"; }

if ! command -v docker >/dev/null 2>&1; then
  fail "docker command missing"
else
  pass "docker command exists"
fi

compose_ps_file="$(mktemp)"
if ! docker compose ps >"$compose_ps_file" 2>&1; then
  fail "docker compose ps failed"
else
  pass "docker compose ps works"
  cat "$compose_ps_file"
fi
rm -f "$compose_ps_file"

for name in proxy-new-api proxy-cpa proxy-postgres proxy-redis; do
  state="$(docker inspect -f "{{.State.Running}}" "$name" 2>/dev/null || true)"
  if [ "$state" = "true" ]; then
    pass "container $name running"
  else
    fail "container $name not running"
  fi
done

if curl -fsS --max-time 8 http://127.0.0.1:3000/api/status | grep -q '"success":true'; then
  pass "new-api /api/status success"
else
  fail "new-api /api/status failed"
fi

cpa_no_key_out="$(mktemp)"
cpa_no_key_status="$(curl -sS -o "$cpa_no_key_out" -w "%{http_code}" --max-time 8 http://127.0.0.1:8317/v1/models || true)"
rm -f "$cpa_no_key_out"
if [ "$cpa_no_key_status" = "401" ]; then
  pass "cpa rejects missing API key as expected"
else
  fail "cpa missing-key status expected 401, got $cpa_no_key_status"
fi

disk_pct="$(df -P "$ROOT" | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
if [ -n "$disk_pct" ] && [ "$disk_pct" -lt 85 ]; then
  pass "disk usage ${disk_pct}%"
else
  fail "disk usage high or unknown: ${disk_pct:-unknown}%"
fi

if [ "$ok" -eq 1 ]; then
  log "health check completed: healthy"
  exit 0
fi
log "health check completed: unhealthy"
exit 1
