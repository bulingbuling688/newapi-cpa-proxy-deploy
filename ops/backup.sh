#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="${PROXY_ROOT:-/opt/proxy}"
TS="$(date +%Y%m%dT%H%M%S)"
DEST="$ROOT/backups/full-$TS"
mkdir -p "$DEST"
cd "$ROOT"

cp docker-compose.yml "$DEST/docker-compose.yml"
cp cpa/config.yaml "$DEST/cpa-config.yaml"
tar -czf "$DEST/cpa-auths.tgz" -C "$ROOT/cpa" auths

if docker inspect proxy-postgres >/dev/null 2>&1; then
  docker exec proxy-postgres pg_dump -U "${POSTGRES_USER:-newapi}" -d "${POSTGRES_DB:-new-api}" > "$DEST/new-api.sql"
fi

sha256sum "$DEST"/* > "$DEST/SHA256SUMS"
find "$ROOT/backups" -maxdepth 1 -type d -name "full-*" -printf "%T@ %p\n" | sort -rn | awk 'NR>14 {print $2}' | xargs -r rm -rf
printf "backup created: %s\n" "$DEST"
