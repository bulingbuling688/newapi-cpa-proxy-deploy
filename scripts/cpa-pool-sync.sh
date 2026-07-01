#!/usr/bin/env bash
set -euo pipefail
ROOT="${PROXY_ROOT:-/opt/proxy}"
cd "$ROOT"
echo "== validating auth json files =="
python3 - <<'PY'
import json
from pathlib import Path
files = sorted(Path('/opt/proxy/cpa/auths').glob('*.json'))
if not files:
    raise SystemExit('No auth json files found in /opt/proxy/cpa/auths')
for f in files:
    try:
        json.loads(f.read_text())
    except Exception as e:
        raise SystemExit(f'Invalid JSON: {f.name}: {e}')
print(f'valid json files: {len(files)}')
for f in files:
    print(f'- {f.name}')
PY
echo
echo "== restarting CPA to load current auth directory =="
docker compose restart cpa >/dev/null
sleep 3
echo
echo "== loaded status =="
"$ROOT/scripts/cpa-pool-status.sh"
