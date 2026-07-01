import asyncio
import hashlib
import json
import os
import re
import shutil
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import asyncpg
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

DB_DSN = os.environ["DB_DSN"]
CPA_BASE_URL = os.environ.get("CPA_BASE_URL", "http://cpa:8317").rstrip("/")
CPA_MANAGEMENT_KEY = os.environ["CPA_MANAGEMENT_KEY"]
USAGE_API_KEY = os.environ["USAGE_API_KEY"]
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "5"))
POLL_BATCH_SIZE = int(os.environ.get("POLL_BATCH_SIZE", "100"))
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))
ALERT_INTERVAL_SECONDS = float(os.environ.get("ALERT_INTERVAL_SECONDS", "60"))
ALERT_WINDOW_HOURS = int(os.environ.get("ALERT_WINDOW_HOURS", "24"))
ALERT_INACTIVE_HOURS = int(os.environ.get("ALERT_INACTIVE_HOURS", "12"))
ALERT_SLOW_MS = int(os.environ.get("ALERT_SLOW_MS", "30000"))
POOL_AUTO_ENABLE_INTERVAL_SECONDS = float(os.environ.get("POOL_AUTO_ENABLE_INTERVAL_SECONDS", "60"))
SINGLE_ACCOUNT_MODE = os.environ.get("SINGLE_ACCOUNT_MODE", "false").lower() in {"1", "true", "yes", "on"}
SINGLE_ACCOUNT_SWITCH_INTERVAL_SECONDS = float(os.environ.get("SINGLE_ACCOUNT_SWITCH_INTERVAL_SECONDS", "15"))
POOL_TIERED_MODE = os.environ.get("POOL_TIERED_MODE", "false").lower() in {"1", "true", "yes", "on"}
POOL_PRIMARY_PLANS = {item.strip().lower() for item in os.environ.get("POOL_PRIMARY_PLANS", "team,plus").split(",") if item.strip()}
POOL_QUOTA_RETRY_SECONDS = float(os.environ.get("POOL_QUOTA_RETRY_SECONDS", str(6 * 60 * 60)))
CPA_AUTH_DIR = Path(os.environ.get("CPA_AUTH_DIR", "/opt/proxy/cpa/auths"))
CPA_STANDBY_AUTH_DIR = Path(os.environ.get("CPA_STANDBY_AUTH_DIR", "/opt/proxy/cpa/auths_standby"))
CPA_COOLING_AUTH_DIR = Path(os.environ.get("CPA_COOLING_AUTH_DIR", "/opt/proxy/cpa/auths_cooling"))
CPA_DISABLED_AUTH_DIR = Path(os.environ.get("CPA_DISABLED_AUTH_DIR", "/opt/proxy/cpa/auths_disabled"))
CPA_DISABLED_META_FILE = CPA_DISABLED_AUTH_DIR / "disabled_accounts.json"
CPA_SINGLE_MODE_STATE_FILE = Path(os.environ.get("CPA_SINGLE_MODE_STATE_FILE", "/opt/proxy/cpa/single_mode_state.json"))
CPA_POOL_STATE_FILE = Path(os.environ.get("CPA_POOL_STATE_FILE", "/opt/proxy/cpa/pool_state.json"))
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
CPA_CONTAINER_NAME = os.environ.get("CPA_CONTAINER_NAME", "proxy-cpa")

app = FastAPI(title="CPA Usage Keeper", version="0.1.0")
db_pool: Optional[asyncpg.Pool] = None
poller_task: Optional[asyncio.Task] = None
alert_task: Optional[asyncio.Task] = None
pool_task: Optional[asyncio.Task] = None
single_mode_task: Optional[asyncio.Task] = None
stats = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "last_poll_at": None,
    "last_success_at": None,
    "last_error_at": None,
    "last_error": None,
    "events_inserted": 0,
    "events_seen": 0,
    "last_alert_scan_at": None,
    "last_alert_error_at": None,
    "last_alert_error": None,
    "open_alerts": 0,
    "tiered_pool_mode": POOL_TIERED_MODE,
    "tiered_primary_plans": sorted(POOL_PRIMARY_PLANS),
    "last_tiered_reconcile_at": None,
    "last_tiered_reconcile": None,
    "last_tiered_error_at": None,
    "last_tiered_error": None,
    "last_pool_scan_at": None,
    "last_pool_scan_error_at": None,
    "last_pool_scan_error": None,
    "last_pool_auto_enabled": [],
    "single_account_mode": SINGLE_ACCOUNT_MODE,
    "last_single_mode_scan_at": None,
    "last_single_mode_switch_at": None,
    "last_single_mode_switch": None,
    "last_single_mode_error_at": None,
    "last_single_mode_error": None,
}

SCHEMA_SQL = """
create table if not exists cpa_usage_events (
    id bigserial primary key,
    event_hash text not null unique,
    event_time timestamptz not null,
    collected_at timestamptz not null default now(),
    source text,
    auth_index text,
    provider text,
    model text,
    alias text,
    endpoint text,
    auth_type text,
    api_key text,
    request_id text,
    latency_ms integer,
    failed boolean not null default false,
    fail_status_code integer,
    fail_body text,
    input_tokens bigint not null default 0,
    output_tokens bigint not null default 0,
    reasoning_tokens bigint not null default 0,
    cached_tokens bigint not null default 0,
    cache_read_tokens bigint not null default 0,
    cache_creation_tokens bigint not null default 0,
    total_tokens bigint not null default 0,
    raw jsonb not null
);
create index if not exists idx_cpa_usage_events_time on cpa_usage_events (event_time desc);
create index if not exists idx_cpa_usage_events_source on cpa_usage_events (source);
create index if not exists idx_cpa_usage_events_model on cpa_usage_events (model);
create index if not exists idx_cpa_usage_events_failed on cpa_usage_events (failed);
create index if not exists idx_cpa_usage_events_request_id on cpa_usage_events (request_id);

create table if not exists cpa_usage_alerts (
    id bigserial primary key,
    alert_key text not null unique,
    account text,
    status text not null,
    severity text not null,
    title text not null,
    message text not null,
    reasons jsonb not null default '[]'::jsonb,
    window_hours integer not null default 24,
    first_seen_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    resolved_at timestamptz,
    occurrence_count integer not null default 1,
    last_snapshot jsonb not null default '{}'::jsonb
);
create index if not exists idx_cpa_usage_alerts_status on cpa_usage_alerts (status);
create index if not exists idx_cpa_usage_alerts_resolved on cpa_usage_alerts (resolved_at);
create index if not exists idx_cpa_usage_alerts_last_seen on cpa_usage_alerts (last_seen_at desc);
"""

INSERT_SQL = """
insert into cpa_usage_events (
    event_hash, event_time, source, auth_index, provider, model, alias, endpoint,
    auth_type, api_key, request_id, latency_ms, failed, fail_status_code, fail_body,
    input_tokens, output_tokens, reasoning_tokens, cached_tokens, cache_read_tokens,
    cache_creation_tokens, total_tokens, raw
) values (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20,
    $21, $22, $23::jsonb
)
on conflict (event_hash) do nothing
returning id;
"""


def json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def mask_key(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 12:
        return value[:3] + "***"
    return value[:8] + "***" + value[-6:]


def safe_basename(value: str) -> str:
    name = Path(value).name
    if not name or name in {".", ".."} or name != value:
        raise HTTPException(status_code=400, detail="invalid filename")
    if not re.match(r"^[A-Za-z0-9@._+-]+$", name):
        raise HTTPException(status_code=400, detail="invalid filename")
    return name


def normalize_plan(value: Optional[str]) -> str:
    plan = (value or "").strip().lower()
    if plan in {"plus", "team", "free", "pro", "enterprise"}:
        return plan
    return "unknown"


def classify_auth_plan(path: Path, data: dict[str, Any]) -> str:
    candidates = [
        data.get("planType"),
        data.get("plan_type"),
        data.get("chatgpt_plan_type"),
        (data.get("account") or {}).get("planType") if isinstance(data.get("account"), dict) else None,
        (data.get("account") or {}).get("plan_type") if isinstance(data.get("account"), dict) else None,
    ]
    filename = path.name.lower()
    if "team" in filename:
        candidates.insert(0, "team")
    if "plus" in filename:
        candidates.insert(0, "plus")
    if "free" in filename:
        candidates.append("free")
    for candidate in candidates:
        plan = normalize_plan(candidate)
        if plan != "unknown":
            return plan
    return "unknown"


def tier_for_plan(plan: str) -> str:
    return "primary" if normalize_plan(plan) in POOL_PRIMARY_PLANS else "fallback"


def load_disabled_meta() -> dict[str, Any]:
    if not CPA_DISABLED_META_FILE.exists():
        return {}
    try:
        return json.loads(CPA_DISABLED_META_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_disabled_meta(meta: dict[str, Any]) -> None:
    CPA_DISABLED_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CPA_DISABLED_META_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(CPA_DISABLED_META_FILE)


def read_auth_public_info(path: Path) -> dict[str, Any]:
    info = {
        "filename": path.name,
        "email": None,
        "type": None,
        "account_id": None,
        "expired": None,
        "last_refresh": None,
        "plan": "unknown",
        "tier": "fallback",
    }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in ("email", "type", "account_id", "expired", "last_refresh"):
            info[key] = data.get(key)
        info["plan"] = classify_auth_plan(path, data)
    except Exception:
        info["plan"] = classify_auth_plan(path, {})
        pass
    info["tier"] = tier_for_plan(str(info.get("plan") or "unknown"))
    if not info["email"]:
        name = path.name.removesuffix(".disabled").removesuffix(".json")
        if name.startswith("codex-"):
            name = name[6:]
        info["email"] = name.replace("-plus", "").replace("-free", "")
    return info


def list_auth_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    ignored = {"disabled_accounts.json", "disabled-meta.json", "pool_state.json", "single_mode_state.json"}
    return sorted([path for path in directory.iterdir() if path.is_file() and path.name not in ignored], key=lambda p: p.name.lower())


def load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_json_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        tmp.replace(path)
    except OSError:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            tmp.unlink()
        except OSError:
            pass


def move_unique(source: Path, target_dir: Path, suffix: str = "") -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{source.name}{suffix}"
    if target.exists():
        stem = source.name
        target = target_dir / f"{stem}.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}{suffix}"
    shutil.move(str(source), str(target))
    return target


async def restart_cpa_container() -> bool:
    if not Path(DOCKER_SOCKET).exists():
        return False
    transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET)
    async with httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=30) as client:
        response = await client.post(f"/containers/{CPA_CONTAINER_NAME}/restart", params={"t": 10})
        if response.status_code not in (204, 304):
            raise HTTPException(status_code=502, detail=f"failed to restart CPA: {response.text}")
    return True


async def list_pool_accounts() -> dict[str, Any]:
    CPA_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    CPA_STANDBY_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    CPA_COOLING_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    CPA_DISABLED_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    meta = load_disabled_meta()
    active = []
    for path in list_auth_files(CPA_AUTH_DIR):
        if path.is_file() and path.name != CPA_DISABLED_META_FILE.name:
            item = read_auth_public_info(path)
            item["status"] = "active"
            active.append(item)
    standby = []
    for path in list_auth_files(CPA_STANDBY_AUTH_DIR):
        item = read_auth_public_info(path)
        item["status"] = "standby"
        standby.append(item)
    cooling = []
    for path in list_auth_files(CPA_COOLING_AUTH_DIR):
        item = read_auth_public_info(path)
        item["status"] = "cooling"
        cooling.append(item)
    disabled = []
    for path in list_auth_files(CPA_DISABLED_AUTH_DIR):
        if not path.is_file() or path.name == CPA_DISABLED_META_FILE.name:
            continue
        item = read_auth_public_info(path)
        item["status"] = "disabled"
        record = meta.get(path.name) or {}
        item["reason"] = record.get("reason") or ""
        item["disabled_at"] = record.get("disabled_at")
        item["disabled_by"] = record.get("disabled_by")
        item["original_filename"] = record.get("original_filename")
        item["auto_enable_at"] = record.get("auto_enable_at")
        disabled.append(item)
    return {
        "single_account_mode": SINGLE_ACCOUNT_MODE,
        "tiered_pool_mode": POOL_TIERED_MODE,
        "tiered_primary_plans": sorted(POOL_PRIMARY_PLANS),
        "active_count": len(active),
        "standby_count": len(standby),
        "cooling_count": len(cooling),
        "disabled_count": len(disabled),
        "active": active,
        "standby": standby,
        "cooling": cooling,
        "disabled": disabled,
    }


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


async def auto_enable_due_accounts() -> list[str]:
    CPA_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    CPA_DISABLED_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    meta = load_disabled_meta()
    now = datetime.now(timezone.utc)
    enabled: list[str] = []
    for filename, record in list(meta.items()):
        auto_enable_at = parse_iso_datetime(record.get("auto_enable_at"))
        if not auto_enable_at or auto_enable_at > now:
            continue
        source = CPA_DISABLED_AUTH_DIR / filename
        if not source.exists() or not source.is_file():
            meta.pop(filename, None)
            continue
        original = record.get("original_filename")
        target_name = safe_basename(str(original)) if original else safe_basename(filename.removesuffix(".disabled"))
        target_base_dir = CPA_STANDBY_AUTH_DIR if (SINGLE_ACCOUNT_MODE or POOL_TIERED_MODE) else CPA_AUTH_DIR
        target = target_base_dir / target_name
        if target.exists():
            record["auto_enable_error"] = "target auth file already exists"
            record["last_auto_enable_attempt_at"] = now.isoformat()
            continue
        target_base_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(target))
        meta.pop(filename, None)
        enabled.append(target.name)
    save_disabled_meta(meta)
    if enabled:
        await restart_cpa_container()
    return enabled


def find_active_auth_by_account(account: str) -> Optional[Path]:
    needle = account.strip().lower()
    if not needle:
        return None
    for path in list_auth_files(CPA_AUTH_DIR):
        info = read_auth_public_info(path)
        email = str(info.get("email") or "").lower()
        filename = path.name.lower()
        if needle == email or needle in filename or email in needle:
            return path
    return None


def disabled_target_name(filename: str) -> str:
    return filename if filename.endswith(".disabled") else f"{filename}.disabled"


def disable_active_file(source: Path, reason: str, disabled_by: str, auto_enable_at: Optional[str] = None) -> Optional[str]:
    if not source.exists() or not source.is_file():
        return None
    CPA_DISABLED_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    target = CPA_DISABLED_AUTH_DIR / disabled_target_name(source.name)
    if target.exists():
        target = CPA_DISABLED_AUTH_DIR / f"{source.name}.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.disabled"
    original_filename = source.name
    shutil.move(str(source), str(target))
    meta = load_disabled_meta()
    meta[target.name] = {
        "reason": reason,
        "disabled_at": datetime.now(timezone.utc).isoformat(),
        "disabled_by": disabled_by,
        "original_filename": original_filename,
        "auto_enable_at": auto_enable_at,
    }
    save_disabled_meta(meta)
    return target.name


def quota_retry_at() -> str:
    return datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() + POOL_QUOTA_RETRY_SECONDS, tz=timezone.utc).isoformat()


def parse_quota_resets_at(fail_body: str | None) -> str | None:
    if not fail_body:
        return None
    try:
        data = json.loads(fail_body)
        resets_at = (data.get("error") or {}).get("resets_at")
        if resets_at and isinstance(resets_at, (int, float)):
            return datetime.fromtimestamp(float(resets_at), tz=timezone.utc).isoformat()
    except Exception:
        pass
    return None
    if not fail_body:
        return None
    try:
        data = json.loads(fail_body)
        resets_at = (data.get("error") or {}).get("resets_at")
        if resets_at and isinstance(resets_at, (int, float)):
            return datetime.fromtimestamp(float(resets_at), tz=timezone.utc).isoformat()
    except Exception:
        pass
    return None


async def auto_disable_failed_active_accounts() -> list[dict[str, Any]]:
    if not POOL_TIERED_MODE:
        return []
    assert db_pool is not None
    state = load_json_file(CPA_POOL_STATE_FILE)
    if "last_tiered_failure_event_id" not in state:
        latest_id = await db_pool.fetchval("select coalesce(max(id), 0) from cpa_usage_events")
        state["last_tiered_failure_event_id"] = int(latest_id or 0)
        save_json_file(CPA_POOL_STATE_FILE, state)
        return []
    last_event_id = int(state.get("last_tiered_failure_event_id") or 0)
    rows = await db_pool.fetch(
        """
        select id, source, auth_index, fail_status_code, fail_body
        from cpa_usage_events
        where id > $1
          and failed = true
          and (
            fail_status_code in (401, 403, 429)
            or lower(coalesce(fail_body,'')) like '%usage_limit%'
            or lower(coalesce(fail_body,'')) like '%usage limit%'
            or lower(coalesce(fail_body,'')) like '%quota%'
            or lower(coalesce(fail_body,'')) like '%invalidated oauth token%'
          )
        order by id asc
        limit 100
        """,
        last_event_id,
    )
    disabled: list[dict[str, Any]] = []
    max_seen = last_event_id
    for row in rows:
        event_id = int(row["id"])
        max_seen = max(max_seen, event_id)
        account = row["source"] or row["auth_index"] or ""
        source = find_active_auth_by_account(str(account))
        if not source:
            continue
        body = (row["fail_body"] or "").lower()
        status = row["fail_status_code"]
        if status in (401, 403) or "invalidated oauth token" in body:
            reason = "auto_disable_auth_failed"
            auto_enable_at = None
        else:
            reason = "auto_disable_quota_or_usage_limit"
            auto_enable_at = parse_quota_resets_at(row["fail_body"]) or quota_retry_at()
        target_name = disable_active_file(source, reason, "tiered-pool", auto_enable_at)
        if target_name:
            disabled.append({
                "event_id": event_id,
                "account": account,
                "filename": target_name,
                "reason": reason,
                "auto_enable_at": auto_enable_at,
            })
    if max_seen != last_event_id:
        state["last_tiered_failure_event_id"] = max_seen
        save_json_file(CPA_POOL_STATE_FILE, state)
    if disabled:
        await restart_cpa_container()
    return disabled


async def reconcile_tiered_pool() -> dict[str, Any]:
    if not POOL_TIERED_MODE:
        return {"enabled": False, "moves": []}
    CPA_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    CPA_STANDBY_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    moves: list[dict[str, str]] = []

    active_files = list_auth_files(CPA_AUTH_DIR)
    standby_files = list_auth_files(CPA_STANDBY_AUTH_DIR)
    active_primary = [p for p in active_files if tier_for_plan(str(read_auth_public_info(p).get("plan"))) == "primary"]
    standby_primary = [p for p in standby_files if tier_for_plan(str(read_auth_public_info(p).get("plan"))) == "primary"]
    primary_available = bool(active_primary or standby_primary)

    if primary_available:
        for path in list_auth_files(CPA_AUTH_DIR):
            if tier_for_plan(str(read_auth_public_info(path).get("plan"))) != "primary":
                target = move_unique(path, CPA_STANDBY_AUTH_DIR)
                moves.append({"action": "demote_fallback", "from": path.name, "to": target.name})
        for path in list_auth_files(CPA_STANDBY_AUTH_DIR):
            if tier_for_plan(str(read_auth_public_info(path).get("plan"))) == "primary":
                target = CPA_AUTH_DIR / path.name
                shutil.move(str(path), str(target))
                moves.append({"action": "promote_primary", "from": path.name, "to": target.name})
    else:
        for path in list_auth_files(CPA_STANDBY_AUTH_DIR):
            target = CPA_AUTH_DIR / path.name
            shutil.move(str(path), str(target))
            moves.append({"action": "promote_fallback", "from": path.name, "to": target.name})

    result = {
        "enabled": True,
        "primary_available": primary_available,
        "moves": moves,
        "active_count": len(list_auth_files(CPA_AUTH_DIR)),
        "standby_count": len(list_auth_files(CPA_STANDBY_AUTH_DIR)),
    }
    if moves:
        await restart_cpa_container()
    return result


async def activate_next_standby(reason: str, event_id: Optional[int] = None, fail_status_code: Optional[int] = None) -> Optional[dict[str, Any]]:
    active_files = list_auth_files(CPA_AUTH_DIR)
    standby_files = list_auth_files(CPA_STANDBY_AUTH_DIR)
    if not active_files or not standby_files:
        return None
    active = active_files[0]
    cooling_target = move_unique(active, CPA_COOLING_AUTH_DIR, suffix=".cooling")
    next_file = standby_files[0]
    new_active = CPA_AUTH_DIR / next_file.name
    shutil.move(str(next_file), str(new_active))
    state = load_json_file(CPA_SINGLE_MODE_STATE_FILE)
    state.update({
        "last_switch_at": datetime.now(timezone.utc).isoformat(),
        "last_reason": reason,
        "last_event_id": event_id,
        "last_fail_status_code": fail_status_code,
        "last_cooling_file": cooling_target.name,
        "last_active_file": new_active.name,
    })
    save_json_file(CPA_SINGLE_MODE_STATE_FILE, state)
    await restart_cpa_container()
    return {
        "reason": reason,
        "event_id": event_id,
        "fail_status_code": fail_status_code,
        "cooling_file": cooling_target.name,
        "active_file": new_active.name,
        "standby_remaining": max(len(standby_files) - 1, 0),
    }


async def scan_single_account_switch() -> Optional[dict[str, Any]]:
    if not SINGLE_ACCOUNT_MODE:
        return None
    assert db_pool is not None
    active_files = list_auth_files(CPA_AUTH_DIR)
    if len(active_files) != 1:
        return None
    active_info = read_auth_public_info(active_files[0])
    active_email = (active_info.get("email") or "").lower()
    if not active_email:
        return None
    state = load_json_file(CPA_SINGLE_MODE_STATE_FILE)
    last_event_id = int(state.get("last_event_id") or 0)
    row = await db_pool.fetchrow(
        """
        select id, source, fail_status_code, fail_body, event_time
        from cpa_usage_events
        where id > $1
          and lower(coalesce(source,'')) = $2
          and failed = true
          and (
            fail_status_code in (401, 403, 429)
            or lower(coalesce(fail_body,'')) like '%usage_limit%'
            or lower(coalesce(fail_body,'')) like '%quota%'
            or lower(coalesce(fail_body,'')) like '%invalidated oauth token%'
          )
        order by id desc
        limit 1
        """,
        last_event_id,
        active_email,
    )
    if not row:
        return None
    body = (row["fail_body"] or "").lower()
    status = row["fail_status_code"]
    if status in (401, 403) or "invalidated oauth token" in body:
        reason = "auth_failed"
    elif status == 429 or "usage_limit" in body or "quota" in body:
        reason = "quota_or_usage_limit"
    else:
        reason = "request_failed"
    return await activate_next_standby(reason, event_id=int(row["id"]), fail_status_code=status)


def stable_event_hash(event: dict[str, Any]) -> str:
    identity = {
        "request_id": event.get("request_id"),
        "timestamp": event.get("timestamp"),
        "source": event.get("source"),
        "auth_index": event.get("auth_index"),
        "model": event.get("model"),
        "endpoint": event.get("endpoint"),
    }
    raw = json.dumps(identity if identity.get("request_id") else event, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_time(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def event_to_row(event: dict[str, Any]) -> tuple[Any, ...]:
    tokens = event.get("tokens") or {}
    fail = event.get("fail") or {}
    return (
        stable_event_hash(event),
        parse_time(event.get("timestamp")),
        event.get("source"),
        event.get("auth_index"),
        event.get("provider"),
        event.get("model"),
        event.get("alias"),
        event.get("endpoint"),
        event.get("auth_type"),
        event.get("api_key"),
        event.get("request_id"),
        event.get("latency_ms"),
        bool(event.get("failed", False)),
        fail.get("status_code"),
        fail.get("body"),
        int(tokens.get("input_tokens") or 0),
        int(tokens.get("output_tokens") or 0),
        int(tokens.get("reasoning_tokens") or 0),
        int(tokens.get("cached_tokens") or 0),
        int(tokens.get("cache_read_tokens") or 0),
        int(tokens.get("cache_creation_tokens") or 0),
        int(tokens.get("total_tokens") or 0),
        json.dumps(event, ensure_ascii=False),
    )


async def init_db() -> None:
    assert db_pool is not None
    async with db_pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)


async def poll_once() -> int:
    assert db_pool is not None
    stats["last_poll_at"] = datetime.now(timezone.utc).isoformat()
    url = f"{CPA_BASE_URL}/v0/management/usage-queue"
    headers = {"Authorization": f"Bearer {CPA_MANAGEMENT_KEY}"}
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        response = await client.get(url, headers=headers, params={"count": POLL_BATCH_SIZE})
        response.raise_for_status()
        events = response.json()
    if not isinstance(events, list):
        raise RuntimeError(f"unexpected usage-queue payload: {type(events).__name__}")
    inserted = 0
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            for event in events:
                if not isinstance(event, dict):
                    continue
                stats["events_seen"] += 1
                row_id = await conn.fetchval(INSERT_SQL, *event_to_row(event))
                if row_id is not None:
                    inserted += 1
    stats["events_inserted"] += inserted
    stats["last_success_at"] = datetime.now(timezone.utc).isoformat()
    stats["last_error"] = None
    return inserted


def severity_for_status(status: str) -> str:
    return {
        "quota_exceeded": "critical",
        "auth_failed": "critical",
        "unstable": "warning",
        "slow": "warning",
        "inactive": "info",
    }.get(status, "info")


def title_for_status(status: str) -> str:
    return {
        "quota_exceeded": "账号配额耗尽",
        "auth_failed": "账号认证失败",
        "unstable": "账号请求不稳定",
        "slow": "账号响应偏慢",
        "inactive": "账号长时间未调用",
    }.get(status, "账号状态异常")


async def compute_account_health_rows(hours: int, inactive_hours: int, slow_ms: int) -> list[dict[str, Any]]:
    assert db_pool is not None
    rows = await db_pool.fetch(
        """
        with accounts as (
          select coalesce(source, auth_index, 'unknown') as account,
                 max(auth_index) as auth_index,
                 count(*) as requests,
                 coalesce(sum(input_tokens),0) as input_tokens,
                 coalesce(sum(output_tokens),0) as output_tokens,
                 coalesce(sum(reasoning_tokens),0) as reasoning_tokens,
                 coalesce(sum(total_tokens),0) as total_tokens,
                 coalesce(sum(case when failed then 1 else 0 end),0) as failed_requests,
                 coalesce(sum(case when failed and fail_status_code = 429 then 1 else 0 end),0) as quota_429_requests,
                 coalesce(sum(case when failed and fail_status_code in (401,403) then 1 else 0 end),0) as auth_failed_requests,
                 coalesce(round(avg(latency_ms)::numeric, 2),0) as avg_latency_ms,
                 max(event_time) as last_event_time
          from cpa_usage_events
          where event_time >= now() - make_interval(hours => $1::int)
          group by coalesce(source, auth_index, 'unknown')
        )
        select *,
               case when requests > 0 then round((failed_requests::numeric / requests::numeric) * 100, 2) else 0 end as failure_rate,
               case when last_event_time is null then null else extract(epoch from (now() - last_event_time)) / 3600 end as hours_since_last_event
        from accounts
        order by
          case
            when quota_429_requests > 0 then 1
            when auth_failed_requests > 0 then 2
            when requests > 0 and (failed_requests::numeric / greatest(requests, 1)) >= 0.2 then 3
            when avg_latency_ms >= $3 then 4
            when last_event_time < now() - make_interval(hours => $2::int) then 5
            else 9
          end,
          total_tokens desc,
          requests desc
        """,
        hours,
        inactive_hours,
        slow_ms,
    )
    result = []
    for row in rows:
        item = dict(row)
        requests = int(item.get("requests") or 0)
        failure_rate = float(item.get("failure_rate") or 0)
        avg_latency_ms = float(item.get("avg_latency_ms") or 0)
        hours_since_last = item.get("hours_since_last_event")
        quota_429 = int(item.get("quota_429_requests") or 0)
        auth_failed = int(item.get("auth_failed_requests") or 0)
        status = "healthy"
        reasons = []
        if quota_429 > 0:
            status = "quota_exceeded"
            reasons.append(f"{quota_429} 次 429 配额耗尽")
        elif auth_failed > 0:
            status = "auth_failed"
            reasons.append(f"{auth_failed} 次 401/403 认证失败")
        elif requests > 0 and failure_rate >= 20:
            status = "unstable"
            reasons.append(f"失败率 {failure_rate}%")
        elif avg_latency_ms >= slow_ms:
            status = "slow"
            reasons.append(f"平均延迟 {round(avg_latency_ms)}ms")
        if hours_since_last is not None and float(hours_since_last) >= inactive_hours:
            if status == "healthy":
                status = "inactive"
            reasons.append(f"{round(float(hours_since_last), 1)} 小时未调用")
        if not reasons:
            reasons.append("近窗口正常")
        item["status"] = status
        item["reasons"] = reasons
        item["last_event_time"] = item["last_event_time"].isoformat() if item["last_event_time"] else None
        if item.get("hours_since_last_event") is not None:
            item["hours_since_last_event"] = round(float(item["hours_since_last_event"]), 2)
        result.append(item)
    return result


async def scan_alerts_once() -> int:
    assert db_pool is not None
    stats["last_alert_scan_at"] = datetime.now(timezone.utc).isoformat()
    health_rows = await compute_account_health_rows(ALERT_WINDOW_HOURS, ALERT_INACTIVE_HOURS, ALERT_SLOW_MS)
    active_keys = set()
    changed = 0
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            for item in health_rows:
                status = item.get("status")
                if status == "healthy":
                    continue
                account = item.get("account") or "unknown"
                alert_key = f"account:{account}:{status}"
                active_keys.add(alert_key)
                severity = severity_for_status(status)
                title = title_for_status(status)
                message = f"{account}: {'；'.join(item.get('reasons') or [])}"
                row = await conn.fetchrow(
                    """
                    insert into cpa_usage_alerts (
                        alert_key, account, status, severity, title, message, reasons,
                        window_hours, first_seen_at, last_seen_at, resolved_at, occurrence_count, last_snapshot
                    ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,now(),now(),null,1,$9::jsonb)
                    on conflict (alert_key) do update set
                        account = excluded.account,
                        status = excluded.status,
                        severity = excluded.severity,
                        title = excluded.title,
                        message = excluded.message,
                        reasons = excluded.reasons,
                        window_hours = excluded.window_hours,
                        last_seen_at = now(),
                        resolved_at = null,
                        occurrence_count = cpa_usage_alerts.occurrence_count + 1,
                        last_snapshot = excluded.last_snapshot
                    returning id
                    """,
                    alert_key,
                    account,
                    status,
                    severity,
                    title,
                    message,
                    json.dumps(item.get("reasons") or [], ensure_ascii=False),
                    ALERT_WINDOW_HOURS,
                    json.dumps(item, ensure_ascii=False, default=json_default),
                )
                if row:
                    changed += 1
            if active_keys:
                await conn.execute(
                    """
                    update cpa_usage_alerts
                    set resolved_at = now(), last_seen_at = now()
                    where resolved_at is null and alert_key <> all($1::text[])
                    """,
                    list(active_keys),
                )
            else:
                await conn.execute(
                    """
                    update cpa_usage_alerts
                    set resolved_at = now(), last_seen_at = now()
                    where resolved_at is null
                    """
                )
            open_count = await conn.fetchval("select count(*) from cpa_usage_alerts where resolved_at is null")
            stats["open_alerts"] = int(open_count or 0)
    stats["last_alert_error"] = None
    return changed


async def alert_loop() -> None:
    while True:
        try:
            await scan_alerts_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            stats["last_alert_error_at"] = datetime.now(timezone.utc).isoformat()
            stats["last_alert_error"] = repr(exc)
        await asyncio.sleep(ALERT_INTERVAL_SECONDS)


async def pool_auto_enable_loop() -> None:
    while True:
        try:
            stats["last_pool_scan_at"] = datetime.now(timezone.utc).isoformat()
            enabled = await auto_enable_due_accounts()
            if enabled:
                stats["last_pool_auto_enabled"] = enabled
            if POOL_TIERED_MODE:
                disabled = await auto_disable_failed_active_accounts()
                reconciled = await reconcile_tiered_pool()
                stats["last_tiered_reconcile_at"] = datetime.now(timezone.utc).isoformat()
                stats["last_tiered_reconcile"] = {"auto_disabled": disabled, **reconciled}
                stats["last_tiered_error"] = None
            stats["last_pool_scan_error"] = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            stats["last_pool_scan_error_at"] = datetime.now(timezone.utc).isoformat()
            stats["last_pool_scan_error"] = repr(exc)
            stats["last_tiered_error_at"] = datetime.now(timezone.utc).isoformat()
            stats["last_tiered_error"] = repr(exc)
        await asyncio.sleep(POOL_AUTO_ENABLE_INTERVAL_SECONDS)


async def single_account_switch_loop() -> None:
    while True:
        try:
            stats["last_single_mode_scan_at"] = datetime.now(timezone.utc).isoformat()
            switched = await scan_single_account_switch()
            if switched:
                stats["last_single_mode_switch_at"] = datetime.now(timezone.utc).isoformat()
                stats["last_single_mode_switch"] = switched
            stats["last_single_mode_error"] = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            stats["last_single_mode_error_at"] = datetime.now(timezone.utc).isoformat()
            stats["last_single_mode_error"] = repr(exc)
        await asyncio.sleep(SINGLE_ACCOUNT_SWITCH_INTERVAL_SECONDS)


async def poll_loop() -> None:
    while True:
        try:
            await poll_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # keep the collector alive; expose the error via /health
            stats["last_error_at"] = datetime.now(timezone.utc).isoformat()
            stats["last_error"] = repr(exc)
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def require_key(
    request: Request,
    x_usage_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    key: Optional[str] = Query(default=None),
) -> None:
    bearer = None
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization.split(" ", 1)[1].strip()
    provided = x_usage_key or bearer or key
    if provided != USAGE_API_KEY:
        raise HTTPException(status_code=401, detail="invalid usage api key")


@app.on_event("startup")
async def on_startup() -> None:
    global db_pool, poller_task
    db_pool = await asyncpg.create_pool(DB_DSN, min_size=1, max_size=5)
    await init_db()
    poller_task = asyncio.create_task(poll_loop())
    global alert_task, pool_task, single_mode_task
    alert_task = asyncio.create_task(alert_loop())
    pool_task = asyncio.create_task(pool_auto_enable_loop())
    single_mode_task = asyncio.create_task(single_account_switch_loop())


@app.on_event("shutdown")
async def on_shutdown() -> None:
    global poller_task, alert_task, pool_task, single_mode_task, db_pool
    if single_mode_task:
        single_mode_task.cancel()
        try:
            await single_mode_task
        except asyncio.CancelledError:
            pass
    if pool_task:
        pool_task.cancel()
        try:
            await pool_task
        except asyncio.CancelledError:
            pass
    if alert_task:
        alert_task.cancel()
        try:
            await alert_task
        except asyncio.CancelledError:
            pass
    if poller_task:
        poller_task.cancel()
        try:
            await poller_task
        except asyncio.CancelledError:
            pass
    if db_pool:
        await db_pool.close()


@app.get("/health")
async def health() -> dict[str, Any]:
    assert db_pool is not None
    async with db_pool.acquire() as conn:
        count = await conn.fetchval("select count(*) from cpa_usage_events")
    return {"ok": stats.get("last_error") is None, "stored_events": count, "stats": stats}


@app.post("/api/poll", dependencies=[Depends(require_key)])
async def manual_poll() -> dict[str, Any]:
    inserted = await poll_once()
    return {"inserted": inserted, "stats": stats}


@app.get("/api/recent", dependencies=[Depends(require_key)])
async def recent(
    limit: int = Query(default=100, ge=1, le=500),
    failed: Optional[bool] = None,
    source: Optional[str] = None,
    model: Optional[str] = None,
) -> list[dict[str, Any]]:
    assert db_pool is not None
    clauses = []
    params: list[Any] = []
    if failed is not None:
        params.append(failed)
        clauses.append(f"failed = ${len(params)}")
    if source:
        params.append(f"%{source}%")
        clauses.append(f"source ilike ${len(params)}")
    if model:
        params.append(model)
        clauses.append(f"model = ${len(params)}")
    where = "where " + " and ".join(clauses) if clauses else ""
    params.append(limit)
    rows = await db_pool.fetch(
        f"""
        select id, event_time, source, auth_index, provider, model, alias, endpoint, auth_type,
               api_key, request_id, latency_ms, failed, fail_status_code, fail_body,
               input_tokens, output_tokens, reasoning_tokens, cached_tokens,
               cache_read_tokens, cache_creation_tokens, total_tokens
        from cpa_usage_events
        {where}
        order by event_time desc, id desc
        limit ${len(params)}
        """,
        *params,
    )
    result = []
    for row in rows:
        item = dict(row)
        item["event_time"] = item["event_time"].isoformat()
        item["api_key"] = mask_key(item.get("api_key"))
        result.append(item)
    return result


@app.get("/api/summary/overview", dependencies=[Depends(require_key)])
async def overview(hours: int = Query(default=24, ge=1, le=24 * 31)) -> dict[str, Any]:
    assert db_pool is not None
    row = await db_pool.fetchrow(
        """
        select count(*) as requests,
               coalesce(sum(input_tokens),0) as input_tokens,
               coalesce(sum(output_tokens),0) as output_tokens,
               coalesce(sum(reasoning_tokens),0) as reasoning_tokens,
               coalesce(sum(total_tokens),0) as total_tokens,
               coalesce(sum(case when failed then 1 else 0 end),0) as failed_requests,
               coalesce(round(avg(latency_ms)::numeric, 2),0) as avg_latency_ms
        from cpa_usage_events
        where event_time >= now() - make_interval(hours => $1::int)
        """,
        hours,
    )
    return dict(row)


@app.get("/api/summary/accounts", dependencies=[Depends(require_key)])
async def accounts(hours: int = Query(default=24, ge=1, le=24 * 31)) -> list[dict[str, Any]]:
    assert db_pool is not None
    rows = await db_pool.fetch(
        """
        select coalesce(source, auth_index, 'unknown') as account,
               max(auth_index) as auth_index,
               count(*) as requests,
               coalesce(sum(input_tokens),0) as input_tokens,
               coalesce(sum(output_tokens),0) as output_tokens,
               coalesce(sum(reasoning_tokens),0) as reasoning_tokens,
               coalesce(sum(total_tokens),0) as total_tokens,
               coalesce(sum(case when failed then 1 else 0 end),0) as failed_requests,
               max(event_time) as last_event_time
        from cpa_usage_events
        where event_time >= now() - make_interval(hours => $1::int)
        group by coalesce(source, auth_index, 'unknown')
        order by total_tokens desc, requests desc
        """,
        hours,
    )
    return [{**dict(row), "last_event_time": row["last_event_time"].isoformat() if row["last_event_time"] else None} for row in rows]


@app.get("/api/summary/models", dependencies=[Depends(require_key)])
async def models(hours: int = Query(default=24, ge=1, le=24 * 31)) -> list[dict[str, Any]]:
    assert db_pool is not None
    rows = await db_pool.fetch(
        """
        select coalesce(model, 'unknown') as model,
               count(*) as requests,
               coalesce(sum(input_tokens),0) as input_tokens,
               coalesce(sum(output_tokens),0) as output_tokens,
               coalesce(sum(reasoning_tokens),0) as reasoning_tokens,
               coalesce(sum(total_tokens),0) as total_tokens,
               coalesce(sum(case when failed then 1 else 0 end),0) as failed_requests,
               max(event_time) as last_event_time
        from cpa_usage_events
        where event_time >= now() - make_interval(hours => $1::int)
        group by coalesce(model, 'unknown')
        order by total_tokens desc, requests desc
        """,
        hours,
    )
    return [{**dict(row), "last_event_time": row["last_event_time"].isoformat() if row["last_event_time"] else None} for row in rows]


@app.get("/api/health/accounts", dependencies=[Depends(require_key)])
async def account_health(
    hours: int = Query(default=24, ge=1, le=24 * 31),
    inactive_hours: int = Query(default=12, ge=1, le=24 * 31),
    slow_ms: int = Query(default=30000, ge=1000, le=600000),
) -> list[dict[str, Any]]:
    return await compute_account_health_rows(hours, inactive_hours, slow_ms)


@app.post("/api/alerts/scan", dependencies=[Depends(require_key)])
async def manual_alert_scan() -> dict[str, Any]:
    changed = await scan_alerts_once()
    return {"changed": changed, "open_alerts": stats.get("open_alerts", 0), "stats": stats}


@app.get("/api/alerts", dependencies=[Depends(require_key)])
async def alerts(
    include_resolved: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    assert db_pool is not None
    where = "" if include_resolved else "where resolved_at is null"
    rows = await db_pool.fetch(
        f"""
        select id, alert_key, account, status, severity, title, message, reasons,
               window_hours, first_seen_at, last_seen_at, resolved_at, occurrence_count, last_snapshot
        from cpa_usage_alerts
        {where}
        order by resolved_at nulls first, last_seen_at desc, id desc
        limit $1
        """,
        limit,
    )
    result = []
    for row in rows:
        item = dict(row)
        for key in ("first_seen_at", "last_seen_at", "resolved_at"):
            if item.get(key):
                item[key] = item[key].isoformat()
        result.append(item)
    return result



@app.get("/api/failures", dependencies=[Depends(require_key)])
async def failures(hours: int = Query(default=24, ge=1, le=24 * 31), limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    assert db_pool is not None
    rows = await db_pool.fetch(
        """
        select id, event_time, source, auth_index, provider, model, endpoint,
               request_id, latency_ms, fail_status_code, fail_body
        from cpa_usage_events
        where failed = true and event_time >= now() - make_interval(hours => $1::int)
        order by event_time desc, id desc
        limit $2
        """,
        hours,
        limit,
    )
    return [{**dict(row), "event_time": row["event_time"].isoformat()} for row in rows]


@app.get("/api/pool/accounts", dependencies=[Depends(require_key)])
async def pool_accounts() -> dict[str, Any]:
    return await list_pool_accounts()


@app.post("/api/pool/disable", dependencies=[Depends(require_key)])
async def pool_disable(request: Request) -> dict[str, Any]:
    body = await request.json()
    filename = safe_basename(str(body.get("filename") or ""))
    reason = str(body.get("reason") or "manual_disable").strip()[:500]
    source = CPA_AUTH_DIR / filename
    if not source.exists() or not source.is_file():
        raise HTTPException(status_code=404, detail="active auth file not found")
    CPA_DISABLED_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    target_name = filename if filename.endswith(".disabled") else f"{filename}.disabled"
    target = CPA_DISABLED_AUTH_DIR / target_name
    if target.exists():
        raise HTTPException(status_code=409, detail="disabled auth file already exists")
    shutil.move(str(source), str(target))
    meta = load_disabled_meta()
    meta[target.name] = {
        "reason": reason,
        "disabled_at": datetime.now(timezone.utc).isoformat(),
        "disabled_by": "usage-panel",
        "original_filename": filename,
        "auto_enable_at": body.get("auto_enable_at"),
    }
    save_disabled_meta(meta)
    restarted = await restart_cpa_container()
    return {"ok": True, "filename": target.name, "reason": reason, "restarted": restarted, **await list_pool_accounts()}


@app.post("/api/pool/enable", dependencies=[Depends(require_key)])
async def pool_enable(request: Request) -> dict[str, Any]:
    body = await request.json()
    filename = safe_basename(str(body.get("filename") or ""))
    source = CPA_DISABLED_AUTH_DIR / filename
    if not source.exists() or not source.is_file():
        raise HTTPException(status_code=404, detail="disabled auth file not found")
    meta = load_disabled_meta()
    original = meta.get(filename, {}).get("original_filename")
    if original:
        target_name = safe_basename(str(original))
    else:
        target_name = filename.removesuffix(".disabled")
    if not target_name:
        raise HTTPException(status_code=400, detail="invalid target filename")
    target = CPA_AUTH_DIR / target_name
    if target.exists():
        raise HTTPException(status_code=409, detail="active auth file already exists")
    CPA_AUTH_DIR.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(target))
    meta.pop(filename, None)
    save_disabled_meta(meta)
    restarted = await restart_cpa_container()
    return {"ok": True, "filename": target.name, "restarted": restarted, **await list_pool_accounts()}


@app.post("/api/pool/auto-enable-scan", dependencies=[Depends(require_key)])
async def pool_auto_enable_scan() -> dict[str, Any]:
    enabled = await auto_enable_due_accounts()
    return {"ok": True, "enabled": enabled, **await list_pool_accounts()}


@app.post("/api/pool/tiered-reconcile", dependencies=[Depends(require_key)])
async def pool_tiered_reconcile() -> dict[str, Any]:
    disabled = await auto_disable_failed_active_accounts()
    reconciled = await reconcile_tiered_pool()
    stats["last_tiered_reconcile_at"] = datetime.now(timezone.utc).isoformat()
    stats["last_tiered_reconcile"] = {"auto_disabled": disabled, **reconciled}
    return {"ok": True, "auto_disabled": disabled, "reconciled": reconciled, **await list_pool_accounts()}


@app.post("/api/pool/single-switch-scan", dependencies=[Depends(require_key)])
async def pool_single_switch_scan() -> dict[str, Any]:
    switched = await scan_single_account_switch()
    return {"ok": True, "switched": switched, **await list_pool_accounts()}


@app.get("/metrics", response_class=PlainTextResponse, dependencies=[Depends(require_key)])
async def metrics() -> str:
    assert db_pool is not None
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            select count(*) as requests,
                   coalesce(sum(total_tokens),0) as total_tokens,
                   coalesce(sum(case when failed then 1 else 0 end),0) as failures
            from cpa_usage_events
            """
        )
    return "\n".join([
        f"cpa_usage_requests_total {row['requests']}",
        f"cpa_usage_tokens_total {row['total_tokens']}",
        f"cpa_usage_failures_total {row['failures']}",
        f"cpa_usage_collector_events_inserted {stats['events_inserted']}",
        f"cpa_usage_open_alerts {stats.get('open_alerts', 0)}",
    ]) + "\n"


DASHBOARD_HTML = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CPA Usage Keeper</title>
  <style>
    :root { color-scheme: light; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f7f7f4; color: #202124; }
    main { max-width: 1180px; margin: 0 auto; padding: 28px 20px 48px; }
    header { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 22px; }
    h1 { font-size: 28px; margin: 0; }
    .bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    input, select, button { height: 36px; border: 1px solid #d7d7d0; border-radius: 6px; padding: 0 10px; font: inherit; background: #fff; }
    button { cursor: pointer; background: #202124; color: #fff; border-color: #202124; }
    button.secondary { background: #fff; color: #202124; }
    button.danger { background: #fff; color: #b91c1c; border-color: #fecaca; }
    button.small { height: 28px; padding: 0 8px; font-size: 12px; }
    .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 16px 0; }
    .card { background: #fff; border: 1px solid #e0dfd8; border-radius: 8px; padding: 14px; }
    .label { color: #6b6b63; font-size: 13px; }
    .value { font-size: 24px; font-weight: 700; margin-top: 6px; }
    section { background: #fff; border: 1px solid #e0dfd8; border-radius: 8px; margin-top: 14px; overflow: hidden; }
    section h2 { font-size: 17px; padding: 14px 16px; margin: 0; border-bottom: 1px solid #ecebe5; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 9px 10px; border-bottom: 1px solid #efeee9; text-align: left; vertical-align: top; }
    th { color: #66665f; background: #fafaf7; font-weight: 600; }
    .ok { color: #15803d; }
    .bad { color: #b91c1c; }
    .warn { color: #b45309; }
    .critical { color: #b91c1c; font-weight: 700; }
    .pill { display: inline-flex; align-items: center; height: 22px; padding: 0 8px; border-radius: 999px; background: #f1f1ec; font-size: 12px; }
    .muted { color: #777; }
    .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
    @media (max-width: 840px) { .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); } header { align-items: flex-start; flex-direction: column; } }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>CPA Usage Keeper</h1>
      <div class="muted">持久化记录 CPA 账号池调用、token、失败和 429 情况。</div>
    </div>
    <div class="bar">
      <input id="key" type="password" placeholder="统计查询密钥" />
      <select id="hours"><option value="1">1小时</option><option value="24" selected>24小时</option><option value="168">7天</option><option value="720">30天</option></select>
      <button id="save">保存密钥</button>
      <button id="refresh" class="secondary">刷新</button>
    </div>
  </header>
  <div id="status" class="muted"></div>
  <div class="cards">
    <div class="card"><div class="label">请求数</div><div class="value" id="requests">-</div></div>
    <div class="card"><div class="label">总 tokens</div><div class="value" id="tokens">-</div></div>
    <div class="card"><div class="label">失败数</div><div class="value" id="failures">-</div></div>
    <div class="card"><div class="label">平均延迟 ms</div><div class="value" id="latency">-</div></div>
  </div>
  <section><h2>当前告警</h2><div id="alerts"></div></section>
  <section><h2>账号池管理</h2><div id="pool"></div></section>
  <section><h2>账号健康</h2><div id="accountHealth"></div></section>
  <section><h2>账号汇总</h2><div id="accounts"></div></section>
  <section><h2>模型汇总</h2><div id="models"></div></section>
  <section><h2>最近请求</h2><div id="recent"></div></section>
</main>
<script>
const $ = id => document.getElementById(id);
const fmt = n => Number(n || 0).toLocaleString();
const keyInput = $('key');
keyInput.value = localStorage.getItem('cpa_usage_key') || '';
$('save').onclick = () => { localStorage.setItem('cpa_usage_key', keyInput.value); load(); };
$('refresh').onclick = () => load();
$('hours').onchange = () => load();
async function api(path, options = {}) {
  const key = keyInput.value || localStorage.getItem('cpa_usage_key') || '';
  const headers = { 'X-Usage-Key': key, ...(options.headers || {}) };
  const res = await fetch('api/' + path, { ...options, headers });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}
async function postApi(path, body) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
}
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
async function disableAccount(filename) {
  const reason = prompt('下线原因', 'manual_disable');
  if (reason === null) return;
  $('status').textContent = '正在下线账号并重启 CPA...';
  await postApi('pool/disable', { filename, reason });
  await load();
}
async function enableAccount(filename) {
  if (!confirm('确认重新上线这个账号？上线后会回到 CPA 轮询池。')) return;
  $('status').textContent = '正在重新上线账号并重启 CPA...';
  await postApi('pool/enable', { filename });
  await load();
}
function table(rows, cols) {
  if (!rows.length) return '<div style="padding:14px" class="muted">暂无数据</div>';
  return '<table><thead><tr>' + cols.map(c => `<th>${c[0]}</th>`).join('') + '</tr></thead><tbody>' + rows.map(r => '<tr>' + cols.map(c => `<td>${c[2] ? c[2](r[c[1]], r) : (r[c[1]] ?? '')}</td>`).join('') + '</tr>').join('') + '</tbody></table>';
}
async function load() {
  try {
    $('status').textContent = '加载中...';
    const h = $('hours').value;
    const [overview, alerts, pool, health, accounts, models, recent] = await Promise.all([
      api(`summary/overview?hours=${h}`),
      api('alerts?limit=50'),
      api('pool/accounts'),
      api(`health/accounts?hours=${h}`),
      api(`summary/accounts?hours=${h}`),
      api(`summary/models?hours=${h}`),
      api('recent?limit=80')
    ]);
    $('requests').textContent = fmt(overview.requests);
    $('tokens').textContent = fmt(overview.total_tokens);
    $('failures').textContent = fmt(overview.failed_requests);
    $('latency').textContent = fmt(overview.avg_latency_ms);
    const statusText = {healthy:'健康', quota_exceeded:'配额耗尽', auth_failed:'认证失败', unstable:'不稳定', slow:'慢', inactive:'不活跃'};
    const statusClass = s => s === 'healthy' ? 'ok' : (s === 'slow' || s === 'inactive' || s === 'unstable' ? 'warn' : 'bad');
    const severityText = {critical:'严重', warning:'警告', info:'提示'};
    const severityClass = s => s === 'critical' ? 'critical' : (s === 'warning' ? 'warn' : 'muted');
    $('alerts').innerHTML = table(alerts, [
      ['级别','severity', v => `<span class="pill ${severityClass(v)}">${severityText[v] || v}</span>`],
      ['账号','account', v => `<span class="mono">${v || ''}</span>`],
      ['状态','status', v => statusText[v] || v],
      ['说明','message'],
      ['出现次数','occurrence_count', fmt],
      ['首次出现','first_seen_at'],
      ['最近出现','last_seen_at']
    ]);
    const disabledRows = pool.disabled || [];
    const activeRows = pool.active || [];
    $('pool').innerHTML =
      `<div style="padding:12px 16px" class="muted">模式：${pool.single_account_mode ? '单号模式' : (pool.tiered_pool_mode ? 'Plus/Team 优先模式' : '普通模式')}。优先层 ${esc((pool.tiered_primary_plans || []).join(', ') || '-')}。活跃 ${pool.active_count} 个，备用 ${pool.standby_count || 0} 个，冷却 ${pool.cooling_count || 0} 个，下线 ${pool.disabled_count} 个。</div>` +
      '<h2 style="font-size:15px">当前活跃账号</h2>' +
      table(activeRows, [
        ['账号','email', v => `<span class="mono">${esc(v)}</span>`],
        ['套餐','plan', v => esc(v || '')],
        ['层级','tier', v => esc(v === 'primary' ? '优先' : '备用')],
        ['类型','type', v => esc(v || '')],
        ['过期','expired', v => esc(v || '')],
        ['文件','filename', v => `<span class="mono">${esc(v)}</span>`],
        ['操作','filename', v => `<button class="small danger" onclick="disableAccount('${esc(v)}')">下线</button>`]
      ]) +
      '<h2 style="font-size:15px">下线账号</h2>' +
      table(disabledRows, [
        ['账号','email', v => `<span class="mono">${esc(v)}</span>`],
        ['套餐','plan', v => esc(v || '')],
        ['文件','filename', v => `<span class="mono">${esc(v)}</span>`],
        ['原因','reason', v => esc(v || '')],
        ['自动上线','auto_enable_at', v => esc(v || '人工处理')],
        ['下线时间','disabled_at'],
        ['操作','filename', v => `<button class="small" onclick="enableAccount('${esc(v)}')">重新上线</button>`]
      ]) +
      '<h2 style="font-size:15px">备用账号</h2>' +
      table((pool.standby || []).slice(0, 80), [
        ['账号','email', v => `<span class="mono">${esc(v)}</span>`],
        ['套餐','plan', v => esc(v || '')],
        ['层级','tier', v => esc(v === 'primary' ? '优先' : '备用')],
        ['类型','type', v => esc(v || '')],
        ['过期','expired', v => esc(v || '')],
        ['文件','filename', v => `<span class="mono">${esc(v)}</span>`]
      ]) +
      '<h2 style="font-size:15px">冷却账号</h2>' +
      table((pool.cooling || []).slice(0, 80), [
        ['账号','email', v => `<span class="mono">${esc(v)}</span>`],
        ['套餐','plan', v => esc(v || '')],
        ['类型','type', v => esc(v || '')],
        ['过期','expired', v => esc(v || '')],
        ['文件','filename', v => `<span class="mono">${esc(v)}</span>`]
      ]);
    $('accountHealth').innerHTML = table(health, [
      ['账号','account', v => `<span class="mono">${v}</span>`],
      ['状态','status', v => `<span class="${statusClass(v)}">${statusText[v] || v}</span>`],
      ['原因','reasons', v => (v || []).join('；')],
      ['24h请求','requests', fmt],
      ['失败率','failure_rate', v => `${v || 0}%`],
      ['429','quota_429_requests', fmt],
      ['平均延迟','avg_latency_ms', v => `${fmt(v)} ms`],
      ['最近调用','last_event_time']
    ]);
    $('accounts').innerHTML = table(accounts, [
      ['账号','account', v => `<span class="mono">${v}</span>`], ['请求','requests', fmt], ['总 tokens','total_tokens', fmt], ['失败','failed_requests', v => `<span class="${v ? 'bad' : 'ok'}">${fmt(v)}</span>`], ['最近调用','last_event_time']
    ]);
    $('models').innerHTML = table(models, [
      ['模型','model'], ['请求','requests', fmt], ['输入','input_tokens', fmt], ['输出','output_tokens', fmt], ['推理','reasoning_tokens', fmt], ['总 tokens','total_tokens', fmt], ['失败','failed_requests', fmt]
    ]);
    $('recent').innerHTML = table(recent, [
      ['时间','event_time'], ['账号','source', v => `<span class="mono">${v || ''}</span>`], ['模型','model'], ['tokens','total_tokens', fmt], ['延迟','latency_ms', fmt], ['状态','failed', v => v ? '<span class="bad">失败</span>' : '<span class="ok">成功</span>'], ['错误','fail_status_code']
    ]);
    $('status').textContent = '已更新：' + new Date().toLocaleString();
  } catch (err) {
    $('status').textContent = '加载失败：' + err.message;
  }
}
load();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return DASHBOARD_HTML


@app.get("/index.html", response_class=HTMLResponse)
async def dashboard_index() -> str:
    return DASHBOARD_HTML
