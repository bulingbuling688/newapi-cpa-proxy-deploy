# New API + CLIProxyAPI deployment template

Public, sanitized deployment notes for a small OpenAI-compatible API gateway stack:

- New API for users, tokens, model routing, and quota accounting
- CLIProxyAPI for ChatGPT/Codex OAuth account pooling
- PostgreSQL and Redis
- optional CPA Usage Keeper service for usage collection and account-pool operations
- optional Grok2API local fork and upstream proxy integration

This repository is a deployment template. It intentionally does not include production secrets, account JSON files, database data, logs, backups, or token pools.

## Layout

```text
docker-compose.yml              New API + CPA + Postgres + Redis + Usage Keeper
docker-compose.grok2api.yml     Optional Grok2API service override
.env.example                    Required environment variables
cpa/config.example.yaml         CPA config template
cpa-usage-keeper/               FastAPI usage collector service
ezouapi-proxy/                  Optional Nginx upstream proxy template
ops/                            Operational helper scripts
scripts/                        CPA pool helper scripts
usage-proxy.py                  Local usage lookup helper
```

## Quick start

```bash
cp .env.example .env
cp cpa/config.example.yaml cpa/config.yaml
mkdir -p cpa/auths cpa/logs newapi/data newapi/logs
```

Edit `.env` and `cpa/config.yaml`, then start the stack. `cpa/config.example.yaml`
contains placeholder values because CLIProxyAPI reads the YAML file directly.
On Windows you can render those two placeholders from environment variables:

```powershell
$env:CPA_API_KEY = "sk-your-cpa-key"
$env:CPA_MANAGEMENT_SECRET_HASH = "your-bcrypt-hash"
.\scripts\render-cpa-config.ps1
```

Start the stack:

```bash
docker compose up -d
```

If you also vendor or clone a Grok2API fork into `./grok2api`, start it with:

```bash
docker compose -f docker-compose.yml -f docker-compose.grok2api.yml up -d
```

## Security notes

Never commit:

- `.env`
- `cpa/auths/*.json`
- New API database files or SQL dumps
- Grok SSO token pools
- logs, backups, generated media, or account state files

All public files in this repository are templates or source code with secrets replaced by environment variables.
