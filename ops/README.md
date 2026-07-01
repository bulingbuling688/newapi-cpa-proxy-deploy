# Operations

These scripts are examples from a small New API + CLIProxyAPI deployment.

Do not commit runtime account JSON files, New API database dumps, tokens, logs, or backups.

## Scripts

- `health-check.sh`: checks Docker containers, New API, CPA, and disk usage.
- `restart-stack.sh`: runs `docker compose up -d` and then health check.
- `backup.sh`: creates a local backup. Review the destination before enabling on a real server.
- `open-cpa-oauth-tunnel.ps1`: helper for a local CPA OAuth callback tunnel.
