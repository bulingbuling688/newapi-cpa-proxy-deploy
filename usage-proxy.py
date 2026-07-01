#!/usr/bin/env python3
"""Tiny HTTP server that queries New API Postgres for token usage.

Set DB_DSN in the environment, for example:
DB_DSN="dbname=new-api user=newapi password=... host=127.0.0.1"
"""
import http.server
import json
import os
import sys

import psycopg2

DB_DSN = os.environ["DB_DSN"]


def query_usage(token: str) -> dict | None:
    key = token.removeprefix("sk-")
    conn = psycopg2.connect(DB_DSN)
    cur = conn.cursor()
    cur.execute(
        "SELECT u.quota, u.used_quota "
        "FROM tokens t JOIN users u ON t.user_id = u.id "
        "WHERE t.key = %s AND t.status = 1",
        (key,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return None

    quota, used = row
    remaining = max(0, quota - used)
    return {
        "remaining": remaining / 10000.0,
        "total": quota / 10000.0,
        "used": used / 10000.0,
        "unit": "USD",
    }


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ")
        if not token:
            self.send_error(401, "missing token")
            return

        data = query_usage(token)
        if data is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error":"token not found"}')
            return

        result = {
            "isValid": True,
            "remaining": data["remaining"],
            "unit": data["unit"],
            "total": data["total"],
            "used": data["used"],
        }
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8399
    httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    print(f"usage-proxy listening on 127.0.0.1:{port}", flush=True)
    httpd.serve_forever()
