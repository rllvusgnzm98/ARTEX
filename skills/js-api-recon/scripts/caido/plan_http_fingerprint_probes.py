#!/usr/bin/env python3
"""Print a low-volume HTTP fingerprinting probe plan without executing it."""

from __future__ import annotations

import argparse
import json
from urllib.parse import urlparse


DEFAULT_FILES = [
    "/favicon.ico",
    "/package.json",
    "/changelog.txt",
    "/README.txt",
    "/LICENSE.txt",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL or host.")
    args = parser.parse_args()
    target = normalize_target(args.target)
    host = urlparse(target).hostname or args.target
    scheme = urlparse(target).scheme or "https"
    port = 443 if scheme == "https" else 80

    plan = {
        "target": target,
        "requires_user_authorization": True,
        "probes": [
            {
                "technique": "banner-grabbing GET",
                "purpose": "Capture baseline status line, Server/Via/X-* headers, cookies, and header order.",
                "command": f"curl -i --max-time 10 {shell_quote(target)}",
            },
            {
                "technique": "default error page",
                "purpose": "Trigger a likely 404 and inspect body template, comments, phrasing, and status headers.",
                "command": f"curl -i --max-time 10 {shell_quote(target.rstrip('/') + '/__caido_fingerprint_404__')}",
            },
            {
                "technique": "default files and directory structures",
                "purpose": "Check common files that can expose framework/product/version metadata.",
                "commands": [f"curl -I --max-time 10 {shell_quote(target.rstrip('/') + path)}" for path in DEFAULT_FILES],
            },
            {
                "technique": "malformed HTTP version",
                "purpose": "Trigger parser/error behavior that may reveal web server or reverse proxy.",
                "command": f"printf 'GET / HTTP/4.4\\r\\nHost: {host}\\r\\n\\r\\n' | nc -w 10 {host} {port}",
            },
            {
                "technique": "malformed method",
                "purpose": "Trigger method parser behavior that may reveal web server or reverse proxy.",
                "command": f"printf 'XGET / HTTP/1.1\\r\\nHost: {host}\\r\\n\\r\\n' | nc -w 10 {host} {port}",
            },
        ],
    }
    print(json.dumps(plan, indent=2))
    return 0


def normalize_target(target: str) -> str:
    if "://" not in target:
        return f"https://{target}"
    return target


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


if __name__ == "__main__":
    raise SystemExit(main())
