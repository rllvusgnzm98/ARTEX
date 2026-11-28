#!/usr/bin/env python3
"""
auth_token_inspect.py - Offline read-only JWT / Flask session / PHP serialization inspector (stdlib only).
Decodes headers, claims, timestamps, and structure metadata without mutating target state.
"""

import argparse
import base64
import json
import re
import zlib


def _b64url_decode(seg):
    pad = "=" * ((4 - len(seg) % 4) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def inspect_jwt(token):
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {"error": "invalid JWT format (expected header.payload[.sig])"}
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
    return {
        "mode": "jwt",
        "header": header,
        "payload": payload,
        "has_signature": len(parts) >= 3 and bool(parts[2]),
        "alg": header.get("alg"),
    }


def inspect_flask(cookie):
    val = cookie.strip()
    compressed = False
    if val.startswith("."):
        compressed = True
        val = val[1:]
    parts = val.split(".")
    if not parts[0]:
        return {"error": "empty Flask cookie payload"}
    raw = _b64url_decode(parts[0])
    if compressed:
        raw = zlib.decompress(raw)
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        data = raw.decode("utf-8", errors="replace")
    return {
        "mode": "flask",
        "compressed": compressed,
        "parts_count": len(parts),
        "timestamp_segment": parts[1] if len(parts) > 1 else None,
        "payload": data,
    }


def inspect_php_serial(raw):
    classes = re.findall(r'O:\d+:"([^"]+)"', raw)
    strings = re.findall(r's:(\d+):"([^"]*)"', raw)
    mismatches = [
        {"declared_len": int(ln), "actual_bytes": len(val.encode("utf-8")), "preview": val[:40]}
        for ln, val in strings
        if int(ln) != len(val.encode("utf-8"))
    ]
    return {
        "mode": "php-serial",
        "classes": sorted(set(classes)),
        "string_fields": len(strings),
        "length_mismatches": mismatches[:20],
    }


def main():
    parser = argparse.ArgumentParser(description="Read-only JWT / Flask / PHP-serial structure inspector (stdlib)")
    parser.add_argument("--mode", choices=["jwt", "flask", "php-serial"], required=True, help="Token/payload format")
    parser.add_argument("value", nargs="?", default="", help="Token or serialized string to inspect")
    parser.add_argument("--dry-run", action="store_true", help="Print supported modes without parsing")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps({"dry_run": True, "mode": args.mode}, indent=2))
        return

    if not args.value:
        print(json.dumps({"error": "value is required unless --dry-run is set"}))
        raise SystemExit(1)

    if args.mode == "jwt":
        res = inspect_jwt(args.value)
    elif args.mode == "flask":
        res = inspect_flask(args.value)
    else:
        res = inspect_php_serial(args.value)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
