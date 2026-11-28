#!/usr/bin/env python3
"""
oob_diag.py - Offline/local JSONL OOB callback log inspector & summary helper (stdlib only).
"""

import argparse
import json
import os


def summarize_jsonl(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                events.append(json.loads(s))
            except json.JSONDecodeError:
                events.append({"raw": s})
    methods = {}
    ips = set()
    for ev in events:
        m = ev.get("method") or ev.get("protocol") or "unknown"
        methods[m] = methods.get(m, 0) + 1
        if ev.get("remote_ip"):
            ips.add(ev["remote_ip"])
    return {
        "file": path,
        "total_events": len(events),
        "by_method": methods,
        "unique_remote_ips": sorted(ips),
        "latest": events[-5:],
    }


def main():
    parser = argparse.ArgumentParser(description="Inspect local OOB JSONL callback logs (stdlib)")
    parser.add_argument("jsonl_file", nargs="?", help="Path to OOB JSONL log file")
    parser.add_argument("--dry-run", action="store_true", help="Print expected schema without reading files")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps({
            "dry_run": True,
            "recommended_flow": ["oob_allocate", "sendBeacon/keepalive telemetry", "oob_poll"],
        }, indent=2, ensure_ascii=False))
        return

    if not args.jsonl_file or not os.path.isfile(args.jsonl_file):
        print(json.dumps({"error": f"jsonl file not found: {args.jsonl_file}"}))
        raise SystemExit(1)

    print(json.dumps(summarize_jsonl(args.jsonl_file), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
