#!/usr/bin/env python3
"""
patch_diff_triage.py - Unified diff / git patch security-delta analyzer (stdlib only).
Highlights files and added/removed validation, auth, sanitization, or sink lines.
"""

import argparse
import json
import os
import re

SECURITY_DELTA_RE = re.compile(
    r"(?:current_user_can|nonce|permission|auth|sanitize|escape|realpath|basename|intval|"
    r"prepare|escape_sql|csrf|_token|preg_match|allowlist|whitelist|unserialize|eval|exec|writeFile)",
    re.I,
)


def parse_patch(text):
    files = []
    cur = None
    for raw_line in text.splitlines():
        if raw_line.startswith("diff --git "):
            if cur:
                files.append(cur)
            parts = raw_line.split()
            fname = parts[-1].removeprefix("b/") if len(parts) >= 4 else raw_line
            cur = {"file": fname, "added_security_lines": [], "removed_lines": []}
            continue
        if cur is None and raw_line.startswith("+++ "):
            cur = {"file": raw_line[4:].strip().removeprefix("b/"), "added_security_lines": [], "removed_lines": []}
            continue
        if cur is None:
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:].strip()
            if content and SECURITY_DELTA_RE.search(content):
                cur["added_security_lines"].append(content[:180])
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            content = raw_line[1:].strip()
            if content and SECURITY_DELTA_RE.search(content):
                cur["removed_lines"].append(content[:180])
    if cur:
        files.append(cur)
    interesting = [f for f in files if f["added_security_lines"] or f["removed_lines"]]
    return interesting, len(files)


def main():
    parser = argparse.ArgumentParser(description="Unified patch security-delta analyzer (stdlib)")
    parser.add_argument("patch_file", nargs="?", help="Path to unified .diff / .patch file")
    parser.add_argument("--dry-run", action="store_true", help="Print analyzer mode without reading files")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps({"dry_run": True, "mode": "unified_diff_security_triage"}, indent=2))
        return

    if not args.patch_file or not os.path.isfile(args.patch_file):
        print(json.dumps({"error": f"patch file not found: {args.patch_file}"}))
        raise SystemExit(1)

    with open(args.patch_file, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    interesting, total_files = parse_patch(text)
    print(json.dumps({
        "patch_file": args.patch_file,
        "total_diff_files": total_files,
        "security_relevant_files": len(interesting),
        "files": interesting[:60],
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
