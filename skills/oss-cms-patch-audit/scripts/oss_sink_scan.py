#!/usr/bin/env python3
"""
oss_sink_scan.py - Multi-stack static source entry-point & security sink scanner (stdlib only).
Scans PHP (WordPress/PrestaShop/Symfony), Python, JS/TS, and Java directories and emits ranked JSON hits.
"""

import argparse
import json
import os
import re

RULES = [
    ("php_wp_nopriv_ajax", "high", {".php"}, re.compile(r"add_action\s*\(\s*['\"]wp_ajax_nopriv_([^'\"]+)['\"]")),
    ("php_wp_rest_route", "medium", {".php"}, re.compile(r"register_rest_route\s*\(")),
    ("php_wp_permissive_cb", "high", {".php"}, re.compile(r"permission_callback['\"]?\s*=>\s*['\"]__return_true['\"]")),
    ("php_prestashop_front", "medium", {".php"}, re.compile(r"extends\s+(?:ModuleFrontController|AdminController|ModuleAdminController)\b")),
    ("php_file_sink", "high", {".php"}, re.compile(r"\b(?:file_put_contents|move_uploaded_file|unlink|fopen|fwrite)\s*\(")),
    ("php_exec_deser_sink", "critical", {".php"}, re.compile(r"\b(?:unserialize|eval|exec|shell_exec|system|passthru|proc_open)\s*\(")),
    ("php_sql_concat", "high", {".php"}, re.compile(r"\$wpdb->(?:query|get_results|get_var|get_row)\s*\([^\n]*\.\s*\$")),
    ("py_route_decorator", "low", {".py"}, re.compile(r"@(?:app|router|bp)\.(?:route|get|post|put|delete|patch)\s*\(")),
    ("py_dangerous_sink", "critical", {".py"}, re.compile(r"\b(?:pickle\.loads|yaml\.load|eval|exec|subprocess\.(?:Popen|run|call)|os\.system|render_template_string)\s*\(")),
    ("js_route_or_handler", "low", {".js", ".ts", ".mjs", ".cjs"}, re.compile(r"\b(?:app|router|fastify)\.(?:get|post|put|delete|all|use)\s*\(|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE)\b")),
    ("js_dangerous_sink", "high", {".js", ".ts", ".mjs", ".cjs"}, re.compile(r"\b(?:writeFileSync|writeFile|execSync|exec|spawn|eval|innerHTML|dangerouslySetInnerHTML)\b")),
    ("java_mapping", "low", {".java"}, re.compile(r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\b")),
    ("java_dangerous_sink", "critical", {".java"}, re.compile(r"\b(?:ObjectInputStream|readObject|Runtime\.getRuntime|ProcessBuilder|XMLDecoder|DocumentBuilderFactory)\b")),
]

SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
AUTH_HINT_RE = re.compile(r"(?:current_user_can|wp_verify_nonce|check_admin_referer|is_admin|permission_callback|@login_required|PreAuthorize|authenticate)", re.I)


def scan_dir(root, limit):
    hits = []
    files_scanned = 0
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in sorted(dirs) if d not in SKIP_DIRS]
        for fname in sorted(files):
            ext = os.path.splitext(fname)[1].lower()
            applicable = [r for r in RULES if ext in r[2]]
            if not applicable:
                continue
            fpath = os.path.join(cur, fname)
            try:
                if os.path.getsize(fpath) > 2 * 1024 * 1024:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except OSError:
                continue
            files_scanned += 1
            for idx, line in enumerate(lines, 1):
                for rule_id, sev, _, rx in applicable:
                    if rx.search(line):
                        ctx_start = max(0, idx - 6)
                        ctx_end = min(len(lines), idx + 5)
                        nearby = "".join(lines[ctx_start:ctx_end])
                        hits.append({
                            "rule": rule_id,
                            "severity": sev,
                            "file": os.path.relpath(fpath, root),
                            "line": idx,
                            "snippet": line.strip()[:180],
                            "auth_check_nearby": bool(AUTH_HINT_RE.search(nearby)),
                        })
                        if len(hits) >= limit:
                            return hits, files_scanned, True
    return hits, files_scanned, False


def main():
    parser = argparse.ArgumentParser(description="Static OSS/CMS entry-point and sink scanner (stdlib)")
    parser.add_argument("source_dir", nargs="?", default=".", help="Path to unpacked source directory")
    parser.add_argument("--limit", type=int, default=80, help="Max findings to emit (default: 80)")
    parser.add_argument("--dry-run", action="store_true", help="Show active rules without scanning files")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps({
            "dry_run": True,
            "source_dir": args.source_dir,
            "rules": [{"id": r[0], "severity": r[1], "extensions": sorted(r[2])} for r in RULES],
        }, indent=2, ensure_ascii=False))
        return

    if not os.path.isdir(args.source_dir):
        print(json.dumps({"error": f"directory not found: {args.source_dir}"}))
        raise SystemExit(1)

    hits, scanned, truncated = scan_dir(args.source_dir, max(1, args.limit))
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda h: (sev_order.get(h["severity"], 9), h["auth_check_nearby"], h["file"], h["line"]))
    print(json.dumps({
        "source_dir": args.source_dir,
        "files_scanned": scanned,
        "hits_count": len(hits),
        "truncated": truncated,
        "hits": hits,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
