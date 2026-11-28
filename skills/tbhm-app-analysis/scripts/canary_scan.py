#!/usr/bin/env python3
"""
canary_scan.py - TBHM High-Signal Canary Path Auditor (Pure Python 3 Stdlib)
Performs non-destructive, low-noise canary probing for sensitive files & configuration leaks.
Includes automatic SPA / Catch-all false positive filtering.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

CANARY_CATEGORIES = {
    "env_secrets": [
        ".env", ".env.local", ".env.prod", ".env.production", ".env.dev", ".env.backup",
        "config/master.key", "application.properties", "application.yml", "appsettings.json", "web.config",
    ],
    "vcs_leaks": [".git/HEAD", ".git/config", ".git/index", ".gitignore", ".svn/entries", ".DS_Store"],
    "api_schemas": ["swagger.json", "swagger-ui.html", "openapi.json", "v3/api-docs", "docs", "redoc"],
    "debug_actuators": [
        "actuator/env", "actuator/heapdump", "actuator/health",
        "_profiler/empty/search/results", "debug/pprof", "telescope", "debugbar",
    ],
    "backups_dumps": ["backup.sql", "database.sql", "dump.sql", "backup.zip", "db.sql"],
}

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener():
    ctx = ssl._create_unverified_context()
    return urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ctx),
    )


def _fetch(opener, url, timeout=8.0):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": os.environ.get("ARTEX_UA") or DEFAULT_UA,
            "Accept": "*/*",
        },
        method="GET",
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(65536)
            return resp.status, dict(resp.headers), raw.decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read(4096)
        except Exception:
            pass
        return exc.code, dict(exc.headers or {}), raw.decode("utf-8", errors="ignore")
    except Exception:
        return None, {}, ""


def get_baseline(opener, base_url):
    """Detect SPA catch-all fallback or custom 404 pages."""
    rand_path = "non_existent_probe_" + hashlib.md5(os.urandom(16)).hexdigest()[:12]
    target = urllib.parse.urljoin(base_url.rstrip("/") + "/", rand_path)
    status, headers, text = _fetch(opener, target)
    if status is None:
        return None
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v
            break
    return {
        "status": status,
        "length": len(text),
        "hash": hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest(),
        "content_type": ct,
    }


def check_url(opener, base_url, path, baseline):
    target = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    status, headers, text = _fetch(opener, target)
    if status != 200:
        return None

    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
            break

    body_len = len(text)
    body_hash = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()

    if baseline and baseline["status"] == 200:
        if abs(body_len - baseline["length"]) < 50 or body_hash == baseline["hash"]:
            return None

    lower_text = text[:1000].lower()
    if any(phrase in lower_text for phrase in ["not found", "page not found", "404 not found", "cannot find", "页面不存在"]):
        return None

    snippet = text[:300].strip().replace("\n", " ")
    sev = "medium"
    cat = "general_config"
    for c_name, paths in CANARY_CATEGORIES.items():
        if any(path.startswith(p) or path == p for p in paths):
            cat = c_name
            break

    if cat in ("env_secrets", "vcs_leaks", "debug_actuators", "backups_dumps"):
        sev = "high"
    elif cat == "api_schemas":
        sev = "low"

    return {
        "path": path,
        "url": target,
        "status": status,
        "content_type": ct,
        "content_length": body_len,
        "category": cat,
        "severity": sev,
        "evidence": snippet[:200],
    }


def run_scan(base_url, wordlist_path, concurrency=15):
    if not os.path.exists(wordlist_path):
        print(f"Error: Wordlist not found at {wordlist_path}", file=sys.stderr)
        return [], 0

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    opener = _build_opener()
    baseline = get_baseline(opener, base_url)
    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(concurrency, 32))) as pool:
        futures = [pool.submit(check_url, opener, base_url, p, baseline) for p in paths]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                hits.append(res)
    hits.sort(key=lambda item: item["path"])
    return hits, len(paths)


def main():
    parser = argparse.ArgumentParser(description="TBHM High-Signal Canary Path Auditor (stdlib)")
    parser.add_argument("target_url", help="Target base URL (e.g. https://target.example.com)")
    parser.add_argument("wordlist_path", nargs="?", default=None, help="Optional path to wordlist")
    parser.add_argument("--concurrency", type=int, default=15, help="Worker thread count (default: 15)")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without sending HTTP requests")
    args = parser.parse_args()

    default_wl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quick-hits-wordlist.txt")
    wordlist_path = args.wordlist_path or default_wl

    if args.dry_run:
        count = 0
        if os.path.exists(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                count = sum(1 for line in f if line.strip() and not line.startswith("#"))
        print(json.dumps({
            "dry_run": True,
            "target": args.target_url,
            "wordlist": wordlist_path,
            "total_paths": count,
            "concurrency": args.concurrency,
        }, indent=2, ensure_ascii=False))
        return

    hits, total = run_scan(args.target_url, wordlist_path, concurrency=args.concurrency)
    print(json.dumps({
        "target": args.target_url,
        "total_probed": total,
        "hits_count": len(hits),
        "findings": hits,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
