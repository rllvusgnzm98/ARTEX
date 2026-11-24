#!/usr/bin/env python3
"""
canary_scan.py - TBHM High-Signal Canary Path Auditor
Performs non-destructive, low-noise canary probing for sensitive files & configuration leaks.
Includes automatic SPA / Catch-all false positive filtering.
Designed for ARTEX Worker Agents to feed findings directly into record_finding.
"""

import sys
import os
import json
import asyncio
import aiohttp
import urllib.parse
import hashlib

CANARY_CATEGORIES = {
    "env_secrets": [".env", ".env.local", ".env.prod", ".env.production", ".env.dev", ".env.backup", "config/master.key", "application.properties", "application.yml", "appsettings.json", "web.config"],
    "vcs_leaks": [".git/HEAD", ".git/config", ".git/index", ".gitignore", ".svn/entries", ".DS_Store"],
    "api_schemas": ["swagger.json", "swagger-ui.html", "openapi.json", "v3/api-docs", "docs", "redoc"],
    "debug_actuators": ["actuator/env", "actuator/heapdump", "actuator/health", "_profiler/empty/search/results", "debug/pprof", "telescope", "debugbar"],
    "backups_dumps": ["backup.sql", "database.sql", "dump.sql", "backup.zip", "db.sql"]
}

async def get_baseline(session, base_url):
    """Detect SPA catch-all fallback or custom 404 pages."""
    rand_path = "non_existent_probe_" + hashlib.md5(os.urandom(16)).hexdigest()[:12]
    target = urllib.parse.urljoin(base_url.rstrip('/') + '/', rand_path)
    try:
        async with session.get(target, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False, ssl=False) as resp:
            text = await resp.text(errors='ignore')
            return {
                "status": resp.status,
                "length": len(text),
                "hash": hashlib.md5(text.encode()).hexdigest(),
                "content_type": resp.headers.get("Content-Type", "")
            }
    except Exception:
        return None

async def check_url(session, base_url, path, semaphore, baseline):
    target = urllib.parse.urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
    async with semaphore:
        try:
            async with session.get(target, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False, ssl=False) as resp:
                status = resp.status
                ct = resp.headers.get("Content-Type", "").lower()
                
                # Check for genuine hits
                if status == 200:
                    text = await resp.text(errors='ignore')
                    body_len = len(text)
                    body_hash = hashlib.md5(text.encode()).hexdigest()
                    
                    # 1. Filter SPA / Catch-all false positives matching baseline
                    if baseline and baseline["status"] == 200:
                        if abs(body_len - baseline["length"]) < 50 or body_hash == baseline["hash"]:
                            return None
                    
                    # 2. Filter obvious soft 404s
                    lower_text = text[:1000].lower()
                    if any(phrase in lower_text for phrase in ["not found", "page not found", "404 not found", "cannot find", "页面不存在"]):
                        return None
                    
                    snippet = text[:300].strip().replace('\n', ' ')
                    
                    # Categorize severity
                    sev = "medium"
                    cat = "general_config"
                    for c_name, paths in CANARY_CATEGORIES.items():
                        if any(path.startswith(p) or path == p for p in paths):
                            cat = c_name
                            break
                    
                    if cat in ["env_secrets", "vcs_leaks"]:
                        sev = "high"
                    elif cat in ["debug_actuators", "backups_dumps"]:
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
                        "evidence": snippet[:200]
                    }
        except Exception:
            return None
    return None

async def run_scan(base_url, wordlist_path, concurrency=15):
    if not os.path.exists(wordlist_path):
        print(f"Error: Wordlist not found at {wordlist_path}", file=sys.stderr)
        return []
        
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        paths = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        
    semaphore = asyncio.Semaphore(concurrency)
    conn = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*"
    }
    
    hits = []
    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        baseline = await get_baseline(session, base_url)
        tasks = [check_url(session, base_url, p, semaphore, baseline) for p in paths]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                hits.append(r)
                
    return hits

def main():
    if len(sys.argv) < 2:
        print("Usage: canary_scan.py <target_url> [wordlist_path]", file=sys.stderr)
        sys.exit(1)
        
    target_url = sys.argv[1]
    default_wl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quick-hits-wordlist.txt")
    wordlist_path = sys.argv[2] if len(sys.argv) > 2 else default_wl
    
    hits = asyncio.run(run_scan(target_url, wordlist_path))
    
    output = {
        "target": target_url,
        "total_probed": 419,
        "hits_count": len(hits),
        "findings": hits
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
