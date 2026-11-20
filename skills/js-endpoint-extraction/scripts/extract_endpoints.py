#!/usr/bin/env python3
"""
extract_endpoints.py — Cross-platform Python implementation of extract_endpoints.sh.
Pulls API endpoints, relative routes, and URLs out of local JavaScript files.

Usage:
    python extract_endpoints.py                  # Scans all *.js in current working directory
    python extract_endpoints.py ./dist           # Scans all *.js under specified directory
    python extract_endpoints.py bundle.js app.js # Scans specific file(s)
"""
import os
import sys
import re
from pathlib import Path

# Matchers matching JD's original PCRE pattern:
# 1. Full http(s) URLs
URL_PATTERN = re.compile(r'https?://[^"\'` >]{4,}')
# 2. Absolute or relative root paths starting with / or //
PATH_PATTERN = re.compile(r'["\'`](\/{1,2}[a-zA-Z0-9_?&=\/\-#.]{3,})')
# 3. HTTP calls: .get/.post/.ajax/.load/fetch("path")
FETCH_PATTERN = re.compile(r'(?:\.(?:get|post|ajax|load)|fetch)\s*\(\s*["\'`]((?:https?:\/\/)?\/?[^"\'`> ]{3,})')

CLEAN_PATTERN = re.compile(r'((?:https?:\/\/)?\/?[a-zA-Z0-9_?&=\/\-#.]{3,})')

def extract_from_text(text: str) -> set:
    endpoints = set()
    # Pre-split on common JS statement terminators to speed up regex
    for part in re.split(r'[;})>\n]', text):
        if not part:
            continue
        for m in URL_PATTERN.finditer(part):
            endpoints.add(m.group(0))
        for m in PATH_PATTERN.finditer(part):
            endpoints.add(m.group(1))
        for m in FETCH_PATTERN.finditer(part):
            endpoints.add(m.group(1))
    
    cleaned = set()
    for ep in endpoints:
        m = CLEAN_PATTERN.search(ep)
        if m:
            val = m.group(1).strip()
            # Filter out obvious false positives like file extensions only
            if len(val) >= 3 and not val.startswith('//'):
                cleaned.add(val)
    return cleaned

def scan_file(file_path: Path) -> set:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        return extract_from_text(content)
    except Exception as e:
        sys.stderr.write(f"Error reading {file_path}: {e}\n")
        return set()

def main():
    args = sys.argv[1:]
    files_to_scan = []

    if not args:
        files_to_scan = list(Path('.').rglob('*.js'))
    else:
        for arg in args:
            p = Path(arg)
            if p.is_dir():
                files_to_scan.extend(p.rglob('*.js'))
            elif p.is_file():
                files_to_scan.append(p)
            else:
                sys.stderr.write(f"skip: {arg} (not a valid file or directory)\n")

    all_endpoints = set()
    for f in files_to_scan:
        all_endpoints.update(scan_file(f))

    for ep in sorted(all_endpoints):
        print(ep)

if __name__ == '__main__':
    main()
