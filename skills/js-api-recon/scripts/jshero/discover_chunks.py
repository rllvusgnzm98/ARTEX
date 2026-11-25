#!/usr/bin/env python3
"""
JShero static chunk discoverer (jxscout lazy-load parity).

jxscout (https://github.com/francisconeves97/jxscout) parses a bundle's webpack runtime to
enumerate every lazy chunk filename WITHOUT triggering it through interaction, then fetches
the ones the browser never loaded. This recreates that statically: it reads the collected JS,
finds the webpack chunk-id -> content-hash map used by `__webpack_require__.u` (the chunk
filename builder), reconstructs each chunk's filename, resolves candidate URLs (origin +
publicPath + filename), and writes chunk-urls.txt for a later download.

An interaction pass may already have saved some lazy chunks; this closes
the gap for chunks that interaction never reached (routes not exercised, feature-flagged code).

Handles the dominant webpack 5 pattern:
    r.u = e => "static/js/" + e + "." + { 96:"d9f4e1a2", 313:"b7c3", ... }[e] + ".chunk.js"
plus optional brute-force of sequential numeric chunk ids when the filename carries no hash.

Usage:
  python discover_chunks.py --run-root "runs/<domain>/<ts>" --domain <domain> [--origins https://a,https://b] [--brute 0]

Output (into run root):
  chunk-candidates.txt  reconstructed chunk relative filenames
  chunk-urls.txt        candidate absolute URLs to fetch (origin + publicPath + filename)
  chunk-summary.json    counts
"""
import argparse
import json
import re
import sys
from pathlib import Path

SCAN_DIRS = ("raw-js", "inline-js")
JS_GLOBS = ("*.js", "*.mjs")

# chunk-id -> content-hash map: { 96:"d9f4", "313":"b7c3", ... } (>= 2 numeric:string pairs)
REGEX_CHUNKMAP = re.compile(r'\{((?:\s*"?\d+"?\s*:\s*"[A-Za-z0-9_\-]{1,64}"\s*,?){2,})\}')
REGEX_PAIR = re.compile(r'"?(\d+)"?\s*:\s*"([A-Za-z0-9_\-]{1,64})"')
REGEX_STR = re.compile(r'"([^"\n]{0,120})"')
# webpack publicPath: r.p = "..."  (literal)
REGEX_PUBLICPATH = re.compile(r'[.\[]p[\]"\']?\s*=\s*["\']([^"\'\n]{0,200})["\']')
# no-hash chunk filename builder e.g.  .u=e=>"js/"+e+".js"  (brute-forceable)
REGEX_NOHASH_U = re.compile(r'[.\[]u[\]"\']?\s*=\s*(?:function\s*\([^)]*\)\s*\{\s*return\s*)?"([^"\n]{0,80})"\s*\+\s*[a-zA-Z_$][\w$]*\s*\+\s*"([^"\n]{0,40})"')

COMMON_PUBLIC_PATHS = ("/", "/static/", "/assets/", "/_next/", "/dist/")


def reconstruct_filenames(text):
    """Return set of chunk relative filenames from webpack chunk maps in one file."""
    files = set()
    for m in REGEX_CHUNKMAP.finditer(text):
        pairs = REGEX_PAIR.findall(m.group(1))
        if not pairs:
            continue
        before = text[max(0, m.start() - 160):m.start()]
        after = text[m.end():m.end() + 80]
        pre_lits = REGEX_STR.findall(before)      # e.g. ["static/js/", "."]
        suf_lits = REGEX_STR.findall(after)       # e.g. [".chunk.js"]
        # require the map to be used as MAP[<var>] (chunk lookup), otherwise it is some other object
        if not re.match(r'\s*\[[a-zA-Z_$][\w$]*\]', after):
            continue
        prefix0 = pre_lits[-2] if len(pre_lits) >= 2 else (pre_lits[-1] if pre_lits else "")
        infix = pre_lits[-1] if len(pre_lits) >= 2 else "."
        suffix = suf_lits[0] if suf_lits else ".js"
        # only accept plausible js chunk templates
        if not (suffix.endswith(".js") and ("/" in prefix0 or prefix0 == "")):
            continue
        for cid, chash in pairs:
            fname = f"{prefix0}{cid}{infix}{chash}{suffix}"
            fname = fname.lstrip("/")
            if len(fname) <= 200 and fname.endswith(".js"):
                files.add(fname)
    return files


def brute_filenames(text, limit):
    files = set()
    if limit <= 0:
        return files
    for m in REGEX_NOHASH_U.finditer(text):
        prefix, suffix = m.group(1), m.group(2)
        if not suffix.endswith(".js"):
            continue
        for i in range(0, limit + 1):
            fname = f"{prefix}{i}{suffix}".lstrip("/")
            if len(fname) <= 200:
                files.add(fname)
    return files


def main():
    ap = argparse.ArgumentParser(description="Static webpack chunk discoverer (jxscout parity).")
    ap.add_argument("--run-root", required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--origins", default=None, help="Comma-separated origins (default https://<domain>,https://www.<domain>)")
    ap.add_argument("--brute", type=int, default=0, help="Brute-force sequential chunk ids up to N when filenames carry no hash (default 0=off)")
    args = ap.parse_args()

    run_root = Path(args.run_root)
    if not run_root.is_dir():
        print(f"ERROR: run-root not found: {run_root}", file=sys.stderr)
        return 2
    domain = args.domain.lower().lstrip(".")
    origins = ([o.strip().rstrip("/") for o in args.origins.split(",")] if args.origins
               else [f"https://{domain}", f"https://www.{domain}"])

    files, publicpaths = [], set()
    for sub in SCAN_DIRS:
        d = run_root / sub
        if d.is_dir():
            for g in JS_GLOBS:
                files.extend(d.rglob(g))

    filenames = set()
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if "webpack" not in text and ".chunk.js" not in text and ".u=" not in text.replace(" ", ""):
            # cheap prefilter: skip files with no webpack runtime signal
            if not REGEX_CHUNKMAP.search(text):
                continue
        filenames |= reconstruct_filenames(text)
        filenames |= brute_filenames(text, args.brute)
        for pm in REGEX_PUBLICPATH.finditer(text):
            pp = pm.group(1)
            if pp and len(pp) < 200 and (pp.startswith("/") or pp.startswith("http")):
                publicpaths.add(pp)

    # build candidate absolute URLs: origin + publicPath + filename (dedup)
    pubs = set(publicpaths) | set(COMMON_PUBLIC_PATHS)
    urls = set()
    for fname in filenames:
        for pp in pubs:
            if pp.startswith("http"):
                base = pp.rstrip("/")
                urls.add(f"{base}/{fname}")
            else:
                for origin in origins:
                    base = origin.rstrip("/") + "/" + pp.strip("/")
                    urls.add(base.rstrip("/") + "/" + fname)

    def write_lines(name, lines):
        (run_root / name).write_text("".join(l + "\n" for l in sorted(lines)), encoding="utf-8")

    write_lines("chunk-candidates.txt", filenames)
    write_lines("chunk-urls.txt", urls)

    summary = {
        "run_id": run_root.name,
        "domain": domain,
        "scanned_files": len(files),
        "chunk_filenames": len(filenames),
        "public_paths_found": sorted(publicpaths),
        "candidate_urls": len(urls),
        "origins": origins,
        "brute_limit": args.brute,
    }
    (run_root / "chunk-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nReconstructed {len(filenames)} chunk filenames -> {len(urls)} candidate URLs.")
    print("Download chunk-urls.txt into raw-js/ (skip HTTP 404); then re-extract.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
