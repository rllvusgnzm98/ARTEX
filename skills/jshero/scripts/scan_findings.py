#!/usr/bin/env python3
"""
JShero findings scanner: secrets + DOM sink/source detection, deduped through the ledger.

Parity layer with jxscout (https://github.com/francisconeves97/jxscout):
  - secrets: jxscout embeds ~1600 patterns from mazen160/secrets-patterns-db. They are
    extracted into secrets_patterns.json (next to this script) and run over all collected JS.
  - sinks/sources: jxscout uses AST analyzers (postmessage, onmessage, eval, inner-html,
    location, document-domain, window-open/name, local/session-storage, cookie, fetch,
    http-methods, url-search-params, graphql). Those are ported here as regexes — lower
    fidelity than AST, but covers the same "interesting parts of JS".

Scans raw-js/, inline-js/, historical-js/ under a run root; writes findings and updates the
per-target ledger's `secrets` and `sinks` sections so re-runs only report what is new.

Usage:
  python scan_findings.py --run-root "runs/<domain>/<ts>" --domain <domain>
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCAN_DIRS = ("raw-js", "inline-js", "historical-js")
JS_GLOBS = ("*.js", "*.mjs", "*.map")
MAX_FILE_BYTES = 4_000_000          # skip secrets scan on bodies bigger than this
MAX_MATCHES_PER_PATTERN_FILE = 5     # cap noisy patterns per file

# --- DOM sink/source regexes (regex ports of jxscout's AST analyzers) ---
SINK_PATTERNS = {
    "postMessage-send": r"\.postMessage\s*\(",
    "message-listener": r"addEventListener\s*\(\s*[\"']message[\"']|\.onmessage\s*=",
    "hashchange": r"addEventListener\s*\(\s*[\"']hashchange[\"']|\.onhashchange\s*=",
    "eval": r"\beval\s*\(|new\s+Function\s*\(",
    "innerHTML": r"\.(?:inner|outer)HTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(",
    "dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
    "document.domain": r"document\.domain\s*=",
    "location-sink": r"location\s*\.\s*(?:href|assign|replace)\s*[=(]|(?:window|document)\.location\s*=",
    "window.open": r"window\.open\s*\(",
    "window.name": r"window\.name\b",
    "storage": r"\b(?:local|session)Storage\s*\.\s*(?:get|set|remove)Item\s*\(",
    "cookie": r"document\.cookie\b",
    "fetch": r"\bfetch\s*\(",
    "xhr": r"new\s+XMLHttpRequest\b|\.open\s*\(\s*[\"'](?:GET|POST|PUT|DELETE|PATCH|OPTIONS)[\"']",
    "url-search-params": r"new\s+URLSearchParams\b|\.searchParams\b",
    "graphql": r"gql\s*`|[\"'`]\s*(?:query|mutation|subscription)\s+\w+\s*[({]",
}
_SINK_COMPILED = {k: re.compile(v, re.IGNORECASE) for k, v in SINK_PATTERNS.items()}


def load_secret_patterns(path):
    if not path.exists():
        print(f"WARNING: secrets DB not found at {path}; skipping secrets scan", file=sys.stderr)
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for e in raw:
        try:
            out.append((e["name"], re.compile(e["pattern"])))
        except re.error:
            continue
    return out


def load_ledger(path):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"domain": None, "runs": [], "endpoints": {}, "params": {}, "secrets": {}, "sinks": {}}


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def main():
    ap = argparse.ArgumentParser(description="JShero secrets + DOM sink/source scanner.")
    ap.add_argument("--run-root", required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--ledger", default=None)
    ap.add_argument("--secrets-db", default=None)
    args = ap.parse_args()

    run_root = Path(args.run_root)
    if not run_root.is_dir():
        print(f"ERROR: run-root not found: {run_root}", file=sys.stderr)
        return 2
    domain = args.domain.lower().lstrip(".")
    run_id = run_root.name
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger_path = Path(args.ledger) if args.ledger else (run_root.parent / "ledger.json")
    secrets_db = Path(args.secrets_db) if args.secrets_db else (Path(__file__).parent / "secrets_patterns.json")

    secret_patterns = load_secret_patterns(secrets_db)

    files = []
    for sub in SCAN_DIRS:
        d = run_root / sub
        if d.is_dir():
            for g in JS_GLOBS:
                files.extend(d.rglob(g))

    secrets = {}   # key -> {name, match, file}
    sinks = {}     # key -> {type, file, line, snippet}

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = f.name

        # sinks/sources
        for stype, rx in _SINK_COMPILED.items():
            hits = 0
            for m in rx.finditer(text):
                ln = line_of(text, m.start())
                snippet = text[max(0, m.start() - 20): m.start() + 60].replace("\n", " ").strip()
                key = f"{stype}|{rel}|{ln}"
                if key not in sinks:
                    sinks[key] = {"type": stype, "file": rel, "line": ln, "snippet": snippet}
                hits += 1
                if hits >= MAX_MATCHES_PER_PATTERN_FILE:
                    break

        # secrets (skip oversized bodies)
        if len(text) <= MAX_FILE_BYTES:
            for name, rx in secret_patterns:
                hits = 0
                for m in rx.finditer(text):
                    val = (m.group(0) or "").strip()
                    if not val or len(val) > 200:
                        continue
                    key = f"{name}|{val}"
                    if key not in secrets:
                        secrets[key] = {"name": name, "match": val, "file": rel}
                    hits += 1
                    if hits >= MAX_MATCHES_PER_PATTERN_FILE:
                        break

    # ledger diff
    ledger = load_ledger(ledger_path)
    ledger["domain"] = domain
    known_secrets = ledger.setdefault("secrets", {})
    known_sinks = ledger.setdefault("sinks", {})
    new_secrets = {k: v for k, v in secrets.items() if k not in known_secrets}
    new_sinks = {k: v for k, v in sinks.items() if k not in known_sinks}
    for k, v in new_secrets.items():
        known_secrets[k] = {**v, "first_seen_run": run_id, "first_seen_utc": now}
    for k, v in new_sinks.items():
        known_sinks[k] = {**v, "first_seen_run": run_id, "first_seen_utc": now}
    if run_id not in ledger.setdefault("runs", []):
        ledger["runs"].append(run_id)
    ledger_path.write_text(json.dumps(ledger, indent=2, sort_keys=True), encoding="utf-8")

    def write_lines(name, lines):
        (run_root / name).write_text("".join(l + "\n" for l in lines), encoding="utf-8")

    write_lines("secrets-all.txt", [f"{v['name']}\t{v['match']}\t{v['file']}" for v in sorted(secrets.values(), key=lambda x: x["name"])])
    write_lines("secrets-new.txt", [f"{v['name']}\t{v['match']}\t{v['file']}" for v in sorted(new_secrets.values(), key=lambda x: x["name"])])
    write_lines("sinks-all.txt", [f"{v['type']}\t{v['file']}:{v['line']}\t{v['snippet']}" for v in sorted(sinks.values(), key=lambda x: (x["type"], x["file"]))])
    write_lines("sinks-new.txt", [f"{v['type']}\t{v['file']}:{v['line']}\t{v['snippet']}" for v in sorted(new_sinks.values(), key=lambda x: (x["type"], x["file"]))])

    sink_by_type = {}
    for v in sinks.values():
        sink_by_type[v["type"]] = sink_by_type.get(v["type"], 0) + 1

    summary = {
        "run_id": run_id,
        "domain": domain,
        "scanned_files": len(files),
        "secret_patterns_loaded": len(secret_patterns),
        "secrets_found": len(secrets),
        "secrets_new": len(new_secrets),
        "sinks_found": len(sinks),
        "sinks_new": len(new_sinks),
        "sinks_by_type": sink_by_type,
        "ledger_total_secrets": len(known_secrets),
        "ledger_total_sinks": len(known_sinks),
    }
    (run_root / "findings-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
