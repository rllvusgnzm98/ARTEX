#!/usr/bin/env python3
"""
JShero 5x merge: combine N independent live-collection passes into one deduplicated corpus.

Because an LLM drives the crawl, each pass under-samples the surface differently. A full
JShero run is defined as several independent passes merged. This script dedups every pass's
raw-js/ and inline-js/ (by SHA-256 content hash) into the run-set's top-level raw-js/ and
inline-js/, ready for a single extraction pass over the union (historical-js/ is collected
once and already lives at the top level).

It also reports how many UNIQUE files each pass contributed, which quantifies the payoff of
running more than once (if pass 4 and 5 add zero new hashes, the surface has converged).

Layout expected:
  <runset-root>\
    historical-js\            (collected once, shared)
    passes\pass-1\raw-js\ inline-js\
    passes\pass-2\...
    ...
  ->  writes merged  <runset-root>\raw-js\  and  <runset-root>\inline-js\

Usage:
  python merge_runs.py --runset-root "runs/<domain>/<ts>"
"""
import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

SUBS = ("raw-js", "inline-js")


def sha16(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser(description="Merge N JShero passes into one deduplicated corpus.")
    ap.add_argument("--runset-root", required=True)
    args = ap.parse_args()

    root = Path(args.runset_root)
    passes_dir = root / "passes"
    if not passes_dir.is_dir():
        print(f"ERROR: no passes/ under {root}", file=sys.stderr)
        return 2

    passes = sorted([p for p in passes_dir.iterdir() if p.is_dir()])
    if not passes:
        print(f"ERROR: no pass-* folders under {passes_dir}", file=sys.stderr)
        return 2

    for sub in SUBS:
        (root / sub).mkdir(parents=True, exist_ok=True)

    seen = {sub: {} for sub in SUBS}          # sub -> {hash: dest filename}
    contribution = {}                          # pass name -> {sub: unique_added}
    pass_totals = {}                           # pass name -> {sub: files_seen}

    for p in passes:
        contribution[p.name] = {sub: 0 for sub in SUBS}
        pass_totals[p.name] = {sub: 0 for sub in SUBS}
        for sub in SUBS:
            srcdir = p / sub
            if not srcdir.is_dir():
                continue
            for f in sorted(srcdir.iterdir()):
                if not f.is_file():
                    continue
                pass_totals[p.name][sub] += 1
                h = sha16(f)
                if h in seen[sub]:
                    continue
                dest = root / sub / f"{h}-{f.name}"
                if not dest.exists():
                    shutil.copy2(f, dest)
                seen[sub][h] = dest.name
                contribution[p.name][sub] += 1

    summary = {
        "runset_root": str(root),
        "passes": [p.name for p in passes],
        "merged_unique": {sub: len(seen[sub]) for sub in SUBS},
        "per_pass_files_seen": pass_totals,
        "per_pass_unique_contribution": contribution,
    }
    (root / "merge-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print("\nUnique contribution per pass (new hashes each pass added to the union):")
    for p in passes:
        r = contribution[p.name]["raw-js"]
        i = contribution[p.name]["inline-js"]
        print(f"  {p.name:<10} raw-js +{r:<5} inline-js +{i}")
    print(f"\nMerged union: {len(seen['raw-js'])} raw-js, {len(seen['inline-js'])} inline-js "
          f"(historical-js is shared at the run-set root).")
    print("If the last passes contributed ~0 new hashes, collection has converged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
