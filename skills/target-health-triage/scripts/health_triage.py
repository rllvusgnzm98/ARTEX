#!/usr/bin/env python3
"""
health_triage.py - 3-point differential HTTP health & fault classifier (stdlib only).
Distinguishes infra_unavailable (502/503/connect error), uniform_filter (WAF/catch-all),
tarpit_delay, and healthy_app without noisy brute-force retries.
"""

import argparse
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe(opener, url, timeout):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": os.environ.get("ARTEX_UA") or DEFAULT_UA,
            "Accept": "*/*",
        },
        method="GET",
    )
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(32768)
            ms = round((time.monotonic() - t0) * 1000, 1)
            return {
                "url": url,
                "status": resp.status,
                "rtt_ms": ms,
                "length": len(raw),
                "hash": hashlib.sha256(raw).hexdigest()[:16],
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read(16384)
        except Exception:
            pass
        ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "url": url,
            "status": exc.code,
            "rtt_ms": ms,
            "length": len(raw),
            "hash": hashlib.sha256(raw).hexdigest()[:16],
            "error": None,
        }
    except Exception as exc:
        ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "url": url,
            "status": None,
            "rtt_ms": ms,
            "length": 0,
            "hash": "",
            "error": str(exc)[:200],
        }


def classify(probes):
    statuses = [p["status"] for p in probes]
    if all(s is None or s in (502, 503, 504) for s in statuses):
        return (
            "infra_unavailable",
            "high",
            "Target returned transport errors or 502/503/504 across all control probes; record scope_limit after 1-2 backed-off retries and stop polling.",
        )

    root_p, rand_p, param_p = probes[0], probes[1], probes[2]
    if root_p["status"] is not None and param_p["status"] is not None:
        if param_p["rtt_ms"] >= 3000 and root_p["rtt_ms"] < 800:
            return (
                "tarpit_delay",
                "medium",
                "Parameterized probe delayed significantly vs root; avoid timing-based oracles and switch to content/OOB signals.",
            )

    hashes = {p["hash"] for p in probes if p["status"] is not None}
    non_null = [s for s in statuses if s is not None]
    if len(non_null) == 3 and len(set(non_null)) == 1 and len(hashes) == 1:
        if non_null[0] in (403, 406, 429, 503):
            return (
                "uniform_filter",
                "high",
                f"All three control probes returned identical HTTP {non_null[0]} and body hash; edge WAF/rate-limit is blocking before app routing.",
            )
    return (
        "healthy_app",
        "high",
        "Application responded distinctly across control probes; proceed with targeted verification.",
    )


def main():
    parser = argparse.ArgumentParser(description="3-point HTTP health & fault triage (stdlib)")
    parser.add_argument("base_url", help="Target base URL (e.g. https://target.example.com/)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-probe timeout seconds (default: 8)")
    parser.add_argument("--dry-run", action="store_true", help="Output planned control URLs without sending requests")
    args = parser.parse_args()

    base = args.base_url.rstrip("/") + "/"
    rand_slug = "artex_triage_" + hashlib.md5(os.urandom(8)).hexdigest()[:8]
    urls = [
        base,
        urllib.parse.urljoin(base, rand_slug),
        base + "?artex_probe=1",
    ]
    if args.dry_run:
        print(json.dumps({"dry_run": True, "control_urls": urls, "timeout_s": args.timeout}, indent=2, ensure_ascii=False))
        return

    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    probes = [_probe(opener, u, args.timeout) for u in urls]
    verdict, confidence, action = classify(probes)
    print(json.dumps({
        "base_url": args.base_url,
        "verdict": verdict,
        "confidence": confidence,
        "recommended_action": action,
        "probes": probes,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
