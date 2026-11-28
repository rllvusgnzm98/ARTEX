#!/usr/bin/env python3
"""
oracle_calibrate.py - HTTP RTT baseline & boolean/timing separability calibrator (stdlib only).
Samples baseline response latencies/lengths/statuses and optionally checks true vs false probe separation.
"""

import argparse
import json
import os
import ssl
import statistics
import time
import urllib.error
import urllib.request

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


def _sample_once(opener, url, timeout):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": os.environ.get("ARTEX_UA") or DEFAULT_UA, "Accept": "*/*"},
        method="GET",
    )
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(65536)
            return {
                "status": resp.status,
                "length": len(raw),
                "rtt_ms": round((time.monotonic() - t0) * 1000, 1),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        raw = b""
        try:
            raw = exc.read(16384)
        except Exception:
            pass
        return {
            "status": exc.code,
            "length": len(raw),
            "rtt_ms": round((time.monotonic() - t0) * 1000, 1),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": None,
            "length": 0,
            "rtt_ms": round((time.monotonic() - t0) * 1000, 1),
            "error": str(exc)[:180],
        }


def summarize_samples(samples):
    rtts = [s["rtt_ms"] for s in samples if s["status"] is not None]
    lens = [s["length"] for s in samples if s["status"] is not None]
    statuses = [s["status"] for s in samples if s["status"] is not None]
    if not rtts:
        return {"ok": False, "samples": samples}
    rtts_sorted = sorted(rtts)
    p50 = statistics.median(rtts_sorted)
    p95 = rtts_sorted[min(len(rtts_sorted) - 1, max(0, int(round(0.95 * (len(rtts_sorted) - 1)))))]
    recommended_delay_ms = max(int(round(p95 * 3.0)), int(round(p95 + 1000)))
    return {
        "ok": True,
        "count": len(rtts),
        "statuses": sorted(set(statuses)),
        "min_len": min(lens),
        "max_len": max(lens),
        "rtt_p50_ms": round(p50, 1),
        "rtt_p95_ms": round(p95, 1),
        "recommended_sleep_threshold_ms": recommended_delay_ms,
        "samples": samples,
    }


def main():
    parser = argparse.ArgumentParser(description="Blind oracle RTT & separability calibrator (stdlib)")
    parser.add_argument("target_url", help="Baseline URL to sample")
    parser.add_argument("--true-url", help="Optional positive control URL for boolean separability check")
    parser.add_argument("--false-url", help="Optional negative control URL for boolean separability check")
    parser.add_argument("--samples", type=int, default=5, help="Baseline sample count (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print calibration plan without HTTP requests")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps({
            "dry_run": True,
            "target_url": args.target_url,
            "true_url": args.true_url,
            "false_url": args.false_url,
            "samples": args.samples,
        }, indent=2, ensure_ascii=False))
        return

    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    base_samples = [_sample_once(opener, args.target_url, args.timeout) for _ in range(max(1, min(args.samples, 20)))]
    out = {"baseline": summarize_samples(base_samples)}

    if args.true_url and args.false_url:
        t_samples = [_sample_once(opener, args.true_url, args.timeout) for _ in range(3)]
        f_samples = [_sample_once(opener, args.false_url, args.timeout) for _ in range(3)]
        t_sum = summarize_samples(t_samples)
        f_sum = summarize_samples(f_samples)
        separable = False
        if t_sum.get("ok") and f_sum.get("ok"):
            if set(t_sum["statuses"]) != set(f_sum["statuses"]):
                separable = True
            elif t_sum["max_len"] < f_sum["min_len"] or f_sum["max_len"] < t_sum["min_len"]:
                separable = True
        out["boolean_check"] = {"true": t_sum, "false": f_sum, "separable": separable}

    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
