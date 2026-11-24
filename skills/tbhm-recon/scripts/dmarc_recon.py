#!/usr/bin/env python3
"""
dmarc_recon.py - Reverse DMARC Lookup Tool

Downloads Tranco + Majestic + Umbrella domain lists (~2-3M unique domains),
resolves _dmarc TXT records at high concurrency, stores in SQLite,
and provides reverse lookup by rua/ruf reporting address.

Usage:
    python dmarc_recon.py build [--concurrency 500] [--dns 8.8.8.8]
    python dmarc_recon.py search --rua "someone@dmarcian.com"
    python dmarc_recon.py search --ruf "someone@example.com"
    python dmarc_recon.py search --domain "tesla.com"
    python dmarc_recon.py stats
    python dmarc_recon.py export --rua "x@y.com" [--format csv|json]
"""

import argparse
import asyncio
import csv
import io
import json
import os
import re
import sqlite3
import sys
import time
import zipfile
from datetime import datetime, timezone

try:
    import aiodns
except ImportError:
    sys.exit("Missing dependency: pip install aiodns")

try:
    import aiohttp
except ImportError:
    sys.exit("Missing dependency: pip install aiohttp")

try:
    from tqdm import tqdm
except ImportError:
    sys.exit("Missing dependency: pip install tqdm")


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dmarc_recon.db")

DOMAIN_SOURCES = {
    "tranco": {
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "type": "zip_csv",
        "domain_col": 1,
        "skip_header": False,
    },
    "majestic": {
        "url": "https://downloads.majestic.com/majestic_million.csv",
        "type": "csv",
        "domain_col": 2,
        "skip_header": True,
    },
    "umbrella": {
        "url": "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
        "type": "zip_csv",
        "domain_col": 1,
        "skip_header": False,
    },
}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS domains (
            domain TEXT PRIMARY KEY,
            source TEXT
        );
        CREATE TABLE IF NOT EXISTS dmarc_records (
            domain      TEXT PRIMARY KEY,
            raw_record  TEXT,
            policy      TEXT,
            sub_policy  TEXT,
            pct         INTEGER,
            rua         TEXT,
            ruf         TEXT,
            sp_flag     TEXT,
            adkim       TEXT,
            aspf        TEXT,
            scanned_at  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_rua ON dmarc_records(rua);
        CREATE INDEX IF NOT EXISTS idx_ruf ON dmarc_records(ruf);
    """)
    conn.commit()
    return conn


def get_scanned_domains(conn):
    cur = conn.execute("SELECT domain FROM dmarc_records")
    return {row[0] for row in cur.fetchall()}


def insert_domains_batch(conn, domains, source):
    conn.executemany(
        "INSERT OR IGNORE INTO domains (domain, source) VALUES (?, ?)",
        [(d, source) for d in domains],
    )
    conn.commit()


def insert_dmarc_batch(conn, records):
    conn.executemany(
        """INSERT OR REPLACE INTO dmarc_records
           (domain, raw_record, policy, sub_policy, pct, rua, ruf,
            sp_flag, adkim, aspf, scanned_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        records,
    )
    conn.commit()


# ---------------------------------------------------------------------------
# DMARC parsing
# ---------------------------------------------------------------------------

def parse_dmarc(raw: str) -> dict:
    result = {"policy": None, "sub_policy": None, "pct": None,
              "rua": None, "ruf": None, "sp": None, "adkim": None, "aspf": None}

    if not raw or "V=DMARC1" not in raw.upper().replace(" ", ""):
        return result

    tags = [t.strip() for t in raw.split(";") if "=" in t]
    for tag in tags:
        key, _, val = tag.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "p":
            result["policy"] = val.lower()
        elif key == "sp":
            result["sub_policy"] = val.lower()
            result["sp"] = val.lower()
        elif key == "pct":
            try:
                result["pct"] = int(val)
            except ValueError:
                pass
        elif key == "rua":
            result["rua"] = val
        elif key == "ruf":
            result["ruf"] = val
        elif key == "adkim":
            result["adkim"] = val.lower()
        elif key == "aspf":
            result["aspf"] = val.lower()

    return result


# ---------------------------------------------------------------------------
# Domain list downloading
# ---------------------------------------------------------------------------

async def download_domain_list(session, name, config):
    print(f"  Downloading {name}...")
    domains = set()

    async with session.get(config["url"]) as resp:
        if resp.status != 200:
            print(f"  WARNING: Failed to download {name} (HTTP {resp.status})")
            return domains
        data = await resp.read()

    if config["type"] == "zip_csv":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            csv_name = zf.namelist()[0]
            text = zf.read(csv_name).decode("utf-8", errors="ignore")
    else:
        text = data.decode("utf-8", errors="ignore")

    reader = csv.reader(io.StringIO(text))
    if config["skip_header"]:
        next(reader, None)

    col = config["domain_col"]
    for row in reader:
        if len(row) > col:
            domain = row[col].strip().lower().rstrip(".")
            if domain and "." in domain and not domain.startswith("_"):
                domains.add(domain)

    print(f"  {name}: {len(domains):,} domains")
    return domains


async def download_all_lists():
    print("[*] Downloading domain lists...")
    all_domains = set()

    # Use ThreadedResolver to avoid c-ares DNS issues on Windows
    connector = aiohttp.TCPConnector(resolver=aiohttp.resolver.ThreadedResolver())
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=300),
        connector=connector,
    ) as session:
        tasks = [
            download_domain_list(session, name, config)
            for name, config in DOMAIN_SOURCES.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for name, result in zip(DOMAIN_SOURCES.keys(), results):
        if isinstance(result, Exception):
            print(f"  WARNING: {name} failed: {result}")
        else:
            all_domains |= result

    print(f"[*] Total unique domains: {len(all_domains):,}")
    return all_domains


# ---------------------------------------------------------------------------
# Async DNS resolution
# ---------------------------------------------------------------------------

async def resolve_dmarc(resolver, domain, semaphore):
    async with semaphore:
        try:
            result = await asyncio.wait_for(
                resolver.query_dns(f"_dmarc.{domain}", "TXT"),
                timeout=5.0,
            )
            for record in result.answer:
                txt = record.data.data.decode("utf-8", errors="ignore")
                if "DMARC1" in txt.upper().replace(" ", ""):
                    return (domain, txt)
            return None
        except (aiodns.error.DNSError, asyncio.TimeoutError, Exception):
            return None


async def scan_domains(domains, concurrency=500, dns_server="8.8.8.8"):
    resolver = aiodns.DNSResolver(nameservers=[dns_server, "1.1.1.1"])
    semaphore = asyncio.Semaphore(concurrency)
    conn = init_db()

    already_scanned = get_scanned_domains(conn)
    to_scan = [d for d in domains if d not in already_scanned]

    if not to_scan:
        print("[*] All domains already scanned. Nothing to do.")
        conn.close()
        return

    print(f"[*] Scanning {len(to_scan):,} domains ({len(already_scanned):,} already done)")
    print(f"    Concurrency: {concurrency} | DNS: {dns_server}")

    batch = []
    found = 0
    errors = 0
    now = datetime.now(timezone.utc).isoformat()

    pbar = tqdm(total=len(to_scan), desc="Resolving _dmarc", unit="dom",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] found:{postfix}")
    pbar.set_postfix_str("0")

    chunk_size = 2000
    for i in range(0, len(to_scan), chunk_size):
        chunk = to_scan[i : i + chunk_size]
        tasks = [resolve_dmarc(resolver, d, semaphore) for d in chunk]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result is not None:
                domain, raw = result
                parsed = parse_dmarc(raw)
                batch.append((
                    domain, raw, parsed["policy"], parsed["sub_policy"],
                    parsed["pct"], parsed["rua"], parsed["ruf"],
                    parsed["sp"], parsed["adkim"], parsed["aspf"], now,
                ))
                found += 1
            pbar.update(1)
            pbar.set_postfix_str(str(found))

        # Also record domains with no DMARC so we don't re-scan them
        found_in_batch = {r[0] for r in batch}
        no_dmarc = set(chunk) - found_in_batch
        no_dmarc_records = [(d, None, None, None, None, None, None, None, None, None, now) for d in no_dmarc]

        # Insert DMARC records first, then no-DMARC (INSERT OR IGNORE to avoid overwriting)
        if batch:
            insert_dmarc_batch(conn, batch)
        if no_dmarc_records:
            conn.executemany(
                "INSERT OR IGNORE INTO dmarc_records (domain, raw_record, policy, sub_policy, pct, rua, ruf, sp_flag, adkim, aspf, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                no_dmarc_records,
            )
            conn.commit()
        batch = []

    pbar.close()
    conn.close()
    print(f"\n[*] Done! Found {found:,} DMARC records out of {len(to_scan):,} domains scanned.")
    print(f"    Database: {DB_PATH}")


# ---------------------------------------------------------------------------
# Search / Query
# ---------------------------------------------------------------------------

def search_by_rua(conn, rua_query):
    # Support partial matching with LIKE
    pattern = f"%{rua_query}%"
    cur = conn.execute(
        "SELECT domain, rua, ruf, policy, raw_record FROM dmarc_records WHERE rua LIKE ? ORDER BY domain",
        (pattern,),
    )
    return cur.fetchall()


def search_by_ruf(conn, ruf_query):
    pattern = f"%{ruf_query}%"
    cur = conn.execute(
        "SELECT domain, rua, ruf, policy, raw_record FROM dmarc_records WHERE ruf LIKE ? ORDER BY domain",
        (pattern,),
    )
    return cur.fetchall()


def search_by_domain(conn, domain_query):
    pattern = f"%{domain_query}%"
    cur = conn.execute(
        "SELECT domain, rua, ruf, policy, raw_record FROM dmarc_records WHERE domain LIKE ? AND raw_record IS NOT NULL ORDER BY domain",
        (pattern,),
    )
    return cur.fetchall()


def print_results(results, title, brief=False):
    if not results:
        print(f"\nNo results found for: {title}")
        return

    if brief:
        for domain, rua, ruf, policy, raw in results:
            print(domain)
        return

    print(f"\n{'=' * 80}")
    print(f" {len(results)} domain(s) found for: {title}")
    print(f"{'=' * 80}")

    for domain, rua, ruf, policy, raw in results:
        print(f"\n  Domain:  {domain}")
        print(f"  Policy:  {policy or 'N/A'}")
        print(f"  RUA:     {rua or 'N/A'}")
        print(f"  RUF:     {ruf or 'N/A'}")
        print(f"  Record:  {raw[:120] + '...' if raw and len(raw) > 120 else raw}")

    print(f"\n{'=' * 80}")


# ---------------------------------------------------------------------------
# ASN Lookup
# ---------------------------------------------------------------------------

def _cymru_txt(query):
    """Query a TXT record via nslookup/dig/host and return raw output."""
    import subprocess
    for cmd in [
        ["nslookup", "-type=TXT", query],
        ["dig", "+short", "TXT", query],
        ["host", "-t", "TXT", query],
    ]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return r.stdout + r.stderr
        except FileNotFoundError:
            continue
    return ""


def resolve_asn_bulk(domains):
    """Resolve IPs and ASNs for a list of domains using Team Cymru DNS."""
    import socket
    import concurrent.futures

    asn_name_cache = {}

    def get_asn_name(asn_num):
        if asn_num in asn_name_cache:
            return asn_name_cache[asn_num]
        output = _cymru_txt(f"AS{asn_num}.asn.cymru.com")
        # Parse: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
        for line in output.splitlines():
            if "|" in line:
                fields = [f.strip().strip('"') for f in line.split("|")]
                if len(fields) >= 5:
                    name = fields[4].strip()
                    asn_name_cache[asn_num] = name
                    return name
        asn_name_cache[asn_num] = ""
        return ""

    def lookup_one(domain):
        try:
            ip = socket.gethostbyname(domain)
            parts = ip.split(".")
            cymru_query = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.origin.asn.cymru.com"
            output = _cymru_txt(cymru_query)
            # Parse: "15169 | 8.8.8.0/24 | US | arin | 2023-01-01"
            for line in output.splitlines():
                if "|" in line:
                    fields = [f.strip().strip('"') for f in line.split("|")]
                    if len(fields) >= 1:
                        asn_num = fields[0].strip()
                        return (domain, asn_num)
            return (domain, "")
        except Exception:
            return (domain, "")

    # Step 1: resolve all domains to ASN numbers
    domain_asn = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(lookup_one, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            domain, asn_num = future.result()
            domain_asn[domain] = asn_num

    # Step 2: resolve unique ASN numbers to names
    unique_asns = {v for v in domain_asn.values() if v}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        pool.map(get_asn_name, unique_asns)

    # Step 3: combine and clean org names
    results = {}
    for domain, asn_num in domain_asn.items():
        if asn_num:
            raw_name = asn_name_cache.get(asn_num, "")
            # Clean: "AKAMAI-AS - Akamai Technologies, Inc., US" -> "Akamai Technologies, Inc."
            org = raw_name
            if " - " in org:
                org = org.split(" - ", 1)[1]
            # Strip trailing country code like ", US" or ", NL"
            org = re.sub(r',\s*[A-Z]{2}$', '', org).strip()
            results[domain] = (f"AS{asn_num}", org)
        else:
            results[domain] = ("N/A", "")
    return results


def print_results_with_asn(results, title, asn_data):
    if not results:
        print(f"\nNo results found for: {title}")
        return

    print(f"\n{'=' * 100}")
    print(f" {len(results)} domain(s) found for: {title}")
    print(f"{'=' * 100}")
    print(f"  {'Domain':<40s} {'ASN':<12s} {'Org'}")
    print(f"  {'-'*40} {'-'*12} {'-'*40}")

    for domain, rua, ruf, policy, raw in results:
        asn, org = asn_data.get(domain, ("N/A", ""))
        print(f"  {domain:<40s} {asn:<12s} {org}")

    print(f"\n{'=' * 100}")


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def show_stats(conn):
    total = conn.execute("SELECT COUNT(*) FROM dmarc_records").fetchone()[0]
    with_dmarc = conn.execute("SELECT COUNT(*) FROM dmarc_records WHERE raw_record IS NOT NULL").fetchone()[0]
    total_domains = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]

    print(f"\n{'=' * 60}")
    print(f" DMARC Recon Database Stats")
    print(f"{'=' * 60}")
    print(f"  Domain lists loaded:    {total_domains:,}")
    print(f"  Domains scanned:        {total:,}")
    print(f"  DMARC records found:    {with_dmarc:,}")
    if total > 0:
        print(f"  DMARC adoption rate:    {with_dmarc / total * 100:.1f}%")

    # Policy breakdown
    print(f"\n  Policy Breakdown:")
    for policy, count in conn.execute(
        "SELECT policy, COUNT(*) FROM dmarc_records WHERE policy IS NOT NULL GROUP BY policy ORDER BY COUNT(*) DESC"
    ).fetchall():
        safe_policy = policy.encode("ascii", errors="replace").decode("ascii")
        print(f"    {safe_policy:12s} {count:>8,}")

    # Top 15 rua providers
    print(f"\n  Top 15 RUA Reporting Destinations:")
    cur = conn.execute("""
        SELECT
            CASE
                WHEN rua LIKE '%@%' THEN SUBSTR(rua, INSTR(rua, '@') + 1)
                ELSE rua
            END as provider,
            COUNT(*) as cnt
        FROM dmarc_records
        WHERE rua IS NOT NULL
        GROUP BY provider
        ORDER BY cnt DESC
        LIMIT 15
    """)
    for provider, count in cur.fetchall():
        # Clean up mailto: prefix artifacts
        provider = provider.replace("mailto:", "").split(",")[0].strip()
        print(f"    {provider:40s} {count:>8,}")

    print(f"\n  Database size: {os.path.getsize(DB_PATH) / 1024 / 1024:.1f} MB")
    print(f"  Database path: {DB_PATH}")
    print(f"{'=' * 60}")


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_results(results, fmt="csv"):
    if fmt == "json":
        data = [
            {"domain": r[0], "rua": r[1], "ruf": r[2], "policy": r[3], "raw_record": r[4]}
            for r in results
        ]
        print(json.dumps(data, indent=2))
    else:
        writer = csv.writer(sys.stdout)
        writer.writerow(["domain", "rua", "ruf", "policy", "raw_record"])
        for r in results:
            writer.writerow(r)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def cmd_build(args):
    conn = init_db()
    domains = await download_all_lists()

    # Store domain list
    print("[*] Storing domains in database...")
    batch = list(domains)
    for i in range(0, len(batch), 50000):
        insert_domains_batch(conn, batch[i : i + 50000], "combined")
    conn.close()

    # Scan
    await scan_domains(domains, concurrency=args.concurrency, dns_server=args.dns)


def cmd_search(args):
    if not os.path.exists(DB_PATH):
        sys.exit("Database not found. Run 'build' first.")

    conn = sqlite3.connect(DB_PATH)

    brief = getattr(args, "brief", False)
    use_asn = getattr(args, "asn", False)
    results = []
    title = ""
    if args.rua:
        results = search_by_rua(conn, args.rua)
        title = f"rua ~ {args.rua}"
    elif args.ruf:
        results = search_by_ruf(conn, args.ruf)
        title = f"ruf ~ {args.ruf}"
    elif args.domain:
        results = search_by_domain(conn, args.domain)
        title = f"domain ~ {args.domain}"
    else:
        print("Provide --rua, --ruf, or --domain")

    if results and use_asn and not brief:
        domains_list = [r[0] for r in results]
        print(f"[*] Resolving ASNs for {len(domains_list)} domains...")
        asn_data = resolve_asn_bulk(domains_list)
        print_results_with_asn(results, title, asn_data)
    elif results or title:
        print_results(results, title, brief=brief)

    if args.format and results:
        export_results(results, args.format)

    conn.close()


def cmd_recon(args):
    """Resolve a domain's DMARC record live, then reverse lookup all domains sharing the same rua."""
    import socket

    domain = args.domain.lower().strip().rstrip(".")

    brief = getattr(args, "brief", False)
    if not brief:
        print(f"[*] Resolving _dmarc.{domain} ...")
    try:
        answers = socket.getaddrinfo(f"_dmarc.{domain}", None)  # won't work for TXT
    except Exception:
        pass

    # Use dnspython-style stdlib to get TXT record
    # Fall back to subprocess since socket doesn't do TXT
    import subprocess
    try:
        # Try nslookup (works on Windows and most Linux)
        result = subprocess.run(
            ["nslookup", "-type=TXT", f"_dmarc.{domain}"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
    except FileNotFoundError:
        # Try dig on Linux
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout
        except FileNotFoundError:
            # Last resort: use host command
            try:
                result = subprocess.run(
                    ["host", "-t", "TXT", f"_dmarc.{domain}"],
                    capture_output=True, text=True, timeout=10,
                )
                output = result.stdout
            except FileNotFoundError:
                sys.exit("No DNS lookup tool found (nslookup, dig, or host)")

    # Extract DMARC record from output
    raw_dmarc = None
    for line in output.splitlines():
        if "DMARC1" in line.upper().replace(" ", ""):
            # Clean up the line — extract just the TXT value
            match = re.search(r'["\']?(v=DMARC1[^"\']*)["\']?', line, re.IGNORECASE)
            if match:
                raw_dmarc = match.group(1).strip().strip('"').strip("'")
                break
    # Also try joining multi-line TXT
    if not raw_dmarc:
        full = " ".join(output.splitlines())
        match = re.search(r'v=DMARC1[^"\']*', full, re.IGNORECASE)
        if match:
            raw_dmarc = match.group(0).strip()

    if not raw_dmarc:
        sys.exit(f"No DMARC record found for {domain}")

    if not brief:
        print(f"[*] DMARC record: {raw_dmarc}")

    parsed = parse_dmarc(raw_dmarc)
    rua = parsed.get("rua")
    ruf = parsed.get("ruf")

    if not brief:
        print(f"[*] Policy: {parsed.get('policy', 'N/A')}")
        print(f"[*] RUA: {rua or 'N/A'}")
        print(f"[*] RUF: {ruf or 'N/A'}")

    if not rua:
        print("\nNo RUA address found — cannot perform reverse lookup.")
        return

    # Extract individual email addresses from rua (can be comma-separated)
    rua_addresses = [addr.replace("mailto:", "").strip() for addr in rua.split(",")]

    if not os.path.exists(DB_PATH):
        print("\nWARNING: Database not found. Run 'build' first for reverse lookups.")
        return

    conn = sqlite3.connect(DB_PATH)

    use_asn = getattr(args, "asn", False)

    for addr in rua_addresses:
        addr_clean = addr.replace("mailto:", "").strip()
        if not addr_clean:
            continue
        if not brief:
            print(f"\n[*] Reverse lookup: {addr_clean}")
        results = search_by_rua(conn, addr_clean)

        if use_asn and results and not brief:
            domains_list = [r[0] for r in results]
            print(f"[*] Resolving ASNs for {len(domains_list)} domains...")
            asn_data = resolve_asn_bulk(domains_list)
            print_results_with_asn(results, f"rua ~ {addr_clean}", asn_data)
        else:
            print_results(results, f"rua ~ {addr_clean}", brief=brief)

        if args.format and results:
            export_results(results, args.format)

    conn.close()


def cmd_stats(args):
    if not os.path.exists(DB_PATH):
        sys.exit("Database not found. Run 'build' first.")
    conn = sqlite3.connect(DB_PATH)
    show_stats(conn)
    conn.close()


def cmd_export(args):
    if not os.path.exists(DB_PATH):
        sys.exit("Database not found. Run 'build' first.")

    conn = sqlite3.connect(DB_PATH)
    results = []
    if args.rua:
        results = search_by_rua(conn, args.rua)
    elif args.ruf:
        results = search_by_ruf(conn, args.ruf)
    elif args.domain:
        results = search_by_domain(conn, args.domain)

    if results:
        export_results(results, args.format)
    else:
        print("No results to export.", file=sys.stderr)

    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Reverse DMARC Lookup Tool - Find domains by RUA/RUF reporting address",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dmarc_recon.py build
  python dmarc_recon.py build --concurrency 1000 --dns 1.1.1.1
  python dmarc_recon.py recon fisglobal.com
  python dmarc_recon.py recon tesla.com --format csv
  python dmarc_recon.py search --rua "dmarcian.com"
  python dmarc_recon.py search --domain "tesla.com"
  python dmarc_recon.py stats
  python dmarc_recon.py export --rua "dmarcian.com" --format json
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # build
    build_p = sub.add_parser("build", help="Download domain lists and scan DMARC records")
    build_p.add_argument("--concurrency", type=int, default=500, help="Concurrent DNS queries (default: 500)")
    build_p.add_argument("--dns", default="8.8.8.8", help="DNS server to use (default: 8.8.8.8)")

    # search
    search_p = sub.add_parser("search", help="Search DMARC records")
    search_p.add_argument("--rua", help="Search by RUA reporting address (partial match)")
    search_p.add_argument("--ruf", help="Search by RUF forensic address (partial match)")
    search_p.add_argument("--domain", help="Search by domain name (partial match)")
    search_p.add_argument("--brief", "-b", action="store_true", help="Only print domain names")
    search_p.add_argument("--asn", action="store_true", help="Resolve IPs and ASNs for each domain")
    search_p.add_argument("--format", choices=["csv", "json"], help="Output format")

    # recon
    recon_p = sub.add_parser("recon", help="Auto-resolve a domain's DMARC and reverse lookup all related domains")
    recon_p.add_argument("domain", help="Target domain (e.g., fisglobal.com)")
    recon_p.add_argument("--brief", "-b", action="store_true", help="Only print domain names")
    recon_p.add_argument("--asn", action="store_true", help="Resolve IPs and ASNs for each domain")
    recon_p.add_argument("--format", choices=["csv", "json"], help="Output format")

    # stats
    sub.add_parser("stats", help="Show database statistics")

    # export
    export_p = sub.add_parser("export", help="Export search results")
    export_p.add_argument("--rua", help="Search by RUA")
    export_p.add_argument("--ruf", help="Search by RUF")
    export_p.add_argument("--domain", help="Search by domain")
    export_p.add_argument("--format", choices=["csv", "json"], default="csv", help="Export format (default: csv)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "build":
        asyncio.run(cmd_build(args))
    elif args.command == "recon":
        cmd_recon(args)
    elif args.command == "search":
        cmd_search(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "export":
        cmd_export(args)


if __name__ == "__main__":
    main()
