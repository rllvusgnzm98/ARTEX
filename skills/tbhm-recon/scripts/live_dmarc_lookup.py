#!/usr/bin/env python3
"""
live_dmarc_lookup.py - DMARC Record & Organization Association Extractor
Extracts DMARC TXT records, parses rua/ruf endpoints, and discovers organizational relationships.
Outputs JSON for ARTEX asset ingestion.
"""

import sys
import json
import re
import urllib.request
import urllib.parse

def query_dmarc_doh(domain):
    """Query DMARC via Cloudflare DNS-over-HTTPS (reliable without local dns dependencies)."""
    target = f"_dmarc.{domain.strip().lower()}"
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(target)}&type=TXT"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "ARTEX-TBHM-Recon"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            answers = data.get("Answer", [])
            txt_records = []
            for ans in answers:
                if ans.get("type") == 16:  # TXT
                    txt_records.append(ans.get("data", "").strip('"'))
            return txt_records
    except Exception as e:
        return []

def parse_dmarc(record):
    """Parse DMARC tags like rua, ruf, p, sp."""
    tags = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags

def extract_domains_from_uris(uri_str):
    """Extract domains from rua/ruf mailto strings."""
    found = []
    # e.g. mailto:dmarc_rua@tesla.com,mailto:re+xxx@dmarcian.com
    emails = re.findall(r'mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', uri_str)
    for email in emails:
        domain = email.split("@")[-1].lower()
        found.append({"email": email, "domain": domain})
    return found

def analyze(domain):
    records = query_dmarc_doh(domain)
    res = {
        "target_domain": domain,
        "dmarc_found": False,
        "raw_records": records,
        "rua_domains": [],
        "ruf_domains": [],
        "related_domains": [],
        "policy": "unknown"
    }
    
    for r in records:
        if "DMARC1" in r:
            res["dmarc_found"] = True
            tags = parse_dmarc(r)
            res["policy"] = tags.get("p", "none")
            
            rua = tags.get("rua", "")
            if rua:
                rua_items = extract_domains_from_uris(rua)
                res["rua_domains"].extend(rua_items)
                
            ruf = tags.get("ruf", "")
            if ruf:
                ruf_items = extract_domains_from_uris(ruf)
                res["ruf_domains"].extend(ruf_items)

    related = set()
    for item in res["rua_domains"] + res["ruf_domains"]:
        d = item["domain"]
        if d != domain and not any(third_party in d for third_party in ['dmarcian.com', 'agari.com', 'valimail.com', 'ondmarc.com', 'proofpoint.com', 'mimecast.com', 'easy-dmarc.com']):
            related.add(d)
    
    res["related_domains"] = list(related)
    return res

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: live_dmarc_lookup.py <domain>", file=sys.stderr)
        sys.exit(1)
    
    domain = sys.argv[1]
    result = analyze(domain)
    print(json.dumps(result, indent=2, ensure_ascii=False))
