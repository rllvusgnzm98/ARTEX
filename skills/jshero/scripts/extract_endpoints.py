#!/usr/bin/env python3
"""
JShero endpoint + parameter extractor with a persistent per-target ledger.

Scans the JavaScript collected by JShero (raw-js/, inline-js/, historical-js/ under a
run folder), extracts links/endpoints and parameters, classifies every link into one
of four categories, diffs the results against a per-target ledger of everything already
known, and writes both the full result set and the newly-discovered items. In-scope new
URLs are emitted separately so they can be fed into another collection pass.

The four link categories (as requested):
  1. full                -> https://example.com/*  and  //example.com/*
  2. absolute_or_dotted  -> /*   ./*   ../*   #/*
  3. relative_with_slash -> path/to/file.php
  4. relative_no_slash   -> file.php

Link/param parsing regexes are adapted from GAP-Burp-Extension by @Xnl-h4ck3r
(https://github.com/xnl-h4ck3r/GAP-Burp-Extension). GAP's master link regex already
covers all four categories above; the JS-built (.get/.post/...), fetch(), query-key,
sourcemap, and encoded-separator patterns are ported for smarter coverage.

Usage:
  python extract_endpoints.py --run-root "runs/<domain>/<ts>" --domain <domain> [--seed https://www.<domain>]

Stdlib only. Reads files as utf-8 with errors ignored so minified/binary bodies never crash it.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

# --- file extensions treated as "interesting" for extension-anchored links (GAP LINK_REGEX_FILES) ---
LINK_REGEX_FILES = (
    r"php|php3|php5|asp|aspx|ashx|cfm|cgi|pl|jsp|jspx|json|js|action|html|xhtml|htm|bak|do|txt|"
    r"wsdl|wadl|xml|xls|xlsx|bin|conf|config|bz2|bzip2|gzip|tar\.gz|tgz|log|src|zip|js\.map"
)


def _nonstandard_files(files=LINK_REGEX_FILES):
    # GAP's rule: keep extensions longer than 4 chars or containing a digit (used in the 4th group).
    out = [ext for ext in files.split("|") if len(ext) > 4 or any(c.isdigit() for c in ext)]
    return "|".join(out)


_NONSTD = _nonstandard_files()

# --- master link regex (adapted from GAP REGEX_LINKS) ---
# Branch 1: full URLs (scheme:// or //) ; Branch 2: absolute/dotted (/ ./ ../ #/) ;
# Branch 3: relative-with-slash + known extension ; Branch 4: bare file.ext (relative-no-slash) ;
# plus robots Disallow/Allow, Domain=, <http...>, quoted dir/file, and S3 <Key> bodies.
REGEX_LINKS = re.compile(
    r"(?:(?<=^)|(?<=\"|'|\n|\r|\s))"
    r"(((?:[a-zA-Z]{1,10}:\/\/|\/\/)([^\"'\/\s]{1,255}\.[a-zA-Z]{2,24}|localhost)[^\"'\n\s]{0,255})"
    r"|((?:#?\/|\.\.\/|\.\/)[^\"'><,;| *()(%$^\/\\\[\]][^\"'><,;|()\s]{1,255})"
    r"|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/\.]{1,255}\.(?:[a-zA-Z]{1,4}" + _NONSTD + r")(?:[\?|\/][^\"|']{0,1000}|))"
    r"|([a-zA-Z0-9_\-\.]{1,255}\.(?:" + LINK_REGEX_FILES + r")(?:\?[^\"|^']{0,255}|)))"
    r"(?=$|\"|'|\n|\r|\s)"
    r"|(?<=^Disallow:\s)[^\$\n]{0,500}"
    r"|(?<=^Allow:\s)[^\$\n]{0,500}"
    r"|(?<= Domain\=)[^\";']{0,500}"
    r"|(?<=\<)https?:\/\/[^>\n]{0,1000}"
    r"|(\"|\')([A-Za-z0-9_-]+\/)+[A-Za-z0-9_-]+(\.[A-Za-z0-9]{2,}|\/?(\?|\#)[A-Za-z0-9_\-&=\[\]]{0,500})(\"|\')"
    r"|(?<=\<Key\>)[^\<]{1,500}(?=\<\/Key\>)",
    re.IGNORECASE,
)

# endpoints built in JS via axios/jquery style verbs and fetch()
REGEX_LINKS_JSBUILT = re.compile(r'\.(?:get|post|put|delete|patch)\(\s*["\'`]([^)"\'`]{1,1000}?)["\'`]', re.IGNORECASE)
REGEX_LINKS_FETCH = re.compile(r"""fetch\s*\(\s*["'`]((?:\/|https?:\/\/)[^"'`)]{1,1000})["'`]""", re.IGNORECASE)

# query parameter keys (GAP REGEX_PARAMKEYS) plus validity checks (tightened from GAP REGEX_PARAM
# to cut minified-JS noise). CONTENT is strict (raw scan); QUERY is lenient (keys of ?k=v links).
REGEX_PARAMKEYS = re.compile(r"(?<=\?|&)[^\=\&\n].{0,1000}?(?=\=|&|\n)")
REGEX_PARAM_CONTENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{2,99}$")
REGEX_PARAM_QUERY = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\[\]\.]{0,99}$")

# characters that never appear in a real link but are common in minified-JS false positives
_BAD_LINK_CHARS = set("`${}<>*;\\ (),")


def valid_link(link):
    if not link or len(link) > 600:
        return False
    if any(ch in link for ch in _BAD_LINK_CHARS):
        return False
    if link.count("#") > 1:
        return False
    if not re.search(r"[A-Za-z]", link):  # must contain a letter somewhere
        return False
    return True

# sourcemap reference
REGEX_SOURCEMAP = re.compile(r"(?<=sourceMappingURL=)[^\s\*]{1,500}", re.IGNORECASE)

# normalization of encoded separators, so encoded links are recovered (adapted from GAP REGEX_LINKS* subs)
_DECODE = [
    (re.compile(r"&#x2f;|&#0?47;|%2f|\\u002f", re.IGNORECASE), "/"),
    (re.compile(r"&#x3a;|&#0?58;|%3a|\\u003a", re.IGNORECASE), ":"),
    (re.compile(r"%3d|&equals;|&#0?61;|\\u003d", re.IGNORECASE), "="),
    (re.compile(r"%26|&amp;|&#0?38;|\\u0026", re.IGNORECASE), "&"),
    (re.compile(r"%3f|&#0?63;|\\u003f", re.IGNORECASE), "?"),
    (re.compile(r"\\/"), "/"),
]

# static-asset extensions to drop from the endpoint list (we want endpoints, not media/styles)
EXCLUDE_EXT = {
    "css", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf",
    "otf", "eot", "mp4", "webm", "mp3", "wav", "avif", "bmp", "tif", "tiff", "m4a", "mov",
}

JS_GLOBS = ("*.js", "*.mjs", "*.map")
SCAN_DIRS = ("raw-js", "inline-js", "historical-js")


def decode_seps(text):
    for pat, rep in _DECODE:
        text = pat.sub(rep, text)
    return text


def clean_link(s):
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] in "\"'":
        s = s[1:-1]
    return s.strip().strip("\"'` \t\r\n")


def classify(link):
    if re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]{0,9}://|//)", link):
        return "full"
    if link.startswith(("/", "./", "../", "#/")):
        return "absolute_or_dotted"
    if "/" in link:
        return "relative_with_slash"
    return "relative_no_slash"


def is_asset(link):
    path = link.split("?")[0].split("#")[0]
    last = path.rsplit("/", 1)[-1]
    if "." not in last:
        return False
    return last.rsplit(".", 1)[-1].lower() in EXCLUDE_EXT


def in_scope(link, domain, seed):
    try:
        absu = link if re.match(r"^https?://", link, re.IGNORECASE) else urljoin(seed, link)
        host = urlsplit(absu).hostname or ""
    except Exception:
        return False
    host = host.lower()
    return host == domain or host.endswith("." + domain)


def host_of(u):
    try:
        return (urlsplit(u if re.match(r"^https?://", u, re.I) else "https:" + u).hostname or "").lower()
    except Exception:
        return ""


# ---- jsluice-derived discovery (URL/path/endpoint/param), adapted from BishopFox/jsluice ----
# MaybeURL: jsluice's quality gate for treating a string as a URL/path.
FILE_EXTENSIONS_MAYBEURL = {
    "js", "css", "html", "htm", "xhtml", "xlsx", "xls", "docx", "doc", "pdf", "rss",
    "xml", "php", "phtml", "asp", "aspx", "asmx", "ashx", "cgi", "pl", "rb", "py",
    "do", "jsp", "jspa", "json", "jsonp", "txt",
}
_MAYBEURL_BAD = set(" ()!<>'\"`{}^$,")


def maybe_url(s):
    if not any(c in s for c in "/?."):
        return False
    if any(c in s for c in _MAYBEURL_BAD):
        return False
    if s.startswith("/"):
        return True
    try:
        u = urlsplit(s)
    except Exception:
        return False
    if u.scheme and u.scheme.lower() not in ("http", "https"):
        return False
    host = u.hostname or ""
    if host and len(host.split(".")) > 1:
        return True
    if u.query:
        for pair in u.query.split("&"):
            if "=" in pair and pair.split("=", 1)[1]:
                return True
    path = u.path or s
    if "." not in path:
        return False
    return path.rsplit(".", 1)[-1].lower() in FILE_EXTENSIONS_MAYBEURL


# template literals: normalize ${...} to EXPR (jsluice ExpressionPlaceholder)
REGEX_TEMPLATE = re.compile(r"`([^`]{1,1000})`")
REGEX_TEMPLATE_EXPR = re.compile(r"\$\{[^}]{0,200}\}")


def normalize_template(s):
    return REGEX_TEMPLATE_EXPR.sub("EXPR", s)


def is_all_expr(link):
    return re.sub(r"[^A-Za-z]", "", link).replace("EXPR", "") == ""


# assignment sinks whose RHS is a URL/path (jsluice: location, *.href, *.src, this.baseUrl)
REGEX_ASSIGN_SINK = re.compile(
    r"""(?:\blocation\b(?:\.(?:href|assign|replace))?|[\w$.]+\.(?:href|src)|this\.(?:url|_url|baseUrl))\s*=\s*['"`]([^'"`]{1,600})['"`]""",
    re.IGNORECASE,
)
# calls taking a URL first arg (fetch/axios/$.get/$.post/$.ajax/jQuery)
REGEX_CALL_URL = re.compile(
    r"""\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|\$\.(?:get|post|ajax)|jQuery\.(?:get|post|ajax))\s*\(\s*['"`]([^'"`]{1,600})['"`]""",
    re.IGNORECASE,
)
# XHR .open("METHOD","url") -> method + url
REGEX_XHR_OPEN = re.compile(
    r"""\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]\s*,\s*['"`]([^'"`]{1,600})['"`]""",
    re.IGNORECASE,
)
# axios.<verb>( and $.get/$.post/jQuery.get -> method context by verb
REGEX_VERB_CALL = re.compile(
    r"""\b(?:axios\.(get|post|put|delete|patch)|\$\.(get|post)|jQuery\.(get|post))\s*\(\s*['"`]([^'"`]{1,600})['"`]""",
    re.IGNORECASE,
)
# body/query param objects (jsluice BodyParams/QueryParams from config objects)
REGEX_PARAM_OBJ = re.compile(r"""\b(?:data|params|body|query|form|json)\s*:\s*\{([^{}]{0,2000})\}""", re.IGNORECASE)
REGEX_OBJ_KEY = re.compile(r"""['"]?([A-Za-z_$][\w$\-]{0,60})['"]?\s*:""")


def accept_link(link):
    """Quality gate: our four categories pass by prefix; other candidates go through MaybeURL."""
    if not valid_link(link) or is_all_expr(link):
        return False
    if link.startswith(("/", "./", "../", "#/")):
        return True
    if maybe_url(link):
        return True
    last = link.split("?")[0].split("#")[0].rsplit("/", 1)[-1]
    return "." in last and last.rsplit(".", 1)[-1].lower() in FILE_EXTENSIONS_MAYBEURL


def _params_from_query(link, params):
    if "?" in link:
        for pair in re.split(r"[&;]", link.split("?", 1)[1]):
            key = pair.split("=", 1)[0].strip()
            if REGEX_PARAM_QUERY.match(key) and key != "EXPR":
                params.add(key)


def extract_from_text(text):
    """Return (links:set, params:set, methods:list[(method,url)]) from one file's text."""
    links, params, methods = set(), set(), []
    decoded = decode_seps(text)
    for src in (text, decoded):
        for m in REGEX_LINKS.finditer(src):
            link = clean_link(m.group(0))
            if valid_link(link) and not is_all_expr(link):
                links.add(link)
        for m in REGEX_LINKS_JSBUILT.finditer(src):
            link = clean_link(m.group(1))
            if accept_link(link):
                links.add(link)
        for m in REGEX_LINKS_FETCH.finditer(src):
            link = clean_link(m.group(1))
            if accept_link(link):
                links.add(link)
        # jsluice: assignment sinks + URL-arg calls
        for rx in (REGEX_ASSIGN_SINK, REGEX_CALL_URL):
            for m in rx.finditer(src):
                link = clean_link(normalize_template(m.group(1)))
                if accept_link(link):
                    links.add(link)
        # jsluice: XHR open(method,url) and verb calls -> method context
        for m in REGEX_XHR_OPEN.finditer(src):
            link = clean_link(normalize_template(m.group(2)))
            if accept_link(link):
                links.add(link)
                methods.append((m.group(1).upper(), link))
        for m in REGEX_VERB_CALL.finditer(src):
            verb = (m.group(1) or m.group(2) or m.group(3) or "").upper()
            link = clean_link(normalize_template(m.group(4)))
            if accept_link(link):
                links.add(link)
                methods.append((verb, link))
        # jsluice: template literals as route skeletons (${...} -> EXPR)
        for m in REGEX_TEMPLATE.finditer(src):
            body = normalize_template(m.group(1))
            for lm in REGEX_LINKS.finditer(body):
                link = clean_link(lm.group(0))
                if valid_link(link) and not is_all_expr(link):
                    links.add(link)
            cand = clean_link(body)
            if accept_link(cand):
                links.add(cand)
        # Parameters come only from high-precision sources (jsluice approach): actual URL
        # query strings (below) and config-object body/query params. The raw-content "?k="
        # scan is intentionally NOT used — on minified JS it yields mostly variable-name noise.
        for m in REGEX_PARAM_OBJ.finditer(src):
            for km in REGEX_OBJ_KEY.finditer(m.group(1)):
                key = km.group(1)
                if REGEX_PARAM_CONTENT.match(key) and key != "EXPR":
                    params.add(key)
    # query-string params are added in main() from IN-SCOPE links only (see scope split)
    return links, params, methods


def load_ledger(path):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"domain": None, "runs": [], "endpoints": {}, "params": {}}


def main():
    ap = argparse.ArgumentParser(description="JShero endpoint + parameter extractor with a persistent ledger.")
    ap.add_argument("--run-root", required=True, help="Run folder containing raw-js/ inline-js/ historical-js/")
    ap.add_argument("--domain", required=True, help="Registrable domain (scope + ledger location)")
    ap.add_argument("--seed", default=None, help="Seed URL for resolving relative links (default https://<domain>)")
    ap.add_argument("--ledger", default=None, help="Ledger path (default <run-root>/../ledger.json)")
    args = ap.parse_args()

    run_root = Path(args.run_root)
    if not run_root.is_dir():
        print(f"ERROR: run-root not found: {run_root}", file=sys.stderr)
        return 2
    domain = args.domain.lower().lstrip(".")
    seed = args.seed or f"https://{domain}"
    ledger_path = Path(args.ledger) if args.ledger else (run_root.parent / "ledger.json")
    run_id = run_root.name
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # gather JS files
    files = []
    for sub in SCAN_DIRS:
        d = run_root / sub
        if d.is_dir():
            for g in JS_GLOBS:
                files.extend(d.rglob(g))
    if not files:
        print(f"WARNING: no JS files found under {run_root}\\{{{','.join(SCAN_DIRS)}}}", file=sys.stderr)

    all_links, all_params = {}, set()
    all_methods = {}   # url -> set(methods)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        links, params, methods = extract_from_text(text)
        all_params |= params
        for link in links:
            if is_asset(link):
                continue
            cat = classify(link)
            # category 4 (relative, no slash) is specifically file.ext, so it must carry a dot
            if cat == "relative_no_slash" and "." not in link:
                continue
            all_links.setdefault(link, cat)
        for meth, url in methods:
            if not is_asset(url):
                all_methods.setdefault(url, set()).add(meth)

    # split target (in-scope) from third-party; the main report is target-only.
    # Only `full` URLs carry a host; relative/absolute paths always resolve to the target.
    inscope, thirdparty = {}, {}
    for url, cat in all_links.items():
        if cat == "full":
            h = host_of(url)
            if not h or "." not in h:
                continue  # malformed protocol-relative / code fragment -> drop entirely
            (inscope if in_scope(url, domain, seed) else thirdparty)[url] = cat
        else:
            inscope[url] = cat
    # query-string params come only from in-scope endpoints (third-party keys like utm_* are noise)
    for url in inscope:
        _params_from_query(url, all_params)
    all_methods = {u: m for u, m in all_methods.items() if u in inscope}

    # ledger diff (target endpoints only)
    ledger = load_ledger(ledger_path)
    ledger["domain"] = domain
    known_ep = ledger.setdefault("endpoints", {})
    known_pa = ledger.setdefault("params", {})
    new_links = {k: v for k, v in inscope.items() if k not in known_ep}
    new_params = sorted(p for p in all_params if p not in known_pa)

    for link, cat in new_links.items():
        known_ep[link] = {"category": cat, "first_seen_run": run_id, "first_seen_utc": now}
    for p in new_params:
        known_pa[p] = {"first_seen_run": run_id, "first_seen_utc": now}
    if run_id not in ledger.setdefault("runs", []):
        ledger["runs"].append(run_id)
    ledger_path.write_text(json.dumps(ledger, indent=2, sort_keys=True), encoding="utf-8")

    # in-scope reseed URLs from NEW full/absolute links (resolved absolute), deduped
    reseed = set()
    for link, cat in new_links.items():
        if cat in ("full", "absolute_or_dotted") and in_scope(link, domain, seed):
            try:
                reseed.add(link if re.match(r"^https?://", link, re.IGNORECASE) else urljoin(seed, link))
            except Exception:
                pass

    # write outputs
    def write_lines(name, lines):
        (run_root / name).write_text("".join(l + "\n" for l in lines), encoding="utf-8")

    cat_order = ["full", "absolute_or_dotted", "relative_with_slash", "relative_no_slash"]
    all_sorted = sorted(inscope.items(), key=lambda kv: (cat_order.index(kv[1]), kv[0]))
    new_sorted = sorted(new_links.items(), key=lambda kv: (cat_order.index(kv[1]), kv[0]))
    write_lines("endpoints-all.txt", [f"{c}\t{k}" for k, c in all_sorted])
    write_lines("endpoints-new.txt", [f"{c}\t{k}" for k, c in new_sorted])
    write_lines("params-all.txt", sorted(all_params))
    write_lines("params-new.txt", new_params)
    write_lines("reseed-urls.txt", sorted(reseed))
    write_lines(
        "endpoints-methods.txt",
        [f"{','.join(sorted(all_methods[u]))}\t{u}" for u in sorted(all_methods)],
    )

    # third-party endpoints -> their own file (host-tagged), excluded from the main report
    tp_sorted = sorted(thirdparty, key=lambda u: (host_of(u), u))
    write_lines("endpoints-thirdparty.txt", [f"{host_of(u)}\t{u}" for u in tp_sorted])

    counts_by_cat = {c: sum(1 for v in inscope.values() if v == c) for c in cat_order}
    summary = {
        "run_id": run_id,
        "domain": domain,
        "scanned_files": len(files),
        "endpoints_found": len(inscope),
        "endpoints_thirdparty": len(thirdparty),
        "endpoints_new": len(new_links),
        "endpoints_by_category": counts_by_cat,
        "endpoints_with_method": len(all_methods),
        "params_found": len(all_params),
        "params_new": len(new_params),
        "reseed_urls": len(reseed),
        "ledger_total_endpoints": len(known_ep),
        "ledger_total_params": len(known_pa),
        "ledger_path": str(ledger_path),
    }
    (run_root / "extract-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print("\nendpoints by category (this run):")
    for c in cat_order:
        print(f"  {c:<20} {counts_by_cat[c]}")
    print(f"\nTarget endpoints: {len(inscope)}  |  third-party (separate file): {len(thirdparty)}")
    print(f"NEW this run: {len(new_links)} endpoints, {len(new_params)} params, {len(reseed)} in-scope reseed URLs")
    print(f"Ledger: {ledger_path}  (totals: {len(known_ep)} endpoints, {len(known_pa)} params)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
