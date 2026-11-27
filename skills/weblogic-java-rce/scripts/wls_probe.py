#!/usr/bin/env python3
"""Deterministic XML entity escaper, well-formedness validator, and read-only WebLogic endpoint inventory planner.

Uses Python 3 standard library only and emits structured JSON.
Does not send network traffic or generate exploit payloads.
"""

import argparse
import json
import pathlib
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from xml.sax import saxutils
from typing import Any, Dict, List, Set, Tuple


INVALID_XML10_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
DTD_OR_ENTITY_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)

STANDARD_SCHEMA_HOSTS: Set[str] = {
    "www.w3.org",
    "schemas.xmlsoap.org",
    "schemas.microsoft.com",
    "www.bea.com",
    "xmlns.oracle.com",
    "www.springframework.org",
    "java.sun.com",
}

ENDPOINT_PROFILES: Dict[str, List[Dict[str, Any]]] = {
    "minimal": [
        {
            "path": "/console/login/LoginForm.jsp",
            "method": "GET",
            "category": "admin_console",
            "purpose": "Check WebLogic Administration Console login presence and version footer/headers.",
            "expected_indicators": ["WebLogic Server", "ADMINCONSOLESESSION", "X-Powered-By"],
        },
        {
            "path": "/bea_wls_internal/",
            "method": "HEAD",
            "category": "internal_service",
            "purpose": "Confirm WebLogic internal servlet mapping existence (read-only status/header check).",
            "expected_indicators": ["Server", "X-Powered-By", "HTTP 403/404 differentiation"],
        },
    ],
    "standard": [
        {
            "path": "/console/login/LoginForm.jsp",
            "method": "GET",
            "category": "admin_console",
            "purpose": "Check WebLogic Administration Console login presence and version footer/headers.",
            "expected_indicators": ["WebLogic Server", "ADMINCONSOLESESSION", "X-Powered-By"],
        },
        {
            "path": "/console/",
            "method": "HEAD",
            "category": "admin_console",
            "purpose": "Verify console redirect target and Set-Cookie flags (HttpOnly/Secure).",
            "expected_indicators": ["Location", "Set-Cookie", "ADMINCONSOLESESSION"],
        },
        {
            "path": "/bea_wls_internal/",
            "method": "HEAD",
            "category": "internal_service",
            "purpose": "Confirm WebLogic internal servlet mapping existence (read-only).",
            "expected_indicators": ["Server", "X-Powered-By"],
        },
        {
            "path": "/wls-wsat/",
            "method": "HEAD",
            "category": "soap_subsystem",
            "purpose": "Inventory whether WS-AtomicTransaction web service component is deployed.",
            "expected_indicators": ["HTTP 200/403/404", "Server"],
        },
        {
            "path": "/_async/",
            "method": "HEAD",
            "category": "async_subsystem",
            "purpose": "Inventory whether AsyncResponseService subsystem is exposed.",
            "expected_indicators": ["HTTP 200/403/404", "Server"],
        },
        {
            "path": "/uddiexplorer/",
            "method": "HEAD",
            "category": "uddi_subsystem",
            "purpose": "Check whether optional UDDI Explorer web application is deployed.",
            "expected_indicators": ["HTTP 200/302/404", "Set-Cookie"],
        },
    ],
    "extended": [
        {
            "path": "/console/login/LoginForm.jsp",
            "method": "GET",
            "category": "admin_console",
            "purpose": "Check WebLogic Administration Console login presence and version footer/headers.",
            "expected_indicators": ["WebLogic Server", "ADMINCONSOLESESSION", "X-Powered-By"],
        },
        {
            "path": "/console/",
            "method": "HEAD",
            "category": "admin_console",
            "purpose": "Verify console redirect target and Set-Cookie flags.",
            "expected_indicators": ["Location", "Set-Cookie"],
        },
        {
            "path": "/bea_wls_internal/",
            "method": "HEAD",
            "category": "internal_service",
            "purpose": "Confirm WebLogic internal servlet mapping existence.",
            "expected_indicators": ["Server", "X-Powered-By"],
        },
        {
            "path": "/bea_wls_deployment_internal/",
            "method": "HEAD",
            "category": "deployment_service",
            "purpose": "Inventory deployment internal endpoint availability.",
            "expected_indicators": ["HTTP 200/403/404", "Server"],
        },
        {
            "path": "/wls-wsat/",
            "method": "HEAD",
            "category": "soap_subsystem",
            "purpose": "Inventory whether WS-AtomicTransaction web service component is deployed.",
            "expected_indicators": ["HTTP 200/403/404", "Server"],
        },
        {
            "path": "/_async/",
            "method": "HEAD",
            "category": "async_subsystem",
            "purpose": "Inventory whether AsyncResponseService subsystem is exposed.",
            "expected_indicators": ["HTTP 200/403/404", "Server"],
        },
        {
            "path": "/uddiexplorer/",
            "method": "HEAD",
            "category": "uddi_subsystem",
            "purpose": "Check whether optional UDDI Explorer web application is deployed.",
            "expected_indicators": ["HTTP 200/302/404"],
        },
        {
            "path": "/em/",
            "method": "HEAD",
            "category": "enterprise_manager",
            "purpose": "Check whether Fusion Middleware Control (/em) is deployed.",
            "expected_indicators": ["Location", "X-ORACLE-DMS-ECID"],
        },
        {
            "path": "/sbconsole/",
            "method": "HEAD",
            "category": "service_bus",
            "purpose": "Check whether Oracle Service Bus Console is deployed.",
            "expected_indicators": ["Location", "Server"],
        },
    ],
}


def cmd_plan(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    parsed = urllib.parse.urlparse(args.base_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return 2, {
            "ok": False,
            "error": "base-url must be a valid http:// or https:// URL with a host",
            "base_url": args.base_url,
        }

    base = f"{parsed.scheme}://{parsed.netloc}"
    entries = list(ENDPOINT_PROFILES[args.profile])

    if args.custom_paths:
        for raw in args.custom_paths.split(","):
            p = raw.strip()
            if not p:
                continue
            if not p.startswith("/"):
                p = "/" + p
            entries.append({
                "path": p,
                "method": "HEAD",
                "category": "custom",
                "purpose": "Operator-supplied read-only endpoint inventory check.",
                "expected_indicators": ["HTTP status", "Server", "Location"],
            })

    seen_paths: Set[str] = set()
    manifest_checks: List[Dict[str, Any]] = []
    for item in entries:
        if item["path"] in seen_paths:
            continue
        seen_paths.add(item["path"])
        manifest_checks.append({
            "url": urllib.parse.urljoin(base, item["path"]),
            "path": item["path"],
            "method": item["method"],
            "category": item["category"],
            "purpose": item["purpose"],
            "expected_indicators": item["expected_indicators"],
        })

    return 0, {
        "ok": True,
        "action": "plan",
        "base_url": base,
        "profile": args.profile,
        "check_count": len(manifest_checks),
        "checks": manifest_checks,
        "stability_guardrails": [
            "Execute read-only HEAD/GET inventory sequentially or with low concurrency (<=2).",
            "Do NOT run blocking full-disk scans (find /, dir /s) on Java/WebLogic hosts.",
            "Register verified persistent access via register_session and archive artifacts in <taskDir>/shared/.",
        ],
    }


def cmd_escape(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        if args.text is not None:
            raw = args.text
        else:
            raw = pathlib.Path(args.file).read_text(encoding="utf-8")
    except OSError as exc:
        return 1, {"ok": False, "error": f"failed to read input: {exc}"}

    invalid_matches = INVALID_XML10_RE.findall(raw)
    cleaned = INVALID_XML10_RE.sub("", raw) if args.strip_invalid_xml_chars else raw

    extra = {'"': "&quot;", "'": "&apos;"} if args.mode == "attr" else {}
    escaped = saxutils.escape(cleaned, entities=extra)

    entity_counts = {
        "&": cleaned.count("&"),
        "<": cleaned.count("<"),
        ">": cleaned.count(">"),
    }
    if args.mode == "attr":
        entity_counts['"'] = cleaned.count('"')
        entity_counts["'"] = cleaned.count("'")

    warnings: List[str] = []
    if invalid_matches and not args.strip_invalid_xml_chars:
        warnings.append(
            f"Found {len(invalid_matches)} illegal XML 1.0 control character(s); pass --strip-invalid-xml-chars to remove them."
        )
    if "]]>" in raw:
        warnings.append("Input contains CDATA terminator ']]>'; escaping converts '>' to '&gt;' safely.")

    return 0, {
        "ok": True,
        "action": "escape",
        "mode": args.mode,
        "input_length": len(raw),
        "escaped_length": len(escaped),
        "invalid_xml_chars_found": len(invalid_matches),
        "invalid_xml_chars_stripped": len(invalid_matches) if args.strip_invalid_xml_chars else 0,
        "entities_replaced": entity_counts,
        "warnings": warnings,
        "escaped": escaped,
    }


def _collect_xml_stats(root: ET.Element) -> Tuple[int, int, List[str]]:
    count = 0
    max_depth = 0
    ns_set: Set[str] = set()

    def walk(elem: ET.Element, depth: int) -> None:
        nonlocal count, max_depth
        count += 1
        if depth > max_depth:
            max_depth = depth
        if elem.tag.startswith("{") and "}" in elem.tag:
            ns_set.add(elem.tag[1 : elem.tag.index("}")])
        for attr_name in elem.attrib:
            if attr_name.startswith("{") and "}" in attr_name:
                ns_set.add(attr_name[1 : attr_name.index("}")])
        for child in elem:
            walk(child, depth + 1)

    walk(root, 1)
    return count, max_depth, sorted(ns_set)


def cmd_validate(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        if args.xml is not None:
            raw = args.xml
        else:
            raw = pathlib.Path(args.file).read_text(encoding="utf-8")
    except OSError as exc:
        return 1, {"ok": False, "error": f"failed to read input: {exc}"}

    dtd_matches = DTD_OR_ENTITY_RE.findall(raw)
    invalid_chars = INVALID_XML10_RE.findall(raw)
    warnings: List[str] = []
    if dtd_matches:
        warnings.append("Document contains DTD/ENTITY declaration; reject or strip DTD blocks before processing.")
    if invalid_chars:
        warnings.append(f"Document contains {len(invalid_chars)} illegal XML 1.0 control character(s).")

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        line, col = exc.position if hasattr(exc, "position") and exc.position else (None, None)
        return 1, {
            "ok": False,
            "action": "validate",
            "well_formed": False,
            "dtd_or_entity_detected": bool(dtd_matches),
            "parse_error": str(exc),
            "line": line,
            "column": col,
            "warnings": warnings,
        }

    elem_count, max_depth, namespaces = _collect_xml_stats(root)
    ns_info = []
    for uri in namespaces:
        host = urllib.parse.urlparse(uri).hostname or ""
        ns_info.append({
            "uri": uri,
            "host": host,
            "is_standard_schema_ns": host.lower() in STANDARD_SCHEMA_HOSTS,
        })

    return 0, {
        "ok": True,
        "action": "validate",
        "well_formed": True,
        "dtd_or_entity_detected": bool(dtd_matches),
        "root_tag": root.tag,
        "element_count": elem_count,
        "max_depth": max_depth,
        "namespaces": ns_info,
        "warnings": warnings,
    }


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deterministic XML entity escaper, well-formedness validator, and read-only WebLogic endpoint inventory planner."
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_plan = sub.add_parser("plan", help="Build a read-only WebLogic endpoint inventory manifest JSON.")
    p_plan.add_argument("--base-url", required=True, help="Target base URL (e.g. https://10.10.1.5:7002).")
    p_plan.add_argument(
        "--profile",
        choices=["minimal", "standard", "extended"],
        default="standard",
        help="Inventory path profile (default: standard).",
    )
    p_plan.add_argument("--custom-paths", default="", help="Optional comma-separated extra paths to include.")

    p_esc = sub.add_parser("escape", help="Deterministically escape XML text or attribute values.")
    src_esc = p_esc.add_mutually_exclusive_group(required=True)
    src_esc.add_argument("--text", help="Inline text to XML-escape.")
    src_esc.add_argument("--file", help="Path to local UTF-8 file to XML-escape.")
    p_esc.add_argument(
        "--mode",
        choices=["text", "attr"],
        default="text",
        help="Escaping context: 'text' (&, <, >) or 'attr' (also escapes \" and ').",
    )
    p_esc.add_argument(
        "--strip-invalid-xml-chars",
        action="store_true",
        help="Remove illegal XML 1.0 control characters before escaping.",
    )

    p_val = sub.add_parser("validate", help="Validate XML well-formedness and inspect namespaces without XXE.")
    src_val = p_val.add_mutually_exclusive_group(required=True)
    src_val.add_argument("--xml", help="Inline XML document string to validate.")
    src_val.add_argument("--file", help="Path to local XML file to validate.")

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    if args.subcommand == "plan":
        rc, payload = cmd_plan(args)
    elif args.subcommand == "escape":
        rc, payload = cmd_escape(args)
    else:
        rc, payload = cmd_validate(args)

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
