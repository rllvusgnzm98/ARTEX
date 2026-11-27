#!/usr/bin/env python3
"""Cross-OS PowerShell command validator, UTF-16LE -EncodedCommand encoder, and chunked transfer planner.

Uses Python 3 standard library only and emits structured JSON.
"""

import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Tuple


V3_PLUS_PATTERNS: List[Tuple[str, str]] = [
    (r"\bInvoke-WebRequest\b|\biwr\b", "Invoke-WebRequest/iwr requires PowerShell v3+"),
    (r"\bInvoke-RestMethod\b|\birm\b", "Invoke-RestMethod/irm requires PowerShell v3+"),
    (r"\bConvertFrom-Json\b|\bConvertTo-Json\b", "ConvertFrom-Json/ConvertTo-Json require PowerShell v3+"),
    (r"\$PSScriptRoot\b|\$PSCommandPath\b", "$PSScriptRoot/$PSCommandPath require PowerShell v3+"),
    (r"\bGet-Content\b[^\n\r;]*\s-Raw\b", "Get-Content -Raw requires PowerShell v3+"),
    (r"\$using:", "$using: scope modifier requires PowerShell v3+"),
    (r"\bGet-CimInstance\b", "Get-CimInstance requires PowerShell v3+ (use Get-WmiObject on v2)"),
    (r"\[ordered\]", "[ordered] hashtable literal requires PowerShell v3+"),
    (r"\bUnblock-File\b", "Unblock-File requires PowerShell v3+"),
]

V4_PLUS_PATTERNS: List[Tuple[str, str]] = [
    (r"\bGet-FileHash\b", "Get-FileHash requires PowerShell v4+ (use [System.Security.Cryptography.SHA256]::Create() on v2/v3)"),
    (r"\.Where\s*\(|\.ForEach\s*\(", "Collection .Where()/.ForEach() methods require PowerShell v4+"),
]

V5_PLUS_PATTERNS: List[Tuple[str, str]] = [
    (r"\bCompress-Archive\b|\bExpand-Archive\b", "Compress-Archive/Expand-Archive require PowerShell v5+"),
    (r"(?m)^\s*class\s+[A-Za-z_][A-Za-z0-9_]*", "PowerShell class definitions require PowerShell v5+"),
]

V7_PLUS_PATTERNS: List[Tuple[str, str]] = [
    (r"\bForEach-Object\b[^\n\r;]*\s-Parallel\b", "ForEach-Object -Parallel requires PowerShell v7+"),
    (r"\?\?=?|\&\&|\|\|", "Null-coalescing (??) and pipeline chain operators (&&/||) require PowerShell v7+"),
]


def check_ps_compatibility(text: str, ps_version: int) -> List[Dict[str, str]]:
    warnings: List[Dict[str, str]] = []
    checks: List[Tuple[int, List[Tuple[str, str]]]] = [
        (3, V3_PLUS_PATTERNS),
        (4, V4_PLUS_PATTERNS),
        (5, V5_PLUS_PATTERNS),
        (7, V7_PLUS_PATTERNS),
    ]
    for min_ver, patterns in checks:
        if ps_version < min_ver:
            for pattern, message in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    warnings.append({
                        "code": f"ps_v{min_ver}_feature",
                        "severity": "warning",
                        "message": message,
                    })

    if ps_version <= 2 and re.search(r"(?:^|\s)-File(?:\s|$)", text, re.IGNORECASE):
        warnings.append({
            "code": "ps_v2_file_flag",
            "severity": "warning",
            "message": "PowerShell v2 -File handling has quoting/argument splitting quirks; verify quoting or use -EncodedCommand / explicit script path.",
        })
    return warnings


def detect_bash_quoting_hazards(text: str) -> List[Dict[str, str]]:
    hazards: List[Dict[str, str]] = []
    rules = [
        (r"\$[A-Za-z__{?]", "dollar_expansion", "Contains '$' variable/token that Bash double quotes would expand before reaching PowerShell."),
        (r"\$\(", "command_substitution", "Contains '$()' subexpression that Bash double quotes would evaluate locally."),
        (r"`", "backtick_hazard", "Contains backtick ('`'): Bash double quotes execute it as command substitution, while PowerShell uses it as escape character."),
        (r"!", "history_expansion", "Contains '!' which interactive Bash double quotes may expand via history substitution."),
        (r'"', "double_quote_nesting", "Contains double quotes that conflict with outer Bash/cmd double-quoted strings."),
    ]
    for pattern, code, detail in rules:
        if re.search(pattern, text):
            hazards.append({"code": code, "detail": detail})
    return hazards


def build_chunked_plan(raw_bytes: bytes, chunk_size: int, target_path: str, ps_version: int) -> Dict[str, Any]:
    full_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    b64_payload = base64.b64encode(raw_bytes).decode("ascii")
    chunks: List[Dict[str, Any]] = []
    total_chunks = (len(b64_payload) + chunk_size - 1) // chunk_size if b64_payload else 1
    for idx in range(total_chunks):
        part = b64_payload[idx * chunk_size : (idx + 1) * chunk_size]
        chunks.append({
            "index": idx + 1,
            "total": total_chunks,
            "length": len(part),
            "sha256": hashlib.sha256(part.encode("ascii")).hexdigest(),
            "data": part,
        })

    escaped_path = target_path.replace("'", "''")
    verify_v2 = (
        f"$sha=[System.Security.Cryptography.SHA256]::Create();"
        f"$b=[System.IO.File]::ReadAllBytes('{escaped_path}');"
        f"([System.BitConverter]::ToString($sha.ComputeHash($b)) -replace '-','').ToLower()"
    )
    verify_v4 = f"(Get-FileHash -Algorithm SHA256 -Path '{escaped_path}').Hash.ToLower()"

    return {
        "target_path": target_path,
        "raw_byte_length": len(raw_bytes),
        "base64_total_length": len(b64_payload),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "expected_sha256": full_sha256,
        "verify_sha256_cmd": verify_v2 if ps_version < 4 else verify_v4,
        "verify_sha256_ps_v2": verify_v2,
        "verify_sha256_ps_v4_plus": verify_v4,
        "chunks": chunks,
    }


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate PowerShell compatibility, encode UTF-16LE -EncodedCommand strings, or generate SHA256-verified chunked transfer plans."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--command", help="Inline PowerShell command text to validate and encode.")
    src.add_argument("--file", help="Path to a local script file to validate and encode.")
    src.add_argument("--stdin", action="store_true", help="Read PowerShell script content from stdin.")

    parser.add_argument(
        "--ps-version",
        type=int,
        choices=[2, 3, 5, 7],
        default=5,
        help="Target PowerShell major version for compatibility warnings (default: 5).",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "encoded", "chunked"],
        default="auto",
        help="Output mode: 'encoded' (-EncodedCommand), 'chunked' (base64 file plan), or 'auto' (default).",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=2048,
        help="Base64 character length per chunk in chunked mode (default: 2048).",
    )
    parser.add_argument(
        "--max-cli-len",
        type=int,
        default=8000,
        help="Safe command-line length ceiling before warning/switching to chunked mode (default: 8000).",
    )
    parser.add_argument(
        "--target-path",
        default=r"C:\Windows\Temp\work_script.ps1",
        help=r"Target Windows file path recorded in chunked plan metadata (default: C:\Windows\Temp\work_script.ps1).",
    )
    parser.add_argument(
        "--verify-roundtrip",
        action="store_true",
        help="Verify lossless UTF-16LE Base64 decode roundtrip.",
    )
    parser.add_argument(
        "--include-all",
        action="store_true",
        help="Include both encoded and chunked sections in JSON output regardless of selected mode.",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    if args.chunk_size < 64:
        print(json.dumps({"ok": False, "error": "--chunk-size must be >= 64"}, indent=2))
        return 2
    if args.max_cli_len < 256:
        print(json.dumps({"ok": False, "error": "--max-cli-len must be >= 256"}, indent=2))
        return 2

    source_kind = "command"
    source_path = None
    try:
        if args.command is not None:
            text = args.command
            raw_bytes = text.encode("utf-8")
        elif args.file is not None:
            source_kind = "file"
            p = pathlib.Path(args.file)
            raw_bytes = p.read_bytes()
            text = raw_bytes.decode("utf-8", errors="replace")
            source_path = str(p.resolve())
        else:
            source_kind = "stdin"
            text = sys.stdin.read()
            raw_bytes = text.encode("utf-8")
    except OSError as exc:
        print(json.dumps({"ok": False, "error": f"failed to read input: {exc}"}, indent=2))
        return 1

    lines = text.splitlines()
    non_empty_lines = [ln for ln in lines if ln.strip()]

    warnings = check_ps_compatibility(text, args.ps_version)
    bash_hazards = detect_bash_quoting_hazards(text)

    utf16_bytes = text.encode("utf-16-le")
    b64_utf16 = base64.b64encode(utf16_bytes).decode("ascii")
    ps_cli = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {b64_utf16}"
    bash_safe_cli = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand '{b64_utf16}'"
    cli_exceeds_limit = len(ps_cli) > args.max_cli_len

    if cli_exceeds_limit:
        warnings.append({
            "code": "cli_length_exceeded",
            "severity": "warning",
            "message": f"Encoded command length ({len(ps_cli)}) exceeds --max-cli-len ({args.max_cli_len}); use chunked file transfer.",
        })

    if args.mode == "auto":
        if len(non_empty_lines) > 2 or cli_exceeds_limit:
            selected_mode = "chunked"
            selection_reason = (
                "script exceeds 2 non-empty lines or safe CLI length limit; chunked transfer with SHA256 verification recommended"
            )
        else:
            selected_mode = "encoded"
            selection_reason = "short script (<=2 non-empty lines) within safe CLI length limit; UTF-16LE -EncodedCommand is optimal"
    else:
        selected_mode = args.mode
        selection_reason = f"explicitly requested --mode {args.mode}"

    roundtrip_ok = None
    if args.verify_roundtrip:
        decoded = base64.b64decode(b64_utf16.encode("ascii")).decode("utf-16-le")
        roundtrip_ok = decoded == text

    result: Dict[str, Any] = {
        "ok": True,
        "source_kind": source_kind,
        "source_path": source_path,
        "ps_version": args.ps_version,
        "selected_mode": selected_mode,
        "selection_reason": selection_reason,
        "input_stats": {
            "char_length": len(text),
            "utf8_byte_length": len(raw_bytes),
            "utf16le_byte_length": len(utf16_bytes),
            "total_lines": len(lines),
            "non_empty_lines": len(non_empty_lines),
            "sha256_utf8": hashlib.sha256(raw_bytes).hexdigest(),
        },
        "warnings": warnings,
        "bash_quoting_hazards": bash_hazards,
        "encoded_diagnostics": {
            "base64_length": len(b64_utf16),
            "cli_length": len(ps_cli),
            "max_cli_len": args.max_cli_len,
            "exceeds_cli_limit": cli_exceeds_limit,
            "roundtrip_verified": roundtrip_ok,
        },
    }

    if selected_mode == "encoded" or args.include_all:
        result["encoded"] = {
            "encoding": "utf-16-le",
            "base64": b64_utf16,
            "powershell_cli": ps_cli,
            "bash_safe_cli": bash_safe_cli,
        }

    if selected_mode == "chunked" or args.include_all:
        result["chunked_plan"] = build_chunked_plan(
            raw_bytes=raw_bytes,
            chunk_size=args.chunk_size,
            target_path=args.target_path,
            ps_version=args.ps_version,
        )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
