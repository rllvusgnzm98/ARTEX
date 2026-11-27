#!/usr/bin/env python3
"""Local <taskDir>/shared/ artifact indexer, manifest builder, and deduplicating structured output parser.

Uses Python 3 standard library only and emits structured JSON.
Strictly operates on local files under operator-provided directories; does not access OS hives or remote hosts.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


# Matches standard colon-delimited account hash export lines: [domain\]user:rid:lm32:nt32:::
COLON_HASH_RE = re.compile(
    r"^(?:(?P<domain>[^:\\/\s]+)\\)?(?P<user>[^:\s]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32})(?::::.*)?$"
)

# Matches simple structured key: value or key=value host inventory metadata lines
HOST_META_KEYS = {
    "host name": "hostname",
    "hostname": "hostname",
    "computername": "hostname",
    "domain": "domain",
    "os name": "os_name",
    "os version": "os_version",
    "logon server": "logon_server",
    "primary dns suffix": "dns_suffix",
}

TEXT_EXTENSIONS = {".txt", ".log", ".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".kv", ".ini", ".conf", ".cfg"}
BINARY_ARTIFACT_EXTS = {".hiv", ".save", ".dmp", ".bin", ".zip", ".tar", ".gz", ".kirbi", ".ccache"}


def normalize_host_token(host: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", host.strip().lower()).strip("_")


def classify_file(path: pathlib.Path) -> str:
    name = path.name.lower()
    ext = path.suffix.lower()
    if name == "manifest.json":
        return "manifest"
    if ext in {".json", ".jsonl", ".ndjson"}:
        return "json"
    if ext in {".csv", ".tsv"}:
        return "tabular"
    if ext in {".ini", ".conf", ".cfg", ".xml", ".yaml", ".yml"}:
        return "config"
    if ext in BINARY_ARTIFACT_EXTS:
        return "binary_artifact"
    if ext in {".txt", ".log", ".kv", ".md"}:
        return "text"
    return "other"


def sha256_file(path: pathlib.Path, chunk_size: int = 65536) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            buf = fh.read(chunk_size)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def is_probably_text(path: pathlib.Path, max_bytes: int) -> bool:
    try:
        st = path.stat()
        if st.st_size > max_bytes:
            return False
        with path.open("rb") as fh:
            sample = fh.read(4096)
        return b"\x00" not in sample
    except OSError:
        return False


def mask_value(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 8:
        return "***"
    return f"{val[:4]}...{val[-4:]}"


def cmd_scan(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    shared_dir = pathlib.Path(args.shared_dir)
    if not shared_dir.exists() or not shared_dir.is_dir():
        return 1, {
            "ok": False,
            "action": "scan",
            "error": f"shared directory does not exist or is not a directory: {shared_dir}",
        }

    max_bytes = args.max_file_mb * 1024 * 1024
    collected_hosts: Dict[str, Dict[str, Any]] = {}
    top_level_files: List[Dict[str, Any]] = []
    by_hash: Dict[str, List[str]] = {}
    total_files = 0
    total_bytes = 0

    for root, dirs, files in os.walk(shared_dir, followlinks=False):
        dirs.sort()
        files.sort()
        root_path = pathlib.Path(root)
        rel_root = root_path.relative_to(shared_dir)
        parts = rel_root.parts

        host_bucket: Optional[str] = None
        if parts and parts[0].lower().startswith("loot_"):
            host_bucket = parts[0][5:]
            if host_bucket not in collected_hosts:
                collected_hosts[host_bucket] = {
                    "host_key": host_bucket,
                    "normalized_key": normalize_host_token(host_bucket),
                    "dir": str((shared_dir / parts[0]).resolve()),
                    "has_manifest": False,
                    "file_count": 0,
                    "total_bytes": 0,
                    "categories": {},
                    "files": [],
                }

        for fname in files:
            fpath = root_path / fname
            if fpath.is_symlink():
                continue
            try:
                st = fpath.stat()
            except OSError:
                continue

            total_files += 1
            total_bytes += st.st_size
            category = classify_file(fpath)
            digest = sha256_file(fpath) if st.st_size <= max_bytes else None
            abs_str = str(fpath.resolve())
            if digest:
                by_hash.setdefault(digest, []).append(abs_str)

            entry = {
                "path": abs_str,
                "relative_path": str(fpath.relative_to(shared_dir)),
                "size_bytes": st.st_size,
                "mtime_utc": datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc).isoformat(),
                "category": category,
                "sha256": digest,
            }

            if host_bucket is not None:
                rec = collected_hosts[host_bucket]
                rec["file_count"] += 1
                rec["total_bytes"] += st.st_size
                rec["categories"][category] = rec["categories"].get(category, 0) + 1
                if fname.lower() == "manifest.json":
                    rec["has_manifest"] = True
                rec["files"].append(entry)
            else:
                top_level_files.append(entry)

    duplicates = [
        {"sha256": digest, "paths": paths}
        for digest, paths in sorted(by_hash.items())
        if len(paths) > 1
    ]

    target_check: Optional[Dict[str, Any]] = None
    if args.target_host:
        norm_target = normalize_host_token(args.target_host)
        matching_hosts = [
            h["dir"]
            for h in collected_hosts.values()
            if h["normalized_key"] == norm_target or norm_target in h["normalized_key"]
        ]
        matching_top = [
            f["path"]
            for f in top_level_files
            if norm_target and norm_target in normalize_host_token(f["relative_path"])
        ]
        already = bool(matching_hosts or matching_top)
        target_check = {
            "target_host": args.target_host,
            "normalized_host": norm_target,
            "target_already_collected": already,
            "matching_loot_dirs": matching_hosts,
            "matching_top_level_files": matching_top,
            "skip_recommendation": (
                "Existing artifacts found in shared/; inspect existing files before re-collecting."
                if already
                else "No existing artifacts found for this host in shared/; safe to proceed with bounded collection."
            ),
        }

    return 0, {
        "ok": True,
        "action": "scan",
        "shared_dir": str(shared_dir.resolve()),
        "total_files": total_files,
        "total_bytes": total_bytes,
        "collected_host_count": len(collected_hosts),
        "collected_hosts": list(collected_hosts.values()),
        "top_level_files": top_level_files,
        "duplicate_files": duplicates,
        "target_check": target_check,
    }


def _record_fingerprint(kind: str, domain: str, account: str, secret: str) -> Tuple[str, str]:
    secret_sha = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    dedup_key = f"{kind}|{domain.lower()}|{account.lower()}|{secret_sha}"
    return dedup_key, secret_sha


def _extract_from_json_obj(obj: Any, source_path: str, records_out: List[Dict[str, Any]], meta_out: Dict[str, Any]) -> None:
    if isinstance(obj, list):
        for item in obj:
            _extract_from_json_obj(item, source_path, records_out, meta_out)
        return
    if not isinstance(obj, dict):
        return

    lower_map = {str(k).lower(): v for k, v in obj.items()}
    account = lower_map.get("username") or lower_map.get("user") or lower_map.get("account")
    secret = (
        lower_map.get("nt_hash")
        or lower_map.get("hash")
        or lower_map.get("secret")
        or lower_map.get("password")
        or lower_map.get("token")
    )
    if isinstance(account, str) and account.strip() and isinstance(secret, str) and secret.strip():
        domain = str(lower_map.get("domain") or "").strip()
        kind = str(lower_map.get("kind") or ("nt_hash" if "nt_hash" in lower_map else "structured_entry"))
        records_out.append({
            "kind": kind,
            "domain": domain,
            "account": account.strip(),
            "secret": secret.strip(),
            "source_file": source_path,
        })
        return

    for k, v in lower_map.items():
        if k in HOST_META_KEYS and isinstance(v, str) and v.strip():
            meta_out.setdefault(HOST_META_KEYS[k], set()).add(v.strip())
        elif isinstance(v, (dict, list)):
            _extract_from_json_obj(v, source_path, records_out, meta_out)


def _parse_single_file(
    fpath: pathlib.Path, raw_records: List[Dict[str, Any]], host_meta: Dict[str, Any]
) -> None:
    source_str = str(fpath.resolve())
    ext = fpath.suffix.lower()
    text = fpath.read_text(encoding="utf-8", errors="replace")

    if ext == ".json":
        try:
            data = json.loads(text)
            _extract_from_json_obj(data, source_str, raw_records, host_meta)
            return
        except json.JSONDecodeError:
            pass

    if ext in {".jsonl", ".ndjson"}:
        parsed_any = False
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                _extract_from_json_obj(obj, source_str, raw_records, host_meta)
                parsed_any = True
            except json.JSONDecodeError:
                continue
        if parsed_any:
            return

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = COLON_HASH_RE.match(stripped)
        if m:
            raw_records.append({
                "kind": "ntlm_hash",
                "domain": (m.group("domain") or "").strip(),
                "account": m.group("user").strip(),
                "rid": int(m.group("rid")),
                "lm_hash": m.group("lm").lower(),
                "secret": m.group("nt").lower(),
                "source_file": source_str,
            })
            continue

        sep = ":" if ":" in stripped else ("=" if "=" in stripped else None)
        if sep:
            k, v = stripped.split(sep, 1)
            norm_k = k.strip().lower()
            val = v.strip()
            if norm_k in HOST_META_KEYS and val:
                host_meta.setdefault(HOST_META_KEYS[norm_k], set()).add(val)


def cmd_parse(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    targets: List[pathlib.Path] = []
    if args.input:
        p = pathlib.Path(args.input)
        if not p.exists():
            return 1, {"ok": False, "action": "parse", "error": f"input path not found: {p}"}
        targets.append(p)
    if args.shared_dir:
        p = pathlib.Path(args.shared_dir)
        if not p.exists():
            return 1, {"ok": False, "action": "parse", "error": f"shared-dir not found: {p}"}
        targets.append(p)
    if not targets:
        return 2, {"ok": False, "action": "parse", "error": "provide --shared-dir and/or --input"}

    max_bytes = args.max_file_mb * 1024 * 1024
    files_to_read: List[pathlib.Path] = []
    for target in targets:
        if target.is_file():
            files_to_read.append(target)
        else:
            for root, dirs, files in os.walk(target, followlinks=False):
                dirs.sort()
                files.sort()
                for fname in files:
                    if fname.lower() == "manifest.json":
                        continue
                    fp = pathlib.Path(root) / fname
                    if not fp.is_symlink():
                        files_to_read.append(fp)

    raw_records: List[Dict[str, Any]] = []
    host_meta_sets: Dict[str, Any] = {}
    scanned = 0
    skipped = 0

    for fp in files_to_read:
        if fp.suffix.lower() in BINARY_ARTIFACT_EXTS or not is_probably_text(fp, max_bytes):
            skipped += 1
            continue
        try:
            _parse_single_file(fp, raw_records, host_meta_sets)
            scanned += 1
        except OSError:
            skipped += 1

    dedup: Dict[str, Dict[str, Any]] = {}
    for rec in raw_records:
        key, secret_sha = _record_fingerprint(rec["kind"], rec.get("domain", ""), rec["account"], rec["secret"])
        if key not in dedup:
            display_secret = mask_value(rec["secret"]) if args.mask_secrets else rec["secret"]
            entry: Dict[str, Any] = {
                "kind": rec["kind"],
                "domain": rec.get("domain", ""),
                "account": rec["account"],
                "secret": display_secret,
                "secret_masked": bool(args.mask_secrets),
                "secret_sha256": secret_sha,
                "occurrences": 1,
                "source_files": [rec["source_file"]],
            }
            if "rid" in rec:
                entry["rid"] = rec["rid"]
            dedup[key] = entry
        else:
            existing = dedup[key]
            existing["occurrences"] += 1
            if rec["source_file"] not in existing["source_files"]:
                existing["source_files"].append(rec["source_file"])

    host_metadata = {k: sorted(v) for k, v in sorted(host_meta_sets.items())}
    records_list = sorted(dedup.values(), key=lambda r: (r["kind"], r["domain"].lower(), r["account"].lower()))

    return 0, {
        "ok": True,
        "action": "parse",
        "files_scanned": scanned,
        "files_skipped": skipped,
        "dedup_summary": {
            "raw_records_found": len(raw_records),
            "unique_records": len(records_list),
            "duplicates_removed": len(raw_records) - len(records_list),
        },
        "host_metadata": host_metadata,
        "records": records_list,
    }


def cmd_manifest(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    loot_dir = pathlib.Path(args.loot_dir)
    if not loot_dir.exists() or not loot_dir.is_dir():
        return 1, {"ok": False, "action": "manifest", "error": f"loot directory not found: {loot_dir}"}

    inferred_host = args.host
    if not inferred_host:
        name = loot_dir.name
        inferred_host = name[5:] if name.lower().startswith("loot_") else name

    files_index: List[Dict[str, Any]] = []
    artifact_paths: List[str] = []
    total_bytes = 0

    for root, dirs, files in os.walk(loot_dir, followlinks=False):
        dirs.sort()
        files.sort()
        for fname in files:
            if fname.lower() == "manifest.json":
                continue
            fp = pathlib.Path(root) / fname
            if fp.is_symlink():
                continue
            try:
                st = fp.stat()
            except OSError:
                continue
            abs_str = str(fp.resolve())
            total_bytes += st.st_size
            files_index.append({
                "relative_path": str(fp.relative_to(loot_dir)),
                "absolute_path": abs_str,
                "size_bytes": st.st_size,
                "sha256": sha256_file(fp),
                "category": classify_file(fp),
                "mtime_utc": datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc).isoformat(),
            })
            artifact_paths.append(abs_str)

    manifest_path = (loot_dir / "manifest.json").resolve()
    manifest_doc: Dict[str, Any] = {
        "host": inferred_host,
        "loot_dir": str(loot_dir.resolve()),
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "file_count": len(files_index),
        "total_bytes": total_bytes,
        "artifact_paths": [str(manifest_path)] + artifact_paths,
        "files": files_index,
    }

    written = False
    if args.write:
        manifest_path.write_text(json.dumps(manifest_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written = True

    return 0, {
        "ok": True,
        "action": "manifest",
        "manifest_path": str(manifest_path),
        "written": written,
        "manifest": manifest_doc,
    }


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local <taskDir>/shared/ artifact indexer, manifest builder, and deduplicating structured output parser."
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_scan = sub.add_parser("scan", help="Index <taskDir>/shared/ to detect existing host artifacts and duplicates.")
    p_scan.add_argument("--shared-dir", required=True, help="Path to <taskDir>/shared/ directory.")
    p_scan.add_argument("--target-host", help="Optional target host/IP to check whether it was already collected.")
    p_scan.add_argument("--max-file-mb", type=int, default=50, help="Max file size in MB to hash during scan (default: 50).")

    p_parse = sub.add_parser("parse", help="Parse and deduplicate local structured text/JSON/hash outputs.")
    p_parse.add_argument("--shared-dir", help="Path to <taskDir>/shared/ directory to parse recursively.")
    p_parse.add_argument("--input", help="Optional single local file or subdirectory to parse.")
    p_parse.add_argument("--mask-secrets", action="store_true", help="Mask secret values in JSON output while preserving SHA256 dedup keys.")
    p_parse.add_argument("--max-file-mb", type=int, default=10, help="Max text file size in MB to parse (default: 10).")

    p_man = sub.add_parser("manifest", help="Build or update manifest.json and ARTEX artifact_paths for a loot_<host> directory.")
    p_man.add_argument("--loot-dir", required=True, help="Path to <taskDir>/shared/loot_<host>/ directory.")
    p_man.add_argument("--host", help="Host label (inferred from loot_<host> folder name if omitted).")
    p_man.add_argument("--write", action="store_true", help="Write manifest.json inside --loot-dir.")

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    if args.subcommand == "scan":
        rc, payload = cmd_scan(args)
    elif args.subcommand == "parse":
        rc, payload = cmd_parse(args)
    else:
        rc, payload = cmd_manifest(args)

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
