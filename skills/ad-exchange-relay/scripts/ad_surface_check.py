#!/usr/bin/env python3
"""Read-only AD/Exchange TCP banner, TLS certificate, HTTP header, and SMBv2 signing posture inspector.

Supports optional SOCKS5 proxy via Python 3 standard library sockets only.
Emits structured JSON assessment manifests.
"""

import argparse
import datetime
import email.utils
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple


EXCHANGE_INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "x-owa-version",
    "x-feserver",
    "x-beserver",
    "x-aspnet-version",
    "x-cafeserver",
    "www-authenticate",
    "location",
    "date",
    "strict-transport-security",
)

SMB2_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

FILETIME_EPOCH_DIFF_100NS = 116444736000000000


def parse_ports(spec: str) -> List[int]:
    ports: List[int] = []
    seen: Set[int] = set()
    for part in spec.split(","):
        s = part.strip()
        if not s:
            continue
        p = int(s)
        if not (1 <= p <= 65535):
            raise ValueError(f"port out of range 1..65535: {p}")
        if p not in seen:
            seen.add(p)
            ports.append(p)
    return ports


def parse_socks5(spec: Optional[str]) -> Optional[Tuple[str, int]]:
    if not spec:
        return None
    if ":" not in spec:
        raise ValueError("--socks5 must be formatted as host:port")
    host, port_s = spec.rsplit(":", 1)
    host = host.strip("[] ")
    port = int(port_s)
    if not host or not (1 <= port <= 65535):
        raise ValueError(f"invalid --socks5 endpoint: {spec}")
    return host, port


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        buf.extend(chunk)
    return bytes(buf)


def open_tcp(
    host: str,
    port: int,
    timeout: float,
    socks5: Optional[Tuple[str, int]] = None,
) -> socket.socket:
    if socks5 is None:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock

    proxy_host, proxy_port = socks5
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2)
        if greeting != b"\x05\x00":
            raise ConnectionError(f"SOCKS5 auth negotiation failed: {greeting!r}")

        try:
            ip_obj = ipaddress.ip_address(host)
            atyp = 0x01 if ip_obj.version == 4 else 0x04
            addr_bytes = ip_obj.packed
        except ValueError:
            host_b = host.encode("idna")
            if len(host_b) > 255:
                raise ValueError("hostname exceeds 255 bytes")
            atyp = 0x03
            addr_bytes = bytes([len(host_b)]) + host_b

        req = struct.pack("!BBBB", 0x05, 0x01, 0x00, atyp) + addr_bytes + struct.pack("!H", port)
        sock.sendall(req)

        hdr = _recv_exact(sock, 4)
        if hdr[0] != 0x05 or hdr[1] != 0x00:
            raise ConnectionError(f"SOCKS5 CONNECT failed with reply code 0x{hdr[1]:02x}")
        rep_atyp = hdr[3]
        if rep_atyp == 0x01:
            _recv_exact(sock, 6)
        elif rep_atyp == 0x04:
            _recv_exact(sock, 18)
        elif rep_atyp == 0x03:
            dlen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, dlen + 2)
        return sock
    except Exception:
        sock.close()
        raise


def inspect_tcp_banner(
    host: str, port: int, timeout: float, socks5: Optional[Tuple[str, int]]
) -> Dict[str, Any]:
    t0 = time.monotonic()
    try:
        with open_tcp(host, port, timeout, socks5) as sock:
            latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
            banner_preview: Optional[str] = None
            sock.settimeout(min(0.4, timeout))
            try:
                raw = sock.recv(256)
                if raw:
                    banner_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in raw).strip()
            except OSError:
                pass
            return {
                "port": port,
                "reachable": True,
                "latency_ms": latency_ms,
                "banner_preview": banner_preview,
                "error": None,
            }
    except OSError as exc:
        return {
            "port": port,
            "reachable": False,
            "latency_ms": round((time.monotonic() - t0) * 1000.0, 2),
            "banner_preview": None,
            "error": str(exc),
        }


def _decode_der_cert(der_bytes: bytes) -> Dict[str, Any]:
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return {}
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="ascii") as tf:
            tf.write(pem)
            tmp_path = tf.name
        parsed = decoder(tmp_path)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _flatten_x509_name(tuples: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(tuples, (list, tuple)):
        return out
    for rdn in tuples:
        if not isinstance(rdn, (list, tuple)):
            continue
        for pair in rdn:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                out[str(pair[0])] = str(pair[1])
    return out


def inspect_tls(
    host: str, port: int, sni: str, timeout: float, socks5: Optional[Tuple[str, int]]
) -> Dict[str, Any]:
    verified = False
    verify_error: Optional[str] = None
    cert_dict: Dict[str, Any] = {}
    der_bytes: Optional[bytes] = None
    tls_version: Optional[str] = None
    cipher: Optional[Tuple[Any, ...]] = None

    # Attempt verified handshake first
    try:
        ctx = ssl.create_default_context()
        with open_tcp(host, port, timeout, socks5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                verified = True
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()
                cert_dict = tls_sock.getpeercert(binary_form=False) or {}
                der_bytes = tls_sock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        verify_error = str(exc)
    except OSError as exc:
        return {
            "port": port,
            "tls_ok": False,
            "verified": False,
            "error": str(exc),
        }

    # Fall back to read-only unverified inspection for internal AD CA / self-signed certs
    if not verified:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with open_tcp(host, port, timeout, socks5) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                    tls_version = tls_sock.version()
                    cipher = tls_sock.cipher()
                    der_bytes = tls_sock.getpeercert(binary_form=True)
            if der_bytes:
                cert_dict = _decode_der_cert(der_bytes)
        except OSError as exc:
            return {
                "port": port,
                "tls_ok": False,
                "verified": False,
                "verify_error": verify_error,
                "error": str(exc),
            }

    sans = [
        f"{k}:{v}"
        for (k, v) in cert_dict.get("subjectAltName", ())
        if isinstance(k, str) and isinstance(v, str)
    ]
    return {
        "port": port,
        "tls_ok": True,
        "sni": sni,
        "verified": verified,
        "verify_error": verify_error,
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
        "sha256_fingerprint": hashlib.sha256(der_bytes).hexdigest() if der_bytes else None,
        "subject": _flatten_x509_name(cert_dict.get("subject")),
        "issuer": _flatten_x509_name(cert_dict.get("issuer")),
        "san": sans,
        "not_before": cert_dict.get("notBefore"),
        "not_after": cert_dict.get("notAfter"),
    }


def _http_once(
    host: str,
    port: int,
    use_tls: bool,
    sni: str,
    method: str,
    path: str,
    timeout: float,
    socks5: Optional[Tuple[str, int]],
) -> Dict[str, Any]:
    req_lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {sni}",
        "User-Agent: artex-ad-surface-check/1.0",
        "Accept: */*",
        "Connection: close",
        "",
        "",
    ]
    req_bytes = "\r\n".join(req_lines).encode("ascii", errors="replace")

    with open_tcp(host, port, timeout, socks5) as raw_sock:
        conn: socket.socket = raw_sock
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(raw_sock, server_hostname=sni)
        try:
            conn.sendall(req_bytes)
            chunks: List[bytes] = []
            total = 0
            while total < 8192:
                data = conn.recv(min(2048, 8192 - total))
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
        finally:
            if conn is not raw_sock:
                conn.close()

    raw_resp = b"".join(chunks)
    header_part = raw_resp.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    lines = header_part.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        raise ConnectionError("invalid HTTP response")

    parts = lines[0].split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) >= 3 else ""

    headers_multi: Dict[str, List[str]] = {}
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers_multi.setdefault(k.strip().lower(), []).append(v.strip())

    selected: Dict[str, Any] = {}
    for h in EXCHANGE_INTERESTING_HEADERS:
        if h in headers_multi:
            vals = headers_multi[h]
            selected[h] = vals if len(vals) > 1 else vals[0]

    auth_schemes: List[str] = []
    for raw_auth in headers_multi.get("www-authenticate", []):
        for piece in raw_auth.split(","):
            tok = piece.strip().split(" ", 1)[0].strip()
            if tok and tok not in auth_schemes:
                auth_schemes.append(tok)

    clock_skew_seconds: Optional[float] = None
    date_vals = headers_multi.get("date")
    if date_vals:
        try:
            remote_dt = email.utils.parsedate_to_datetime(date_vals[0])
            if remote_dt.tzinfo is None:
                remote_dt = remote_dt.replace(tzinfo=datetime.timezone.utc)
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            clock_skew_seconds = round((remote_dt - now_utc).total_seconds(), 2)
        except Exception:
            pass

    return {
        "scheme": "https" if use_tls else "http",
        "port": port,
        "path": path,
        "method": method,
        "status_code": status_code,
        "reason": reason,
        "headers": selected,
        "auth_schemes": auth_schemes,
        "clock_skew_seconds": clock_skew_seconds,
        "error": None,
    }


def inspect_http(
    host: str,
    port: int,
    use_tls: bool,
    sni: str,
    paths: List[str],
    timeout: float,
    socks5: Optional[Tuple[str, int]],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for p in paths:
        norm_p = p if p.startswith("/") else "/" + p
        try:
            res = _http_once(host, port, use_tls, sni, "HEAD", norm_p, timeout, socks5)
            if res["status_code"] == 405:
                res = _http_once(host, port, use_tls, sni, "GET", norm_p, timeout, socks5)
            results.append(res)
        except OSError as exc:
            results.append({
                "scheme": "https" if use_tls else "http",
                "port": port,
                "path": norm_p,
                "method": "HEAD",
                "status_code": None,
                "reason": None,
                "headers": {},
                "auth_schemes": [],
                "clock_skew_seconds": None,
                "error": str(exc),
            })
    return results


def inspect_smb2_signing(
    host: str, port: int, timeout: float, socks5: Optional[Tuple[str, int]]
) -> Dict[str, Any]:
    """Send a standard unauthenticated SMBv2 Negotiate request to read SecurityMode and SystemTime."""
    # SMB2 Header (64 bytes)
    smb2_header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",  # ProtocolId
        64,          # StructureSize
        0,           # CreditCharge
        0,           # Status
        0,           # Command: NEGOTIATE
        1,           # CreditRequest
        0,           # Flags
        0,           # NextCommand
        0,           # MessageId
        0,           # Reserved
        0,           # TreeId
        0,           # SessionId
        b"\x00" * 16,  # Signature
    )
    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    # SMB2 NEGOTIATE Request Body (36 bytes) + dialects
    neg_body = struct.pack(
        "<HHHHI16sQ",
        36,            # StructureSize
        len(dialects), # DialectCount
        0x0001,        # SecurityMode: Signing Enabled
        0,             # Reserved
        0,             # Capabilities
        b"\x00" * 16,  # ClientGuid
        0,             # ClientStartTime
    ) + struct.pack(f"<{len(dialects)}H", *dialects)

    smb_msg = smb2_header + neg_body
    nbss = struct.pack("!I", len(smb_msg))  # 0x00 + 3-byte length (len < 65535)

    try:
        with open_tcp(host, port, timeout, socks5) as sock:
            sock.sendall(nbss + smb_msg)
            nbss_hdr = _recv_exact(sock, 4)
            msg_len = struct.unpack("!I", nbss_hdr)[0] & 0x00FFFFFF
            if msg_len < 112 or msg_len > 65536:
                return {
                    "port": port,
                    "smb2_ok": False,
                    "error": f"unexpected SMB2 negotiate response length: {msg_len}",
                }
            resp = _recv_exact(sock, msg_len)
            if resp[0:4] != b"\xfeSMB":
                return {
                    "port": port,
                    "smb2_ok": False,
                    "error": "server did not return an SMB2 response signature",
                }
            security_mode, dialect = struct.unpack_from("<HH", resp, 66)
            system_time_ft = struct.unpack_from("<Q", resp, 104)[0]

            server_time_utc: Optional[str] = None
            clock_skew_seconds: Optional[float] = None
            if system_time_ft > FILETIME_EPOCH_DIFF_100NS:
                unix_ts = (system_time_ft - FILETIME_EPOCH_DIFF_100NS) / 10_000_000.0
                remote_dt = datetime.datetime.fromtimestamp(unix_ts, tz=datetime.timezone.utc)
                server_time_utc = remote_dt.isoformat()
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                clock_skew_seconds = round((remote_dt - now_utc).total_seconds(), 2)

            return {
                "port": port,
                "smb2_ok": True,
                "dialect_hex": f"0x{dialect:04x}",
                "dialect_name": SMB2_DIALECT_NAMES.get(dialect, f"0x{dialect:04x}"),
                "security_mode_hex": f"0x{security_mode:04x}",
                "signing_enabled": bool(security_mode & 0x01),
                "signing_required": bool(security_mode & 0x02),
                "server_time_utc": server_time_utc,
                "clock_skew_seconds": clock_skew_seconds,
                "error": None,
            }
    except OSError as exc:
        return {
            "port": port,
            "smb2_ok": False,
            "error": str(exc),
        }


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only AD/Exchange TCP banner, TLS certificate, HTTP header, and SMBv2 signing posture inspector."
    )
    parser.add_argument("--host", required=True, help="Target IP or FQDN to inspect.")
    parser.add_argument(
        "--ports",
        default="80,88,389,443,445,636",
        help="Comma-separated TCP ports to check (default: 80,88,389,443,445,636).",
    )
    parser.add_argument(
        "--tls-ports",
        default="443,636,3269,5986,8443",
        help="Comma-separated ports to inspect with TLS (when reachable and present in --ports).",
    )
    parser.add_argument(
        "--http-ports",
        default="80,443,8080,8443",
        help="Comma-separated ports to inspect with read-only HTTP HEAD/GET (when reachable and present in --ports).",
    )
    parser.add_argument(
        "--http-paths",
        default="/,/owa/auth/logon.aspx,/ecp/",
        help="Comma-separated HTTP paths for read-only header inspection.",
    )
    parser.add_argument("--sni", help="Optional TLS SNI / HTTP Host header override (defaults to --host).")
    parser.add_argument("--socks5", help="Optional SOCKS5 proxy formatted as host:port (stdlib socket).")
    parser.add_argument("--timeout", type=float, default=4.0, help="Per-check socket timeout in seconds (default: 4.0).")
    parser.add_argument("--no-smb-signing", action="store_true", help="Skip read-only SMBv2 Negotiate check on port 445.")
    parser.add_argument("--dry-run", action="store_true", help="Output planned read-only checks as JSON without opening sockets.")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        tls_ports = set(parse_ports(args.tls_ports))
        http_ports = set(parse_ports(args.http_ports))
        socks5 = parse_socks5(args.socks5)
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2

    sni = args.sni or args.host
    http_paths = [p.strip() for p in args.http_paths.split(",") if p.strip()]

    if args.dry_run:
        plan = {
            "ok": True,
            "dry_run": True,
            "host": args.host,
            "sni": sni,
            "socks5": args.socks5,
            "ports": ports,
            "planned_tls_ports": [p for p in ports if p in tls_ports],
            "planned_http_ports": [p for p in ports if p in http_ports],
            "http_paths": http_paths,
            "planned_smb2_signing_check": (445 in ports and not args.no_smb_signing),
            "read_only": True,
        }
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        return 0

    tcp_results: List[Dict[str, Any]] = []
    reachable_set: Set[int] = set()
    for p in ports:
        res = inspect_tcp_banner(args.host, p, args.timeout, socks5)
        tcp_results.append(res)
        if res["reachable"]:
            reachable_set.add(p)

    tls_results: List[Dict[str, Any]] = []
    for p in ports:
        if p in reachable_set and p in tls_ports:
            tls_results.append(inspect_tls(args.host, p, sni, args.timeout, socks5))

    http_results: List[Dict[str, Any]] = []
    for p in ports:
        if p in reachable_set and p in http_ports:
            http_results.extend(
                inspect_http(args.host, p, p in tls_ports, sni, http_paths, args.timeout, socks5)
            )

    smb_result: Optional[Dict[str, Any]] = None
    if 445 in reachable_set and not args.no_smb_signing:
        smb_result = inspect_smb2_signing(args.host, 445, args.timeout, socks5)

    skews: List[float] = []
    exchange_headers_found: List[str] = []
    for item in http_results:
        if item.get("clock_skew_seconds") is not None:
            skews.append(float(item["clock_skew_seconds"]))
        hdrs = item.get("headers", {})
        for key in ("x-owa-version", "x-feserver", "x-beserver", "x-cafeserver"):
            if key in hdrs and key not in exchange_headers_found:
                exchange_headers_found.append(key)

    if smb_result and smb_result.get("clock_skew_seconds") is not None:
        skews.append(float(smb_result["clock_skew_seconds"]))

    max_abs_skew = max((abs(s) for s in skews), default=None)

    summary = {
        "reachable_ports": sorted(reachable_set),
        "kerberos_88_reachable": 88 in reachable_set,
        "ldap_389_reachable": 389 in reachable_set,
        "ldaps_636_reachable": 636 in reachable_set,
        "smb_445_reachable": 445 in reachable_set,
        "smb_signing_enabled": smb_result.get("signing_enabled") if smb_result and smb_result.get("smb2_ok") else None,
        "smb_signing_required": smb_result.get("signing_required") if smb_result and smb_result.get("smb2_ok") else None,
        "exchange_headers_found": exchange_headers_found,
        "max_abs_clock_skew_seconds": max_abs_skew,
        "kerberos_clock_skew_warning": (max_abs_skew is not None and max_abs_skew > 240.0),
    }

    manifest = {
        "ok": True,
        "inspected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": args.host,
        "sni": sni,
        "socks5": args.socks5,
        "summary": summary,
        "tcp": tcp_results,
        "tls": tls_results,
        "http": http_results,
        "smb_signing": smb_result,
    }
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
