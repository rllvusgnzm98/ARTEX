#!/usr/bin/env python3
"""Local port occupancy checker, conflict-free netsh portproxy command generator, and TCP/SOCKS5 reachability verifier.

Uses Python 3 standard library only and emits structured JSON.
"""

import argparse
import datetime
import ipaddress
import json
import socket
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple


SOCKS5_REPLY_MAP: Dict[int, str] = {
    0x00: "succeeded",
    0x01: "general_socks_server_failure",
    0x02: "connection_not_allowed_by_ruleset",
    0x03: "network_unreachable",
    0x04: "host_unreachable",
    0x05: "connection_refused",
    0x06: "ttl_expired",
    0x07: "command_not_supported",
    0x08: "address_type_not_supported",
}


def parse_port_spec(spec: str) -> List[int]:
    ports: List[int] = []
    seen: Set[int] = set()
    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start_p, end_p = int(start_s.strip()), int(end_s.strip())
            if start_p < 1 or end_p > 65535 or start_p > end_p:
                raise ValueError(f"invalid port range: {token}")
            if end_p - start_p > 1024:
                raise ValueError(f"port range too wide (>1024 ports): {token}")
            for p in range(start_p, end_p + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
        else:
            p = int(token)
            if p < 1 or p > 65535:
                raise ValueError(f"port out of range 1..65535: {p}")
            if p not in seen:
                seen.add(p)
                ports.append(p)
    return ports


def check_local_port(host: str, port: int) -> Dict[str, Any]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listening = False
    connect_target = "127.0.0.1" if host == "0.0.0.0" else ("::1" if host == "::" else host)

    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.25)
            if probe.connect_ex((connect_target, port)) == 0:
                listening = True
    except OSError:
        pass

    bindable = False
    bind_error = None
    try:
        with socket.socket(family, socket.SOCK_STREAM) as srv:
            srv.bind((host, port))
            bindable = True
    except OSError as exc:
        bind_error = str(exc)

    return {
        "port": port,
        "available": bindable and not listening,
        "bindable": bindable,
        "listening": listening,
        "bind_error": bind_error,
    }


def cmd_port_check(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        ports = parse_port_spec(args.ports)
    except ValueError as exc:
        return 2, {"ok": False, "error": str(exc)}

    results = [check_local_port(args.host, p) for p in ports]
    occupied = [r["port"] for r in results if not r["available"]]
    available = [r["port"] for r in results if r["available"]]

    suggested: List[int] = []
    if args.find_free > 0:
        cand = args.free_start
        while len(suggested) < args.find_free and cand <= 65535:
            if check_local_port(args.host, cand)["available"]:
                suggested.append(cand)
            cand += 1

    return 0, {
        "ok": True,
        "action": "port-check",
        "host": args.host,
        "results": results,
        "occupied_ports": occupied,
        "available_ports": available,
        "suggested_free_ports": suggested,
    }


def _netsh_mode(listen_addr: str, connect_addr: str) -> str:
    l_ver = ipaddress.ip_address(listen_addr).version
    c_ver = ipaddress.ip_address(connect_addr).version
    return f"v{l_ver}tov{c_ver}"


def cmd_netsh_plan(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    if args.action == "show":
        return 0, {
            "ok": True,
            "action": "netsh-plan",
            "mode": "show",
            "command": "netsh interface portproxy show all",
            "conflicts": [],
        }

    if args.listen_port is None or not (1 <= args.listen_port <= 65535):
        return 2, {"ok": False, "error": "--listen-port (1..65535) is required for add/delete"}

    try:
        ipaddress.ip_address(args.listen_addr)
    except ValueError as exc:
        return 2, {"ok": False, "error": f"invalid --listen-addr: {exc}"}

    used_ports: Set[int] = set()
    if args.used_ports:
        try:
            used_ports = set(parse_port_spec(args.used_ports))
        except ValueError as exc:
            return 2, {"ok": False, "error": f"invalid --used-ports: {exc}"}

    conflicts: List[str] = []
    if args.action == "add":
        if not args.connect_addr or args.connect_port is None or not (1 <= args.connect_port <= 65535):
            return 2, {"ok": False, "error": "--connect-addr and --connect-port (1..65535) are required for add"}
        try:
            ipaddress.ip_address(args.connect_addr)
        except ValueError as exc:
            return 2, {"ok": False, "error": f"invalid --connect-addr: {exc}"}

        if args.listen_port in used_ports:
            conflicts.append(f"listen_port {args.listen_port} is present in --used-ports list")
        if args.check_local:
            status = check_local_port(args.listen_addr, args.listen_port)
            if not status["available"]:
                conflicts.append(
                    f"local port {args.listen_addr}:{args.listen_port} is unavailable ({status['bind_error'] or 'listener active'})"
                )

        proto = _netsh_mode(args.listen_addr, args.connect_addr)
        add_cmd = (
            f"netsh interface portproxy add {proto} "
            f"listenaddress={args.listen_addr} listenport={args.listen_port} "
            f"connectaddress={args.connect_addr} connectport={args.connect_port}"
        )
        del_cmd = (
            f"netsh interface portproxy delete {proto} "
            f"listenaddress={args.listen_addr} listenport={args.listen_port}"
        )
        show_cmd = "netsh interface portproxy show all"

        payload: Dict[str, Any] = {
            "ok": len(conflicts) == 0,
            "action": "netsh-plan",
            "mode": "add",
            "protocol_family": proto,
            "conflicts": conflicts,
            "command": add_cmd,
            "verify_command": show_cmd,
            "teardown_command": del_cmd,
            "tunnels_json_entry": {
                "id": f"portproxy-{args.listen_port}-to-{args.connect_addr}-{args.connect_port}",
                "type": "portproxy",
                "listen": f"{args.listen_addr}:{args.listen_port}",
                "connect": f"{args.connect_addr}:{args.connect_port}",
                "teardown_cmd": del_cmd,
                "planned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            },
            "notes": [
                "Requires elevated Administrator privileges on Windows.",
                "Verify Windows Firewall inbound rule on listenport if remote hops must reach this listener.",
                "Register active tunnel via tunnel_register and record teardown_command in <taskDir>/shared/tunnels.json.",
            ],
        }
        return (0 if len(conflicts) == 0 else 1), payload

    # delete action
    proto = f"v{ipaddress.ip_address(args.listen_addr).version}tov4"
    if args.connect_addr:
        try:
            proto = _netsh_mode(args.listen_addr, args.connect_addr)
        except ValueError as exc:
            return 2, {"ok": False, "error": f"invalid --connect-addr: {exc}"}

    del_cmd = (
        f"netsh interface portproxy delete {proto} "
        f"listenaddress={args.listen_addr} listenport={args.listen_port}"
    )
    return 0, {
        "ok": True,
        "action": "netsh-plan",
        "mode": "delete",
        "protocol_family": proto,
        "command": del_cmd,
        "verify_command": "netsh interface portproxy show all",
        "conflicts": [],
    }


def cmd_verify_tcp(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    if not (1 <= args.port <= 65535):
        return 2, {"ok": False, "error": "--port must be in 1..65535"}
    t0 = time.monotonic()
    resolved_ip: Optional[str] = None
    try:
        infos = socket.getaddrinfo(args.host, args.port, type=socket.SOCK_STREAM)
        resolved_ip = infos[0][4][0] if infos else None
        with socket.create_connection((args.host, args.port), timeout=args.timeout):
            latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
            return 0, {
                "ok": True,
                "action": "verify-tcp",
                "host": args.host,
                "resolved_ip": resolved_ip,
                "port": args.port,
                "reachable": True,
                "latency_ms": latency_ms,
                "error": None,
            }
    except OSError as exc:
        latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
        return 1, {
            "ok": False,
            "action": "verify-tcp",
            "host": args.host,
            "resolved_ip": resolved_ip,
            "port": args.port,
            "reachable": False,
            "latency_ms": latency_ms,
            "error": str(exc),
        }


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("unexpected EOF from SOCKS5 server")
        buf.extend(chunk)
    return bytes(buf)


def cmd_verify_socks5(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    if not (1 <= args.proxy_port <= 65535):
        return 2, {"ok": False, "error": "--proxy-port must be in 1..65535"}
    if args.target_host and (args.target_port is None or not (1 <= args.target_port <= 65535)):
        return 2, {"ok": False, "error": "--target-port (1..65535) is required when --target-host is set"}

    t0 = time.monotonic()
    result: Dict[str, Any] = {
        "ok": False,
        "action": "verify-socks5",
        "proxy": f"{args.proxy_host}:{args.proxy_port}",
        "handshake_ok": False,
        "selected_auth_method": None,
        "target_connect_tested": bool(args.target_host),
        "target_reachable": None,
        "reply_code": None,
        "reply_status": None,
        "latency_ms": None,
        "error": None,
    }

    try:
        with socket.create_connection((args.proxy_host, args.proxy_port), timeout=args.timeout) as sock:
            sock.settimeout(args.timeout)
            # RFC 1928 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
            sock.sendall(b"\x05\x01\x00")
            resp = _recv_exact(sock, 2)
            if resp[0] != 0x05:
                result["error"] = f"non-SOCKS5 version byte: 0x{resp[0]:02x}"
                result["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
                return 1, result

            result["selected_auth_method"] = resp[1]
            if resp[1] == 0xFF:
                result["error"] = "SOCKS5 server rejected no-auth method (0xFF)"
                result["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
                return 1, result

            result["handshake_ok"] = True
            if not args.target_host:
                result["ok"] = True
                result["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
                return 0, result

            # Build RFC 1928 CONNECT request
            addr_bytes: bytes
            atyp: int
            try:
                ip_obj = ipaddress.ip_address(args.target_host)
                if ip_obj.version == 4:
                    atyp = 0x01
                    addr_bytes = ip_obj.packed
                else:
                    atyp = 0x04
                    addr_bytes = ip_obj.packed
            except ValueError:
                host_b = args.target_host.encode("idna")
                if len(host_b) > 255:
                    raise ValueError("target hostname exceeds 255 bytes")
                atyp = 0x03
                addr_bytes = bytes([len(host_b)]) + host_b

            req = struct.pack("!BBBB", 0x05, 0x01, 0x00, atyp) + addr_bytes + struct.pack("!H", args.target_port)
            sock.sendall(req)

            hdr = _recv_exact(sock, 4)
            rep = hdr[1]
            rep_atyp = hdr[3]
            if rep_atyp == 0x01:
                _recv_exact(sock, 4 + 2)
            elif rep_atyp == 0x04:
                _recv_exact(sock, 16 + 2)
            elif rep_atyp == 0x03:
                dlen = _recv_exact(sock, 1)[0]
                _recv_exact(sock, dlen + 2)

            result["reply_code"] = rep
            result["reply_status"] = SOCKS5_REPLY_MAP.get(rep, f"unknown_0x{rep:02x}")
            result["target_reachable"] = rep == 0x00
            result["ok"] = rep == 0x00
            result["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
            return (0 if rep == 0x00 else 1), result
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
        result["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        return 1, result


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local port occupancy checker, conflict-free netsh portproxy planner, and TCP/SOCKS5 reachability verifier."
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_port = sub.add_parser("port-check", help="Check local TCP port availability and suggest conflict-free ports.")
    p_port.add_argument("--host", default="127.0.0.1", help="Local bind address to check (default: 127.0.0.1).")
    p_port.add_argument("--ports", default="1080,1081,8080,8443,9050", help="Comma-separated ports or start-end ranges.")
    p_port.add_argument("--find-free", type=int, default=0, help="Number of conflict-free ports to suggest.")
    p_port.add_argument("--free-start", type=int, default=10800, help="Starting port for --find-free search (default: 10800).")

    p_netsh = sub.add_parser("netsh-plan", help="Generate conflict-free Windows netsh interface portproxy commands.")
    p_netsh.add_argument("--action", choices=["add", "show", "delete"], default="add", help="Portproxy action (default: add).")
    p_netsh.add_argument("--listen-addr", default="0.0.0.0", help="Listen IPv4/IPv6 address (default: 0.0.0.0).")
    p_netsh.add_argument("--listen-port", type=int, help="Listen TCP port (1..65535).")
    p_netsh.add_argument("--connect-addr", help="Target IPv4/IPv6 address (required for add).")
    p_netsh.add_argument("--connect-port", type=int, help="Target TCP port (required for add).")
    p_netsh.add_argument("--check-local", action="store_true", help="Also verify listen port is free on this local host.")
    p_netsh.add_argument("--used-ports", default="", help="Comma-separated known occupied ports from target netstat output.")

    p_tcp = sub.add_parser("verify-tcp", help="Verify read-only TCP reachability and latency.")
    p_tcp.add_argument("--host", required=True, help="Destination host or IP.")
    p_tcp.add_argument("--port", type=int, required=True, help="Destination TCP port.")
    p_tcp.add_argument("--timeout", type=float, default=3.0, help="Connect timeout in seconds (default: 3.0).")

    p_s5 = sub.add_parser("verify-socks5", help="Verify SOCKS5 proxy handshake and optional end-to-end CONNECT reachability.")
    p_s5.add_argument("--proxy-host", default="127.0.0.1", help="SOCKS5 proxy host (default: 127.0.0.1).")
    p_s5.add_argument("--proxy-port", type=int, default=1080, help="SOCKS5 proxy port (default: 1080).")
    p_s5.add_argument("--target-host", help="Optional target host/IP to test via SOCKS5 CONNECT.")
    p_s5.add_argument("--target-port", type=int, help="Optional target port when --target-host is set.")
    p_s5.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds (default: 5.0).")

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    if args.subcommand == "port-check":
        rc, payload = cmd_port_check(args)
    elif args.subcommand == "netsh-plan":
        rc, payload = cmd_netsh_plan(args)
    elif args.subcommand == "verify-tcp":
        rc, payload = cmd_verify_tcp(args)
    else:
        rc, payload = cmd_verify_socks5(args)

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
