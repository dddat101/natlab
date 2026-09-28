#!/usr/bin/env python3
"""
Carrier Gateway DUT - Maximum Concurrent Sessions Test Tool
Stresses the NAT Gateway by establishing large numbers of concurrent flows (e.g., 4096, 8192, 16384, 32768).
Supports both:
  - Bidirectional (default): Server responds with ACK, marking sessions [ASSURED] in router conntrack.
  - Oneway: Unidirectional fire-and-forget traffic for raw CPS benchmarking.
"""

import sys
import os
import socket
import select
import time
import argparse
import json

def set_high_rlimit():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(65536, hard) if hard > 65536 else hard
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass

def run_server(args):
    set_high_rlimit()
    print(f"[Conntrack Server] Listening on {args.bind_ip}:{args.port} (Bidirectional: {args.bidirectional})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
    except Exception:
        pass
    sock.bind((args.bind_ip, args.port))
    sock.settimeout(args.timeout)

    unique_sessions = set()
    total_packets = 0
    replies_sent = 0
    start_time = time.time()

    print(f"[Conntrack Server] Monitoring active sessions for {args.duration}s (Target: {args.min_sessions})...")
    while (time.time() - start_time) < args.duration:
        try:
            data, addr = sock.recvfrom(2048)
            total_packets += 1
            if addr not in unique_sessions:
                unique_sessions.add(addr)
            if args.bidirectional:
                sock.sendto(b"ACK", addr)
                replies_sent += 1
        except socket.timeout:
            pass

    sock.close()

    status = "PASS" if len(unique_sessions) >= args.min_sessions else "FAIL"
    result = {
        "status": status,
        "direction": "bidirectional" if args.bidirectional else "oneway",
        "unique_sessions_detected": len(unique_sessions),
        "target_min_sessions": args.min_sessions,
        "total_packets_received": total_packets,
        "replies_sent": replies_sent
    }

    print(f"[Conntrack Server] Summary: Detected {len(unique_sessions)} unique concurrent translated sessions.")
    if args.bidirectional:
        print(f"[Conntrack Server] Sent {replies_sent} return ACK packets (triggering ASSURED conntrack state on DUT).")
    if len(unique_sessions) >= args.min_sessions:
        print(f"[Conntrack Server] SUCCESS: Sessions ({len(unique_sessions)}) >= target ({args.min_sessions}) [PASS]")
    else:
        print(f"[Conntrack Server] FAILURE: Sessions ({len(unique_sessions)}) < target ({args.min_sessions}) [FAIL]")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)

    sys.exit(0 if result["status"] == "PASS" else 1)

def run_client(args):
    set_high_rlimit()
    print(f"[Conntrack Client] Target: {args.target_ip}:{args.port}. Creating {args.sessions} sessions (Start Port: {args.start_port}, Bidirectional: {args.bidirectional})...")

    target = (args.target_ip, args.port)
    start_port = args.start_port
    total = args.sessions
    rate = args.rate
    pacing_chunk = max(10, min(100, int(rate / 50))) if rate > 0 else 50
    delay = (pacing_chunk / rate) if rate > 0 else 0.0

    ep = select.epoll() if args.bidirectional else None
    sockets = {}
    
    print(f"[Conntrack Client] Initializing {total} local source ports...")
    t_init = time.time()
    for idx in range(total):
        port = start_port + idx
        if port > 65535:
            port = 1024 + (port % 64000)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            if args.bidirectional:
                s.setblocking(False)
                ep.register(s.fileno(), select.EPOLLIN)
                sockets[s.fileno()] = (s, idx)
            else:
                sockets[idx] = (s, idx)
        except Exception as e:
            pass

    print(f"[Conntrack Client] Bound {len(sockets)} local sockets in {time.time() - t_init:.2f}s. Dispatching traffic...")

    start_time = time.time()
    sent_count = 0
    for idx, item in enumerate(sockets.values()):
        s = item[0]
        try:
            s.sendto(f"FLOW_{idx}".encode(), target)
            sent_count += 1
        except Exception:
            pass

        if delay > 0 and (idx + 1) % pacing_chunk == 0:
            time.sleep(delay)

    t_send = time.time() - start_time
    print(f"[Conntrack Client] Dispatched {sent_count}/{total} flows in {t_send:.2f}s ({sent_count/max(t_send, 0.001):.0f} flows/s).")

    replies_received = 0
    if args.bidirectional and ep:
        print("[Conntrack Client] Collecting return packets through DUT reverse NAT...")
        deadline = time.time() + args.timeout
        while replies_received < sent_count and time.time() < deadline:
            events = ep.poll(0.05)
            for fd, event in events:
                if event & select.EPOLLIN:
                    try:
                        data, addr = sockets[fd][0].recvfrom(1024)
                        replies_received += 1
                        ep.unregister(fd)
                    except Exception:
                        pass

        success_pct = (replies_received / max(1, sent_count)) * 100.0
        print(f"[Conntrack Client] Received {replies_received}/{sent_count} reverse replies ({success_pct:.1f}% bidirectional session success).")

    if args.hold_sec > 0:
        print(f"[Conntrack Client] Holding all {len(sockets)} concurrent sessions active for {args.hold_sec}s...")
        time.sleep(args.hold_sec)

    print("[Conntrack Client] Closing session sockets...")
    for item in sockets.values():
        try:
            item[0].close()
        except Exception:
            pass

    if ep:
        ep.close()

    print("[Conntrack Client] Test completed.")

def main():
    parser = argparse.ArgumentParser(description="Concurrent Sessions Scalability Test Tool")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    srv_parser = subparsers.add_parser("server", help="Run session collector server")
    srv_parser.add_argument("--bind-ip", default="0.0.0.0")
    srv_parser.add_argument("--port", type=int, default=60000)
    srv_parser.add_argument("--min-sessions", type=int, default=1500)
    srv_parser.add_argument("--duration", type=float, default=10.0)
    srv_parser.add_argument("--timeout", type=float, default=2.0)
    srv_parser.add_argument("--direction", choices=["bidirectional", "oneway"], default="bidirectional", help="Session traffic direction")
    srv_parser.add_argument("--oneway", dest="bidirectional", action="store_false", help="Run in oneway (unidirectional) mode")
    srv_parser.add_argument("--bidirectional", dest="bidirectional", action="store_true", default=True, help="Run in bidirectional mode (default)")
    srv_parser.add_argument("--output", help="Result JSON output file")

    cli_parser = subparsers.add_parser("client", help="Run multi-session traffic generator")
    cli_parser.add_argument("--target-ip", required=True)
    cli_parser.add_argument("--port", type=int, default=60000)
    cli_parser.add_argument("--sessions", type=int, default=2000)
    cli_parser.add_argument("--start-port", type=int, default=10000)
    cli_parser.add_argument("--rate", type=float, default=3000.0, help="Dispatch rate in packets/sec")
    cli_parser.add_argument("--hold-sec", type=float, default=2.0)
    cli_parser.add_argument("--timeout", type=float, default=3.0, help="Reply collection timeout")
    cli_parser.add_argument("--direction", choices=["bidirectional", "oneway"], default="bidirectional", help="Session traffic direction")
    cli_parser.add_argument("--oneway", dest="bidirectional", action="store_false", help="Run in oneway (unidirectional) mode")
    cli_parser.add_argument("--bidirectional", dest="bidirectional", action="store_true", default=True, help="Run in bidirectional mode (default)")

    args = parser.parse_args()
    if hasattr(args, "direction"):
        if args.direction == "oneway":
            args.bidirectional = False
        elif args.direction == "bidirectional":
            args.bidirectional = True

    if args.mode == "server":
        run_server(args)
    elif args.mode == "client":
        run_client(args)

if __name__ == "__main__":
    main()
