#!/usr/bin/env python3
"""
Carrier Gateway DUT - Sequential Port Allocation & Blacklist Skip Verification Tool
Verifies:
1. Targeted Boundary Injection: Probes 11 blacklisted ports to verify Gateway refuses to leak them to WAN.
2. Large-scale Collision Sweep (500+ flows): Induces 500 collisions across LAN1 and LAN2 to cross
   the 1433/1434 boundary and empirically verify the skip-list algorithm.
3. Start Port Validation: Verifies all allocated external ports start sequentially from >= 1026.
"""

import sys
import os
import re
import socket
import struct
import time
import argparse
import json

DEFAULT_SKIP_PORTS = [1433, 1434, 4444, 9898, 1900, 2869, 3702, 57321, 3127, 2745, 17300]

def set_high_rlimit():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(65536, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass

def parse_payload(payload_str):
    """
    Parses payload:
      CLIENT_<id>_PROBE_<port>_ORIGPORT_<port>
      CLIENT_<id>_FLOW_<num>_ORIGPORT_<port>
    Returns (msg_type, client_id, flow_or_target, orig_port)
    """
    m_probe = re.match(r"CLIENT_([A-Za-z0-9]+)_PROBE_(\d+)(?:_ORIGPORT_(\d+))?", payload_str)
    if m_probe:
        cid = m_probe.group(1)
        target_port = int(m_probe.group(2))
        orig_port = int(m_probe.group(3)) if m_probe.group(3) else target_port
        return "PROBE", cid, target_port, orig_port

    m_flow = re.match(r"CLIENT_([A-Za-z0-9]+)_FLOW_(\d+)(?:_ORIGPORT_(\d+))?", payload_str)
    if m_flow:
        cid = m_flow.group(1)
        fnum = int(m_flow.group(2))
        orig_port = int(m_flow.group(3)) if m_flow.group(3) else None
        return "FLOW", cid, fnum, orig_port

    return "UNKNOWN", "UNKNOWN", 0, None

def analyze_sequentiality(ports):
    """
    Analyzes whether a list of external ports follows a sequential pattern.
    """
    if len(ports) < 2:
        return "INSUFFICIENT_SAMPLES", []

    deltas = [ports[i+1] - ports[i] for i in range(len(ports)-1)]
    is_strictly_seq = all(d == 1 for d in deltas)
    is_monotonic_inc = all(d > 0 for d in deltas)
    is_near_seq = all(0 < d <= 5 for d in deltas)

    if is_strictly_seq:
        pattern = "STRICT_SEQUENTIAL_STEP_1"
    elif is_near_seq:
        pattern = "NEAR_SEQUENTIAL"
    elif is_monotonic_inc:
        pattern = "MONOTONIC_INCREASING"
    else:
        pattern = "DYNAMIC_OR_HASHED"

    return pattern, deltas

def run_server(args):
    skip_list = set()
    if args.skip_ports:
        for p in args.skip_ports.split(","):
            p = p.strip()
            if p:
                skip_list.add(int(p))
    else:
        skip_list = set(DEFAULT_SKIP_PORTS)

    print(f"[Port Server] Listening on {args.bind_ip}:{args.port}...")
    print(f"[Port Server] Monitored skip/blacklist ports ({len(skip_list)} ports): {sorted(list(skip_list))}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind_ip, args.port))
    sock.settimeout(args.timeout)

    captured_ports = []
    probe_records = []
    flow_records = []
    blacklist_violations = []
    received_count = 0
    start_time = time.time()

    print(f"[Port Server] Collecting packets (expecting up to {args.expected_count} packets)...")

    while received_count < args.expected_count and (time.time() - start_time) < args.timeout:
        try:
            data, addr = sock.recvfrom(2048)
            client_ip, ext_port = addr
            received_count += 1
            captured_ports.append(ext_port)
            payload_str = data.decode(errors="ignore")

            mtype, cid, item_id, orig_port = parse_payload(payload_str)

            if mtype == "PROBE":
                # Boundary injection probe packet
                is_leaked = (ext_port in skip_list)
                is_remapped = (orig_port in skip_list and ext_port not in skip_list)
                rec = {
                    "client_id": cid,
                    "target_blacklist_port": item_id,
                    "orig_port": orig_port,
                    "ext_port": ext_port,
                    "leaked_to_wan": is_leaked,
                    "remapped_safe": is_remapped
                }
                probe_records.append(rec)

                if is_leaked:
                    blacklist_violations.append(ext_port)
                    print(f"[Port Server] PROBE #{received_count:03d}: [CRITICAL VIOLATION] Gateway LEAKED blacklist port {ext_port} to WAN! (LAN Port {orig_port})")
                else:
                    print(f"[Port Server] PROBE #{received_count:03d}: [PROTECTED] Gateway intercepted blacklist port {orig_port} -> Remapped to {ext_port} [PASS]")

            else:
                # Sweep flow packet
                is_translated = (orig_port is not None and ext_port != orig_port)
                rec = {
                    "packet_num": received_count,
                    "client_id": cid,
                    "flow": item_id,
                    "orig_port": orig_port,
                    "ext_ip": client_ip,
                    "ext_port": ext_port,
                    "translated": is_translated
                }
                flow_records.append(rec)

                if ext_port in skip_list:
                    blacklist_violations.append(ext_port)
                    print(f"[Port Server] FLOW #{received_count:03d}: [VIOLATION] Blacklisted port {ext_port} allocated! (Client={cid} Flow={item_id})")
                elif received_count <= 25 or (received_count % 100 == 0):
                    status_tag = f" [TRANSLATED: {orig_port} -> {ext_port}]" if is_translated else f" [PRESERVED: {orig_port}]"
                    print(f"[Port Server] FLOW #{received_count:03d}: ExtAddr={client_ip}:{ext_port} | Client={cid} Flow={item_id}{status_tag}")

        except socket.timeout:
            break

    sock.close()

    # Process and analyze results
    translated_flows = [r for r in flow_records if r["translated"]]
    preserved_flows = [r for r in flow_records if not r["translated"]]
    translated_ports = [r["ext_port"] for r in translated_flows]

    seq_pattern, seq_deltas = analyze_sequentiality(translated_ports)

    # Check 1433/1434 boundary crossing
    skip_1433_1434_crossed = False
    skip_1433_1434_verified = False
    if translated_ports:
        min_p = min(translated_ports)
        max_p = max(translated_ports)
        if min_p <= 1433 and max_p >= 1434:
            skip_1433_1434_crossed = True
            if (1433 not in translated_ports) and (1434 not in translated_ports):
                skip_1433_1434_verified = True

    min_overall_port = min(captured_ports) if captured_ports else 0
    max_overall_port = max(captured_ports) if captured_ports else 0
    start_port_gte_1026 = (min_overall_port >= args.start_port) if captured_ports else False

    probes_leaked = [r for r in probe_records if r["leaked_to_wan"]]
    probes_safe = [r for r in probe_records if r["remapped_safe"]]

    status = "PASS"
    if blacklist_violations or not start_port_gte_1026:
        status = "FAIL"

    result = {
        "status": status,
        "total_packets_received": received_count,
        "min_allocated_port": min_overall_port,
        "max_allocated_port": max_overall_port,
        "start_port_gte_1026": start_port_gte_1026,
        "violations_count": len(blacklist_violations),
        "blacklisted_ports_allocated": list(set(blacklist_violations)),
        "skip_list_verified": len(blacklist_violations) == 0,
        "probes_leaked_count": len(probes_leaked),
        "probes_protected_count": len(probes_safe),
        "translated_flows_count": len(translated_flows),
        "sequential_pattern": seq_pattern,
        "skip_1433_1434_verified": skip_1433_1434_verified,
        "boundary_probe_test": {
            "probes_received": len(probe_records),
            "probes_leaked_count": len(probes_leaked),
            "probes_protected_count": len(probes_safe),
            "probe_details": probe_records
        },
        "collision_sweep_test": {
            "total_sweep_flows": len(flow_records),
            "collisions_induced": len(translated_flows) > 0,
            "translated_flows_count": len(translated_flows),
            "preserved_flows_count": len(preserved_flows),
            "sequential_pattern": seq_pattern,
            "skip_1433_1434_crossed": skip_1433_1434_crossed,
            "skip_1433_1434_verified": skip_1433_1434_verified,
            "translated_ports_sample": translated_ports[:50]
        }
    }

    print("\n" + "=" * 70)
    print("           PORT ALLOCATION & BLACKLIST VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Total Packets Processed: {received_count}")
    print(f"Start Port Check: Min Port={min_overall_port} (>= {args.start_port}) [{'PASS' if start_port_gte_1026 else 'FAIL'}]")

    if probe_records:
        probe_status = "PASS" if len(probes_leaked) == 0 else "FAIL"
        print(f"Boundary Probes: {len(probes_safe)}/{len(probe_records)} protected, {len(probes_leaked)} leaked [{probe_status}]")

    if flow_records:
        print(f"Collision Sweep: {len(translated_flows)} flows remapped due to contention.")
        print(f"Sequential Pattern: {seq_pattern}")
        if skip_1433_1434_crossed:
            skip_status = "VERIFIED (SKIPPED 1433/1434)" if skip_1433_1434_verified else "FAILED (1433/1434 ALLOCATED)"
            print(f"1433/1434 Boundary Skip: {skip_status}")

    print(f"Blacklist Violation Check: {len(blacklist_violations)} violations [{'PASS' if len(blacklist_violations) == 0 else 'FAIL'}]")
    print(f"OVERALL RESULT: [{status}]")
    print("=" * 70 + "\n")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)

    sys.exit(0 if status == "PASS" else 1)

def run_probe_client(args):
    set_high_rlimit()
    ports_to_probe = []
    if args.probe_ports:
        for p in args.probe_ports.split(","):
            p = p.strip()
            if p:
                ports_to_probe.append(int(p))
    else:
        ports_to_probe = sorted(DEFAULT_SKIP_PORTS)

    print(f"[Port Probe {args.client_id}] Target: {args.server_ip}:{args.server_port}, probing {len(ports_to_probe)} blacklist ports: {ports_to_probe}...")

    sent_count = 0
    for port in ports_to_probe:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            actual_src_port = s.getsockname()[1]
            payload = f"CLIENT_{args.client_id}_PROBE_{port}_ORIGPORT_{actual_src_port}".encode()
            s.sendto(payload, (args.server_ip, args.server_port))
            sent_count += 1
            print(f"[Port Probe {args.client_id}] Injected LAN packet from Blacklist port {actual_src_port} -> {args.server_ip}:{args.server_port}")
        except Exception as e:
            print(f"[Port Probe {args.client_id}] Warning binding to port {port}: {e}")
        finally:
            s.close()
        time.sleep(args.interval)

    print(f"[Port Probe {args.client_id}] Completed sending {sent_count} blacklist boundary probes.")

def run_client(args):
    set_high_rlimit()
    base_port_str = f"Base Src Port: {args.base_src_port}" if args.base_src_port > 0 else "Ephemeral Ports"
    print(f"[Port Client {args.client_id}] Target: {args.server_ip}:{args.server_port}, sending {args.count} flows ({base_port_str}, Interval: {args.interval*1000:.1f}ms)...")

    sockets = []
    t_start = time.time()
    try:
        for i in range(args.count):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            src_port = 0
            if args.base_src_port > 0:
                src_port = args.base_src_port + (i if args.increment_port else 0)
                if src_port > 65535:
                    src_port = 1026 + (src_port % 64000)
                try:
                    s.bind(("0.0.0.0", src_port))
                except Exception as e:
                    if i < 5:
                        print(f"[Port Client {args.client_id}] Warning binding port {src_port}: {e}")

            actual_src_port = s.getsockname()[1]
            payload = f"CLIENT_{args.client_id}_FLOW_{i+1}_ORIGPORT_{actual_src_port}".encode()
            s.sendto(payload, (args.server_ip, args.server_port))
            sockets.append(s)
            if args.interval > 0:
                time.sleep(args.interval)

        elapsed = time.time() - t_start
        print(f"[Port Client {args.client_id}] Dispatched {args.count} flows in {elapsed:.2f}s. Holding {len(sockets)} sockets active for {args.hold_sec}s...")
        if args.hold_sec > 0:
            time.sleep(args.hold_sec)
    finally:
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass

    print(f"[Port Client {args.client_id}] Closed sockets. Test completed.")

def main():
    parser = argparse.ArgumentParser(description="Carrier Sequential Port Allocation & Blacklist Verification")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    srv_parser = subparsers.add_parser("server", help="Run port allocation monitor server")
    srv_parser.add_argument("--bind-ip", default="0.0.0.0")
    srv_parser.add_argument("--port", type=int, default=8888)
    srv_parser.add_argument("--start-port", type=int, default=1026)
    srv_parser.add_argument("--skip-ports", default="1433,1434,4444,9898,1900,2869,3702,57321,3127,2745,17300")
    srv_parser.add_argument("--expected-count", type=int, default=1011)
    srv_parser.add_argument("--timeout", type=float, default=12.0)
    srv_parser.add_argument("--output", help="Result JSON file")

    cli_parser = subparsers.add_parser("client", help="Run multi-port traffic generator")
    cli_parser.add_argument("--server-ip", required=True)
    cli_parser.add_argument("--server-port", type=int, default=8888)
    cli_parser.add_argument("--client-id", default="LAN1")
    cli_parser.add_argument("--count", type=int, default=500)
    cli_parser.add_argument("--interval", type=float, default=0.002)
    cli_parser.add_argument("--base-src-port", type=int, default=5000, help="Base source port to bind (0 for ephemeral)")
    cli_parser.add_argument("--no-increment", dest="increment_port", action="store_false", default=True, help="Do not increment port per flow")
    cli_parser.add_argument("--hold-sec", type=float, default=3.0, help="Time to hold sockets open after dispatch")

    prb_parser = subparsers.add_parser("probe", help="Run direct blacklist boundary probe")
    prb_parser.add_argument("--server-ip", required=True)
    prb_parser.add_argument("--server-port", type=int, default=8888)
    prb_parser.add_argument("--client-id", default="LAN1")
    prb_parser.add_argument("--probe-ports", default="1433,1434,4444,9898,1900,2869,3702,57321,3127,2745,17300")
    prb_parser.add_argument("--interval", type=float, default=0.01)

    args = parser.parse_args()
    if args.mode == "server":
        run_server(args)
    elif args.mode == "client":
        run_client(args)
    elif args.mode == "probe":
        run_probe_client(args)

if __name__ == "__main__":
    main()
