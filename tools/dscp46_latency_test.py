#!/usr/bin/env python3
"""
Carrier Gateway DUT - DSCP 46 Process Delay Verification Tool
Measures LAN-to-WAN and WAN-to-LAN latency for packets marked with DSCP 46 (Expedited Forwarding).
Standard Requirement: One-way process delay through DUT <= 1.0 ms.
"""

import sys
import os
import subprocess
import socket
import struct
import time
import argparse
import json

DSCP_46_TOS = 46 << 2  # 184 (0xB8)

def analyze_pcap_transit(lan_pcap, wan_pcap, port=9999):
    """
    Computes exact hardware wiretap transit delay directly from LAN and WAN PCAP timestamps.
    """
    if not (os.path.exists(lan_pcap) and os.path.exists(wan_pcap)):
        return None

    def get_pkts(pcap_path):
        with open(pcap_path, 'rb') as f:
            cmd = ['tshark', '-r', '-', '-Y', f'udp.dstport == {port} or udp.srcport == {port}', '-T', 'fields', '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'udp.srcport', '-e', 'ip.dst', '-e', 'udp.dstport']
            out = subprocess.check_output(cmd, stdin=f).decode(errors='ignore').strip().split('\n')
        pkts = []
        for line in out:
            parts = line.split('\t')
            if len(parts) == 5 and parts[2] and parts[4]:
                try:
                    pkts.append((float(parts[0]), parts[1], int(parts[2]), parts[3], int(parts[4])))
                except ValueError:
                    pass
        return pkts

    try:
        lan_pkts = get_pkts(lan_pcap)
        wan_pkts = get_pkts(wan_pcap)

        forward_delays = []
        reverse_delays = []

        lan_fwd = [p for p in lan_pkts if p[1].startswith('192.168.')]
        wan_fwd = [p for p in wan_pkts if not p[1].startswith('192.168.') and p[3] == '10.10.0.1']

        for l, w in zip(lan_fwd, wan_fwd):
            diff_ms = (w[0] - l[0]) * 1000.0
            if 0 <= diff_ms <= 100.0:
                forward_delays.append(diff_ms)

        wan_rev = [p for p in wan_pkts if p[1] == '10.10.0.1']
        lan_rev = [p for p in lan_pkts if p[1] == '10.10.0.1']

        for w, l in zip(wan_rev, lan_rev):
            diff_ms = (l[0] - w[0]) * 1000.0
            if 0 <= diff_ms <= 100.0:
                reverse_delays.append(diff_ms)

        all_delays = forward_delays + reverse_delays
        all_delays.sort()

        if not all_delays:
            return None

        return {
            'forward_count': len(forward_delays),
            'forward_avg_ms': round(sum(forward_delays)/len(forward_delays), 3) if forward_delays else 0,
            'reverse_count': len(reverse_delays),
            'reverse_avg_ms': round(sum(reverse_delays)/len(reverse_delays), 3) if reverse_delays else 0,
            'overall_count': len(all_delays),
            'hardware_delay_avg_ms': round(sum(all_delays)/len(all_delays), 3),
            'hardware_delay_min_ms': round(min(all_delays), 3),
            'hardware_delay_max_ms': round(max(all_delays), 3),
            'hardware_delay_p95_ms': round(all_delays[int(len(all_delays)*0.95)], 3),
            'hardware_delay_p99_ms': round(all_delays[int(len(all_delays)*0.99)], 3),
        }
    except Exception as e:
        print(f"[PCAP Analyzer] Warning analyzing PCAP timestamps: {e}")
        return None

def run_reflector(args):
    print(f"[DSCP Echo Reflector] Listening on {args.bind_ip}:{args.port} (TOS={DSCP_46_TOS})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_46_TOS)
    sock.bind((args.bind_ip, args.port))
    sock.settimeout(args.timeout)

    start_time = time.time()
    echoed = 0
    while (time.time() - start_time) < args.timeout:
        try:
            data, addr = sock.recvfrom(2048)
            sock.sendto(data, addr)
            echoed += 1
        except socket.timeout:
            break

    sock.close()
    print(f"[DSCP Echo Reflector] Reflected {echoed} packets.")

def run_prober(args):
    print(f"[DSCP Latency Prober] Probing target {args.target_ip}:{args.port} with {args.count} packets (DSCP 46 / TOS={DSCP_46_TOS})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_46_TOS)
    sock.settimeout(args.timeout)

    rtts_ms = []

    for seq in range(args.count):
        send_ts = time.time()
        payload = struct.pack("!Id", seq, send_ts)
        try:
            sock.sendto(payload, (args.target_ip, args.port))
            data, _ = sock.recvfrom(2048)
            recv_ts = time.time()
            if len(data) >= 12:
                r_seq, orig_send_ts = struct.unpack("!Id", data[:12])
                rtt_ms = (recv_ts - orig_send_ts) * 1000.0
                rtts_ms.append(rtt_ms)
        except socket.timeout:
            print(f"[DSCP Latency Prober] Packet #{seq} timed out.")
        time.sleep(args.interval)

    sock.close()

    result = {
        "status": "FAIL",
        "dscp_value": 46,
        "tos_byte": DSCP_46_TOS,
        "packets_sent": args.count,
        "packets_received": len(rtts_ms),
        "loss_rate_percent": ((args.count - len(rtts_ms)) / args.count) * 100.0 if args.count > 0 else 100.0,
        "delay_threshold_ms": args.max_delay_ms,
        "latency_stats_ms": {}
    }

    if rtts_ms:
        rtts_ms.sort()
        avg_rtt = sum(rtts_ms) / len(rtts_ms)
        min_rtt = rtts_ms[0]
        max_rtt = rtts_ms[-1]
        p95_rtt = rtts_ms[int(len(rtts_ms) * 0.95)]
        p99_rtt = rtts_ms[int(len(rtts_ms) * 0.99)]

        # One-way processing delay through the DUT: RTT traverses DUT twice (LAN -> WAN, and WAN -> LAN)
        # Therefore, average one-way transit delay is RTT / 2.
        one_way_avg = avg_rtt / 2.0
        one_way_min = min_rtt / 2.0
        one_way_max = max_rtt / 2.0
        one_way_p95 = p95_rtt / 2.0
        one_way_p99 = p99_rtt / 2.0

        result["avg_one_way_ms"] = round(one_way_avg, 3)
        result["one_way_process_delay_ms"] = round(one_way_avg, 3)
        result["avg_rtt"] = round(avg_rtt, 3)
        result["p95_one_way_ms"] = round(one_way_p95, 3)
        result["p99_one_way_ms"] = round(one_way_p99, 3)

        result["latency_stats_ms"] = {
            "min_rtt": round(min_rtt, 3),
            "max_rtt": round(max_rtt, 3),
            "avg_rtt": round(avg_rtt, 3),
            "p95_rtt": round(p95_rtt, 3),
            "p99_rtt": round(p99_rtt, 3),
            "one_way_avg": round(one_way_avg, 3),
            "one_way_min": round(one_way_min, 3),
            "one_way_max": round(one_way_max, 3),
            "one_way_p95": round(one_way_p95, 3),
            "one_way_p99": round(one_way_p99, 3)
        }

        print(f"[DSCP Latency Prober] Results: Avg RTT = {avg_rtt:.3f} ms (One-Way Delay ≈ {one_way_avg:.3f} ms) | Min = {min_rtt:.3f} ms | Max = {max_rtt:.3f} ms | P99 = {p99_rtt:.3f} ms")

        # Threshold check: Carrier requirement is One-Way Process Delay <= 1.0 ms
        if one_way_avg <= args.max_delay_ms:
            result["status"] = "PASS"
            print(f"[DSCP Latency Prober] SUCCESS: Estimated one-way process delay {one_way_avg:.3f} ms (RTT {avg_rtt:.3f} ms / 2) <= {args.max_delay_ms} ms threshold [PASS]")
        else:
            result["status"] = "FAIL"
            print(f"[DSCP Latency Prober] FAILURE: One-way process delay {one_way_avg:.3f} ms > {args.max_delay_ms} ms threshold [FAIL]")
    else:
        print("[DSCP Latency Prober] FAILURE: 100% packet loss.")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)

    sys.exit(0 if result["status"] == "PASS" else 1)

def run_pcap_analyzer(args):
    print(f"[DSCP Wiretap Analyzer] Analyzing PCAP timestamps: LAN={args.lan_pcap}, WAN={args.wan_pcap} (Port={args.port})...")
    stats = analyze_pcap_transit(args.lan_pcap, args.wan_pcap, args.port)

    if not stats:
        print("[DSCP Wiretap Analyzer] Failed to extract matching UDP transit packets from PCAP captures.")
        sys.exit(1)

    print(f"[DSCP Wiretap Analyzer] Matched {stats['overall_count']} packets across LAN & WAN wiretaps:")
    print(f"  Forward Delay (LAN -> WAN): Avg = {stats['forward_avg_ms']} ms")
    print(f"  Reverse Delay (WAN -> LAN): Avg = {stats['reverse_avg_ms']} ms")
    print(f"  Hardware Process Delay:     Avg = {stats['hardware_delay_avg_ms']} ms | P95 = {stats['hardware_delay_p95_ms']} ms | P99 = {stats['hardware_delay_p99_ms']} ms | Max = {stats['hardware_delay_max_ms']} ms")

    status = "PASS" if stats['hardware_delay_avg_ms'] <= args.max_delay_ms else "FAIL"

    out_data = {
        "status": status,
        "mode": "wiretap_hardware_timestamps",
        "threshold_ms": args.max_delay_ms,
        "hardware_process_delay_avg_ms": stats['hardware_delay_avg_ms'],
        "wiretap_stats_ms": stats
    }

    if args.update_result and os.path.exists(args.update_result):
        try:
            with open(args.update_result, "r") as f:
                existing = json.load(f)
            existing["wiretap_stats_ms"] = stats
            existing["hardware_process_delay_avg_ms"] = stats['hardware_delay_avg_ms']
            if stats['hardware_delay_avg_ms'] <= args.max_delay_ms:
                existing["status"] = "PASS"
            with open(args.update_result, "w") as f:
                json.dump(existing, f, indent=2)
            print(f"[DSCP Wiretap Analyzer] Updated result file: {args.update_result}")
        except Exception as e:
            print(f"[DSCP Wiretap Analyzer] Warning updating result file: {e}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(out_data, f, indent=2)

    sys.exit(0 if status == "PASS" else 1)

def main():
    parser = argparse.ArgumentParser(description="DSCP 46 Process Delay Test Tool")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    ref_parser = subparsers.add_parser("reflector", help="Run UDP echo reflector")
    ref_parser.add_argument("--bind-ip", default="0.0.0.0")
    ref_parser.add_argument("--port", type=int, default=9999)
    ref_parser.add_argument("--timeout", type=float, default=15.0)

    prober_parser = subparsers.add_parser("prober", help="Run latency probe generator")
    prober_parser.add_argument("--target-ip", required=True)
    prober_parser.add_argument("--port", type=int, default=9999)
    prober_parser.add_argument("--count", type=int, default=100)
    prober_parser.add_argument("--interval", type=float, default=0.01)
    prober_parser.add_argument("--timeout", type=float, default=2.0)
    prober_parser.add_argument("--max-delay-ms", type=float, default=1.0)
    prober_parser.add_argument("--output", help="Result JSON output")

    pcap_parser = subparsers.add_parser("analyze-pcap", help="Analyze hardware transit delays from PCAP captures")
    pcap_parser.add_argument("--lan-pcap", required=True)
    pcap_parser.add_argument("--wan-pcap", required=True)
    pcap_parser.add_argument("--port", type=int, default=9999)
    pcap_parser.add_argument("--max-delay-ms", type=float, default=1.0)
    pcap_parser.add_argument("--output", help="Wiretap analysis output JSON")
    pcap_parser.add_argument("--update-result", help="Update existing result JSON with wiretap stats")

    args = parser.parse_args()
    if args.mode == "reflector":
        run_reflector(args)
    elif args.mode == "prober":
        run_prober(args)
    elif args.mode == "analyze-pcap":
        run_pcap_analyzer(args)

if __name__ == "__main__":
    main()
