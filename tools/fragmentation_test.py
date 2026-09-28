#!/usr/bin/env python3
"""
Carrier Gateway DUT - Out-of-Order IP Fragmentation & Reassembly Test Tool
Simulates VoLTE Femtocell traffic where IP fragments arrive out-of-order.
Verifies that the Gateway reassembles and forwards fragmented packets reliably.
"""

import sys
import os
import socket
import struct
import time
import argparse
import json

def checksum(msg):
    s = 0
    if len(msg) % 2 == 1:
        msg += b"\x00"
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF

def build_ip_header(src_ip, dst_ip, identification, flags_offset, proto, payload_len):
    # IPv4 Header: 20 bytes (IHL=5, Ver=4 -> 0x45)
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ttl = 64
    chk = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    hdr_no_chk = struct.pack("!BBHHHBBH4s4s",
                             version_ihl, tos, total_len, identification,
                             flags_offset, ttl, proto, chk,
                             src_bytes, dst_bytes)
    chk = checksum(hdr_no_chk)
    hdr = struct.pack("!BBHHHBBH4s4s",
                      version_ihl, tos, total_len, identification,
                      flags_offset, ttl, proto, chk,
                      src_bytes, dst_bytes)
    return hdr

def build_udp_header(src_port, dst_port, udp_payload_len):
    total_udp_len = 8 + udp_payload_len
    chk = 0  # Optional for IPv4 UDP
    return struct.pack("!HHHH", src_port, dst_port, total_udp_len, chk)

def run_receiver(args):
    print(f"[Frag Receiver] Listening for reassembled UDP datagram on {args.bind_ip}:{args.port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind_ip, args.port))
    sock.settimeout(args.timeout)

    result = {
        "status": "FAIL",
        "reassembled_success": False,
        "bytes_received": 0,
        "expected_bytes": args.expected_bytes,
        "sender_addr": None,
        "error": None
    }

    try:
        data, addr = sock.recvfrom(65535)
        print(f"[Frag Receiver] Received {len(data)} bytes from {addr[0]}:{addr[1]}")
        result["bytes_received"] = len(data)
        result["sender_addr"] = {"ip": addr[0], "port": addr[1]}

        if len(data) == args.expected_bytes:
            result["reassembled_success"] = True
            result["status"] = "PASS"
            print(f"[Frag Receiver] SUCCESS: Full UDP datagram reassembled ({len(data)} bytes match expected).")
        else:
            result["status"] = "FAIL"
            print(f"[Frag Receiver] FAILURE: Received length {len(data)} != expected {args.expected_bytes}")

    except socket.timeout:
        result["error"] = "Timeout waiting for reassembled packet (fragments may have been dropped)"
        print(f"[Frag Receiver] ERROR: {result['error']}")
    except Exception as e:
        result["error"] = str(e)
        print(f"[Frag Receiver] ERROR: {e}")
    finally:
        sock.close()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)

    sys.exit(0 if result["status"] == "PASS" else 1)

def run_sender(args):
    """
    Sends a fragmented UDP datagram out of order.
    Total UDP payload: e.g. 1800 bytes
    Frag 1: 1480 bytes IP payload (8-byte UDP hdr + 1472 data). Flags: MF=1, Offset=0
    Frag 2: 328 bytes IP payload (remaining 328 data). Flags: MF=0, Offset=185
    Sends Frag 2 FIRST, then sleeps 50ms, then sends Frag 1 SECOND!
    """
    print(f"[Femto Sender] Generating out-of-order fragmented UDP packet to {args.dst_ip}:{args.dst_port}")
    
    # 1800 bytes UDP payload total
    udp_payload_len = args.total_payload
    payload_data = b"VOLTE_FEMTO_DATA_" * (udp_payload_len // 17 + 1)
    payload_data = payload_data[:udp_payload_len]

    udp_hdr = build_udp_header(args.src_port, args.dst_port, udp_payload_len)
    full_udp_datagram = udp_hdr + payload_data

    # Frag 1 payload: 1480 bytes (Divisible by 8)
    frag1_data = full_udp_datagram[:1480]
    # Frag 2 payload: remainder
    frag2_data = full_udp_datagram[1480:]

    # Flags & Offset calculations:
    # 13-bit offset in 8-byte units
    # Flags: bit 13 = MF (0x2000)
    frag_id = 0xBEEF

    # Frag 1: MF=1, offset=0 -> 0x2000
    flags_offset_frag1 = 0x2000 | 0
    # Frag 2: MF=0, offset=185 -> 185
    flags_offset_frag2 = 0x0000 | (1480 // 8)

    ip_hdr_frag1 = build_ip_header(args.src_ip, args.dst_ip, frag_id, flags_offset_frag1, socket.IPPROTO_UDP, len(frag1_data))
    ip_hdr_frag2 = build_ip_header(args.src_ip, args.dst_ip, frag_id, flags_offset_frag2, socket.IPPROTO_UDP, len(frag2_data))

    pkt_frag1 = ip_hdr_frag1 + frag1_data
    pkt_frag2 = ip_hdr_frag2 + frag2_data

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        if args.reverse_order:
            print("[Femto Sender] Sending FRAGMENT #2 FIRST (Offset=185, MF=0)...")
            raw_sock.sendto(pkt_frag2, (args.dst_ip, 0))
            time.sleep(0.05)
            print("[Femto Sender] Sending FRAGMENT #1 SECOND (Offset=0, MF=1)...")
            raw_sock.sendto(pkt_frag1, (args.dst_ip, 0))
        else:
            print("[Femto Sender] Sending FRAGMENT #1 FIRST...")
            raw_sock.sendto(pkt_frag1, (args.dst_ip, 0))
            time.sleep(0.05)
            print("[Femto Sender] Sending FRAGMENT #2 SECOND...")
            raw_sock.sendto(pkt_frag2, (args.dst_ip, 0))
        print("[Femto Sender] Fragments successfully dispatched.")
    finally:
        raw_sock.close()

def main():
    parser = argparse.ArgumentParser(description="VoLTE Femto Out-of-Order Fragmentation Test")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    recv_parser = subparsers.add_parser("receiver", help="Run fragmented datagram receiver")
    recv_parser.add_argument("--bind-ip", default="0.0.0.0")
    recv_parser.add_argument("--port", type=int, default=7777)
    recv_parser.add_argument("--expected-bytes", type=int, default=1800)
    recv_parser.add_argument("--timeout", type=float, default=8.0)
    recv_parser.add_argument("--output", help="Output JSON result")

    send_parser = subparsers.add_parser("sender", help="Run fragmented datagram sender")
    send_parser.add_argument("--src-ip", required=True)
    send_parser.add_argument("--dst-ip", required=True)
    send_parser.add_argument("--src-port", type=int, default=17777)
    send_parser.add_argument("--dst-port", type=int, default=7777)
    send_parser.add_argument("--total-payload", type=int, default=1800)
    send_parser.add_argument("--reverse-order", action="store_true", default=True)

    args = parser.parse_args()
    if args.mode == "receiver":
        run_receiver(args)
    elif args.mode == "sender":
        run_sender(args)

if __name__ == "__main__":
    main()
