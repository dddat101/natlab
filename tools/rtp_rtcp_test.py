#!/usr/bin/env python3
"""
RTP and RTCP Port Pairing Test Tool (RFC 3550 Compliance)
Requirement: RTCP port must equal RTP port + 1 through NAT.
"""

import sys
import os
import socket
import struct
import time
import argparse
import json

def craft_rtp_packet(seq=1, pt=0, ssrc=0x12345678):
    # RFC 3550 RTP Header: V=2, P=0, X=0, CC=0 (0x80), PT=0 (PCMU)
    header = struct.pack("!BBHII", 0x80, pt & 0x7f, seq, 160 * seq, ssrc)
    payload = b"\xd5" * 160  # 160 bytes G.711 audio payload
    return header + payload

def craft_rtcp_sr(ssrc=0x12345678, rtp_ts=160, pkt_count=1, octet_count=160):
    # RFC 3550 RTCP Sender Report: V=2, P=0, RC=0 (0x80), PT=200 (SR), length=6 (28 bytes)
    # Header: 4 bytes (V=2, P=0, RC=0, PT=200, length=6 words following)
    header = struct.pack("!BBH", 0x80, 200, 6)
    # Body: 6 words (24 bytes) = SSRC, NTP MSW, NTP LSW, RTP TS, Pkt Count, Octet Count
    # Total RTCP packet length = 4 + 24 = 28 bytes = (6 + 1) * 4 bytes
    ntp_now = time.time() + 2208988800  # NTP epoch offset (1900 to 1970)
    ntp_msw = int(ntp_now)
    ntp_lsw = int((ntp_now - ntp_msw) * (1 << 32))
    sr_body = struct.pack("!IIIIII", ssrc, ntp_msw, ntp_lsw, rtp_ts, pkt_count, octet_count)
    return header + sr_body

def run_server(bind_ip, rtp_port, rtcp_port, timeout=6.0, output=None):
    print(f"[SSW-SERVER] Listening for RTP on {bind_ip}:{rtp_port} and RTCP on {bind_ip}:{rtcp_port}")
    sock_rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rtp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_rtp.bind((bind_ip, rtp_port))

    sock_rtcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rtcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_rtcp.bind((bind_ip, rtcp_port))

    sock_rtp.settimeout(timeout)
    sock_rtcp.settimeout(timeout)

    result_data = {
        "engine": "python",
        "status": "FAIL",
        "rtp_port": 0,
        "rtcp_port": 0,
        "port_delta": 0,
        "expected_delta": 1
    }

    try:
        data_rtp, addr_rtp = sock_rtp.recvfrom(1024)
        print(f"[SSW-SERVER] Received RTP from {addr_rtp[0]}:{addr_rtp[1]} (length: {len(data_rtp)}B)")
    except socket.timeout:
        print("[SSW-SERVER] [FAIL] Timeout waiting for RTP packet")
        if output:
            with open(output, "w") as f:
                json.dump(result_data, f, indent=2)
        sock_rtp.close()
        sock_rtcp.close()
        return 1

    try:
        data_rtcp, addr_rtcp = sock_rtcp.recvfrom(1024)
        print(f"[SSW-SERVER] Received RTCP from {addr_rtcp[0]}:{addr_rtcp[1]} (length: {len(data_rtcp)}B)")
    except socket.timeout:
        print("[SSW-SERVER] [FAIL] Timeout waiting for RTCP packet")
        if output:
            with open(output, "w") as f:
                json.dump(result_data, f, indent=2)
        sock_rtp.close()
        sock_rtcp.close()
        return 1

    wan_ip_rtp, wan_port_rtp = addr_rtp
    wan_ip_rtcp, wan_port_rtcp = addr_rtcp

    print(f"[SSW-SERVER] Mapped RTP Address : {wan_ip_rtp}:{wan_port_rtp}")
    print(f"[SSW-SERVER] Mapped RTCP Address: {wan_ip_rtcp}:{wan_port_rtcp}")

    # Check RFC 3550 RTCP = RTP + 1 rule
    delta = wan_port_rtcp - wan_port_rtp
    result_data["rtp_port"] = wan_port_rtp
    result_data["rtcp_port"] = wan_port_rtcp
    result_data["port_delta"] = delta

    expected_rtcp_port = wan_port_rtp + 1
    if wan_port_rtcp == expected_rtcp_port:
        print(f"[SSW-SERVER] [PASS] RTCP port ({wan_port_rtcp}) correctly equals RTP port ({wan_port_rtp}) + 1!")
        result_data["status"] = "PASS"
        # Test reverse RTCP transmission back to client
        reverse_rtcp = craft_rtcp_sr(ssrc=0x87654321)
        sock_rtcp.sendto(reverse_rtcp, addr_rtcp)
        print(f"[SSW-SERVER] Sent reverse RTCP back to {addr_rtcp}")
        exit_code = 0
    else:
        print(f"[SSW-SERVER] [FAIL] RTCP port mismatch! Got {wan_port_rtcp}, expected {expected_rtcp_port} (delta: {delta})")
        result_data["status"] = "FAIL"
        exit_code = 2

    if output:
        with open(output, "w") as f:
            json.dump(result_data, f, indent=2)

    sock_rtp.close()
    sock_rtcp.close()
    return exit_code

def run_client(server_ip, server_rtp_port, server_rtcp_port, client_rtp_port=20000, client_rtcp_port=20001, timeout=3.0, output=None):
    print(f"[PHONE-CLIENT] Binding local RTP to port {client_rtp_port}, RTCP to port {client_rtcp_port}")

    sock_rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rtp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_rtp.bind(("0.0.0.0", client_rtp_port))

    sock_rtcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rtcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_rtcp.bind(("0.0.0.0", client_rtcp_port))
    sock_rtcp.settimeout(timeout)

    # 1. Send RTP
    rtp_pkt = craft_rtp_packet()
    sock_rtp.sendto(rtp_pkt, (server_ip, server_rtp_port))
    print(f"[PHONE-CLIENT] Sent RTP packet to {server_ip}:{server_rtp_port}")

    time.sleep(0.05)

    # 2. Send RTCP
    rtcp_pkt = craft_rtcp_sr()
    sock_rtcp.sendto(rtcp_pkt, (server_ip, server_rtcp_port))
    print(f"[PHONE-CLIENT] Sent RTCP packet to {server_ip}:{server_rtcp_port}")

    # 3. Wait for reverse RTCP
    try:
        data, srv_addr = sock_rtcp.recvfrom(1024)
        print(f"[PHONE-CLIENT] [PASS] Received reverse RTCP from {srv_addr} ({len(data)}B) on local RTCP port!")
    except socket.timeout:
        print("[PHONE-CLIENT] [WARN] No reverse RTCP received within timeout")

    sock_rtp.close()
    sock_rtcp.close()
    return 0

def run_rtcp_companion_server(bind_ip, rtcp_port, timeout=8.0, output=None):
    print(f"[RTCP-COMPANION-SRV] Listening for RTCP on {bind_ip}:{rtcp_port}")
    sock_rtcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rtcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_rtcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock_rtcp.bind((bind_ip, rtcp_port))
    sock_rtcp.settimeout(0.5)

    result_data = {
        "engine": "sipp",
        "status": "FAIL",
        "rtcp_port": 0
    }

    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            data_rtcp, addr_rtcp = sock_rtcp.recvfrom(1024)
            if result_data["status"] != "PASS":
                print(f"[RTCP-COMPANION-SRV] Received RTCP from {addr_rtcp[0]}:{addr_rtcp[1]} ({len(data_rtcp)}B)")
                result_data["status"] = "PASS"
                result_data["rtcp_port"] = addr_rtcp[1]
                result_data["mapped_ip"] = addr_rtcp[0]
            # Send reverse RTCP back for every received packet
            reverse_rtcp = craft_rtcp_sr(ssrc=0x87654321)
            sock_rtcp.sendto(reverse_rtcp, addr_rtcp)
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[RTCP-COMPANION-SRV] Exception: {e}")
            break

    if output:
        with open(output, "w") as f:
            json.dump(result_data, f, indent=2)

    sock_rtcp.close()
    return 0 if result_data["status"] == "PASS" else 1

def run_rtcp_companion_client(server_ip, server_rtcp_port, client_rtcp_port=20001, client_rtp_port=20000, count=3, interval=0.8, timeout=4.0):
    print(f"[RTCP-COMPANION-CLI] Binding RTCP to port {client_rtcp_port}, target {server_ip}:{server_rtcp_port}")
    sock_rtcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rtcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_rtcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock_rtcp.bind(("0.0.0.0", client_rtcp_port))
    sock_rtcp.settimeout(0.2)

    # Open RTP sink socket on client_rtp_port to absorb echoed RTP packets and avoid ICMP Port Unreachable
    sock_rtp_sink = None
    try:
        sock_rtp_sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_rtp_sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_rtp_sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock_rtp_sink.bind(("0.0.0.0", client_rtp_port))
        sock_rtp_sink.setblocking(False)
        print(f"[RTCP-COMPANION-CLI] Bound RTP sink socket on port {client_rtp_port}")
    except Exception as e:
        print(f"[RTCP-COMPANION-CLI] Could not bind RTP sink on {client_rtp_port}: {e}")

    start_time = time.time()
    pkt_sent = 0
    last_send = 0
    while time.time() - start_time < timeout:
        now = time.time()
        if pkt_sent < count and (now - last_send >= interval):
            rtcp_pkt = craft_rtcp_sr(ssrc=0x12345678, rtp_ts=160*(pkt_sent+1), pkt_count=50*(pkt_sent+1), octet_count=8000*(pkt_sent+1))
            sock_rtcp.sendto(rtcp_pkt, (server_ip, server_rtcp_port))
            print(f"[RTCP-COMPANION-CLI] Sent RTCP SR #{pkt_sent+1} to {server_ip}:{server_rtcp_port}")
            pkt_sent += 1
            last_send = now

        # Drain any reverse RTCP
        try:
            data, srv_addr = sock_rtcp.recvfrom(1024)
            print(f"[RTCP-COMPANION-CLI] [PASS] Received reverse RTCP from {srv_addr} ({len(data)}B)")
        except socket.timeout:
            pass

        # Drain any echoed RTP packets to prevent kernel ICMP port unreachable
        if sock_rtp_sink:
            try:
                while True:
                    sock_rtp_sink.recvfrom(2048)
            except BlockingIOError:
                pass

        time.sleep(0.05)

    sock_rtcp.close()
    if sock_rtp_sink:
        sock_rtp_sink.close()
    return 0

def main():
    parser = argparse.ArgumentParser(description="RFC 3550 RTP/RTCP Port Pairing Conformance Tool")
    parser.add_argument("pos_mode", nargs="?", choices=["server", "client"], help="Mode: server or client")
    parser.add_argument("--mode", choices=["server", "client"], help="Mode (optional if specified positionally)")
    parser.add_argument("--server-ip", default="10.10.0.1", help="WAN Server IP")
    parser.add_argument("--bind-ip", default="0.0.0.0", help="Bind IP for server")
    parser.add_argument("--server-rtp-port", "--rtp-port", dest="rtp_port", type=int, default=30000, help="RTP port on server")
    parser.add_argument("--server-rtcp-port", "--rtcp-port", dest="rtcp_port", type=int, default=30001, help="RTCP port on server")
    parser.add_argument("--client-rtp-port", type=int, default=20000, help="LAN client RTP port (even)")
    parser.add_argument("--client-rtcp-port", type=int, default=20001, help="LAN client RTCP port (odd)")
    parser.add_argument("--client-base-port", type=int, default=20000, help="LAN client base port (even)")
    parser.add_argument("--timeout", type=float, default=6.0, help="Socket timeout")
    parser.add_argument("--rtcp-companion", action="store_true", help="Run only RTCP stream companion (for SIPp integration)")
    parser.add_argument("--output", help="Result JSON output file")
    args = parser.parse_args()

    mode = args.pos_mode or args.mode
    if not mode:
        parser.error("Mode must be specified as 'server' or 'client' (positional or --mode)")

    if args.rtcp_companion:
        if mode == "server":
            sys.exit(run_rtcp_companion_server(args.bind_ip, args.rtcp_port, timeout=args.timeout, output=args.output))
        else:
            client_rtcp = args.client_rtcp_port if args.client_rtcp_port else 20001
            client_rtp = args.client_rtp_port if args.client_rtp_port else 20000
            sys.exit(run_rtcp_companion_client(args.server_ip, args.rtcp_port, client_rtcp_port=client_rtcp, client_rtp_port=client_rtp, timeout=args.timeout))

    if mode == "server":
        sys.exit(run_server(args.bind_ip, args.rtp_port, args.rtcp_port, timeout=args.timeout, output=args.output))
    else:
        client_rtp = args.client_rtp_port if args.client_rtp_port else args.client_base_port
        client_rtcp = args.client_rtcp_port if args.client_rtcp_port else (client_rtp + 1)
        sys.exit(run_client(args.server_ip, args.rtp_port, args.rtcp_port, 
                            client_rtp_port=client_rtp, client_rtcp_port=client_rtcp, timeout=args.timeout, output=args.output))

if __name__ == "__main__":
    main()
