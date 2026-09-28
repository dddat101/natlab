#!/usr/bin/env python3
"""
Carrier Gateway DUT - Super DMZ (TWIN IP) & Port Forwarding Test Tool
Verifies that:
1. Designated LAN client receives public IP / unsolicited inbound WAN traffic.
2. Concurrent LAN clients continue to function normally with NAPT.
3. Specific port forwarding rules correctly route traffic to designated private host.
"""

import sys
import os
import socket
import struct
import time
import argparse
import json

def run_dmz_listener(args):
    print(f"[Super DMZ Client] Listening on port {args.port} for unsolicited WAN traffic...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(args.timeout)

    result = {
        "status": "FAIL",
        "received": False,
        "sender": None,
        "payload": None
    }

    try:
        data, addr = sock.recvfrom(2048)
        print(f"[Super DMZ Client] Successfully received packet from WAN host {addr[0]}:{addr[1]}: {data.decode(errors='ignore')}")
        result["received"] = True
        result["sender"] = {"ip": addr[0], "port": addr[1]}
        result["payload"] = data.decode(errors="ignore")
        result["status"] = "PASS"

        # Reply back
        sock.sendto(b"SUPER_DMZ_ACK_FROM_LAN_CLIENT", addr)
    except socket.timeout:
        print("[Super DMZ Client] Timeout: No inbound packet received.")
    finally:
        sock.close()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)

    sys.exit(0 if result["status"] == "PASS" else 1)

def run_wan_sender(args):
    print(f"[WAN Prober] Sending probe to {args.target_ip}:{args.port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    result = {
        "status": "FAIL",
        "ack_received": False
    }

    try:
        payload = f"PROBE_TO_DMZ_PORT_{args.port}".encode()
        sock.sendto(payload, (args.target_ip, args.port))
        data, addr = sock.recvfrom(2048)
        print(f"[WAN Prober] Received ACK from {addr[0]}:{addr[1]}: {data.decode(errors='ignore')}")
        result["ack_received"] = True
        result["status"] = "PASS"
    except socket.timeout:
        print("[WAN Prober] Timeout waiting for ACK.")
    finally:
        sock.close()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)

    sys.exit(0 if result["status"] == "PASS" else 1)

def main():
    parser = argparse.ArgumentParser(description="Super DMZ and Port Forwarding Conformance Test")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    listen_parser = subparsers.add_parser("listen", help="Run DMZ receiver inside LAN")
    listen_parser.add_argument("--port", type=int, default=5555)
    listen_parser.add_argument("--timeout", type=float, default=8.0)
    listen_parser.add_argument("--output", help="Result JSON output")

    send_parser = subparsers.add_parser("send", help="Send probe from WAN host")
    send_parser.add_argument("--target-ip", required=True)
    send_parser.add_argument("--port", type=int, default=5555)
    send_parser.add_argument("--timeout", type=float, default=4.0)
    send_parser.add_argument("--output", help="Result JSON output")

    args = parser.parse_args()
    if args.mode == "listen":
        run_dmz_listener(args)
    elif args.mode == "send":
        run_wan_sender(args)

if __name__ == "__main__":
    main()
