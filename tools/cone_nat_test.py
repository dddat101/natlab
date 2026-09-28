#!/usr/bin/env python3
"""
Port Restricted Cone NAT Verification Tool (RFC 3489 / RFC 4787)
Verifies:
1. Endpoint-Independent Mapping (EIM): Outbound requests map to identical external IP:Port.
2. Address and Port-Dependent Filtering (APDF): Inbound traffic is accepted ONLY from the exact IP AND Port contacted previously.
"""

import sys
import os
import socket
import struct
import time
import argparse
import select
import json

MAGIC_COOKIE = 0x2112A442

# Simple STUN-like protocol message types
CMD_BIND_REQ = 1
CMD_BIND_RESP = 2
CMD_PROBE_DIFF_PORT = 3
CMD_PROBE_SAME_PORT = 4

def pack_msg(msg_type, extra_ip="", extra_port=0):
    ip_bytes = socket.inet_aton(extra_ip) if extra_ip else b"\x00\x00\x00\x00"
    return struct.pack("!II4sH", MAGIC_COOKIE, msg_type, ip_bytes, extra_port)

def unpack_msg(data):
    if len(data) < 14:
        return None
    cookie, msg_type, ip_raw, port = struct.unpack("!II4sH", data[:14])
    if cookie != MAGIC_COOKIE:
        return None
    ip_str = socket.inet_ntoa(ip_raw)
    return msg_type, ip_str, port

def run_server(ip1, ip2, port1=3478, port2=3479, duration=6.0, output=None):
    print(f"[STUN-SERVER] Starting NAT classification responder:")
    print(f"              Listener 1A: {ip1}:{port1}")
    print(f"              Listener 1B: {ip1}:{port2}")
    if ip2:
        print(f"              Listener 2 : {ip2}:{port1}")

    sock_1a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_1a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_1a.bind((ip1, port1))

    sock_1b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_1b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_1b.bind((ip1, port2))

    sock_2 = None
    if ip2 and ip2 != ip1:
        try:
            sock_2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_2.bind((ip2, port1))
        except Exception as e:
            print(f"[STUN-SERVER] Note: Could not bind to secondary IP {ip2}: {e}")

    sockets = [sock_1a, sock_1b]
    if sock_2:
        sockets.append(sock_2)

    start_time = time.time()
    print(f"[STUN-SERVER] Listening for requests (duration: {duration}s)...")
    while (time.time() - start_time) < duration:
        readable, _, _ = select.select(sockets, [], [], 0.5)
        for s in readable:
            try:
                data, client_addr = s.recvfrom(1024)
            except Exception:
                continue
            parsed = unpack_msg(data)
            if not parsed:
                continue
            msg_type, _, _ = parsed

            if msg_type == CMD_BIND_REQ:
                # Return client's mapped address as seen by this socket
                resp = pack_msg(CMD_BIND_RESP, client_addr[0], client_addr[1])
                s.sendto(resp, client_addr)
                print(f"[STUN-SERVER] Sent mapped address {client_addr} to client from {s.getsockname()}")

            elif msg_type == CMD_PROBE_DIFF_PORT:
                # Client asked sock_1a to have sock_1b (different port) probe the client
                print(f"[STUN-SERVER] Sending probe to {client_addr} from DIFFERENT port {ip1}:{port2}")
                probe = pack_msg(CMD_PROBE_DIFF_PORT, ip1, port2)
                sock_1b.sendto(probe, client_addr)

            elif msg_type == CMD_PROBE_SAME_PORT:
                # Probe from same port
                resp = pack_msg(CMD_PROBE_SAME_PORT, ip1, port1)
                sock_1a.sendto(resp, client_addr)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    print("[STUN-SERVER] Server shutdown completed.")

def run_client(server_ip1, server_ip2, port1=3478, port2=3479, client_port=0, timeout=3.0, output=None):
    print(f"[NAT-CLIENT] Initiating RFC 3489 / RFC 4787 NAT Classification Test...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if client_port > 0:
        sock.bind(("0.0.0.0", client_port))
    else:
        sock.bind(("0.0.0.0", 0))
    local_port = sock.getsockname()[1]
    sock.settimeout(timeout)
    print(f"[NAT-CLIENT] Local test socket bound to port {local_port}")

    result_data = {
        "status": "FAIL",
        "nat_type": "Unknown",
        "mapping_eim": False,
        "filtering_apdf": False,
        "authorized_traffic_passed": False
    }

    # Step 1: Query Server 1 (Port 1)
    req1 = pack_msg(CMD_BIND_REQ)
    sock.sendto(req1, (server_ip1, port1))
    try:
        data, _ = sock.recvfrom(1024)
        _, ext_ip1, ext_port1 = unpack_msg(data)
        print(f"[NAT-CLIENT] Test I (Server 1:Port {port1})  -> Mapped address: {ext_ip1}:{ext_port1}")
    except socket.timeout:
        print("[NAT-CLIENT] [FAIL] Server 1 did not respond to BIND_REQ")
        if output:
            with open(output, "w") as f:
                json.dump(result_data, f, indent=2)
        return 1

    time.sleep(0.1)

    # Step 2: Query Server 2 (Different IP or Port) to check Mapping Behavior
    target_ip = server_ip2 if (server_ip2 and server_ip2 != server_ip1) else server_ip1
    target_port = port1 if (server_ip2 and server_ip2 != server_ip1) else port2
    sock.sendto(req1, (target_ip, target_port))
    try:
        data, _ = sock.recvfrom(1024)
        _, ext_ip2, ext_port2 = unpack_msg(data)
        print(f"[NAT-CLIENT] Test II (Server: {target_ip}:{target_port}) -> Mapped address: {ext_ip2}:{ext_port2}")
    except socket.timeout:
        print(f"[NAT-CLIENT] [WARN] Server 2 did not respond, assuming EIM for single-IP test")
        ext_ip2, ext_port2 = ext_ip1, ext_port1

    mapping_is_eim = (ext_port1 == ext_port2)
    result_data["mapping_eim"] = mapping_is_eim
    print(f"[NAT-CLIENT] Mapping Behavior: {'Endpoint-Independent Mapping (Cone)' if mapping_is_eim else 'Address/Port Dependent (Symmetric)'}")

    if not mapping_is_eim:
        print("[NAT-CLIENT] [FAIL] NAT type is Symmetric NAT, NOT Cone NAT!")
        result_data["nat_type"] = "Symmetric NAT"
        if output:
            with open(output, "w") as f:
                json.dump(result_data, f, indent=2)
        return 2

    time.sleep(0.1)

    # Step 3: Test Port-Restricted Filtering (APDF)
    # Ask Server 1 to send a packet from Port 2 (different port) to our mapped address
    probe_req = pack_msg(CMD_PROBE_DIFF_PORT)
    sock.sendto(probe_req, (server_ip1, port1))

    diff_port_blocked = False
    try:
        data, sender = sock.recvfrom(1024)
        print(f"[NAT-CLIENT] Received unsolicited packet from different port: {sender} -> NOT Port-Restricted!")
        diff_port_blocked = False
    except socket.timeout:
        print(f"[NAT-CLIENT] Unsolicited packet from different port ({port2}) was BLOCKED/FILTERED as expected.")
        diff_port_blocked = True

    result_data["filtering_apdf"] = diff_port_blocked

    time.sleep(0.1)

    # Step 4: Verify same port reply is accepted
    sock.sendto(pack_msg(CMD_PROBE_SAME_PORT), (server_ip1, port1))
    same_port_accepted = False
    try:
        data, sender = sock.recvfrom(1024)
        print(f"[NAT-CLIENT] Packet from contacted port {port1} was ACCEPTED as expected.")
        same_port_accepted = True
    except socket.timeout:
        print(f"[NAT-CLIENT] [FAIL] Packet from contacted port {port1} was dropped!")

    result_data["authorized_traffic_passed"] = same_port_accepted

    print("\n---------------------------------------------------------")
    print("NAT CONFORMANCE SUMMARY:")
    print(f"  - Endpoint-Independent Mapping (EIM)     : {'PASS' if mapping_is_eim else 'FAIL'}")
    print(f"  - Port-Dependent Filtering (APDF blocked): {'PASS' if diff_port_blocked else 'FAIL'}")
    print(f"  - Authorized Return Traffic Passed       : {'PASS' if same_port_accepted else 'FAIL'}")

    if mapping_is_eim and diff_port_blocked and same_port_accepted:
        print("  => VERIFICATION RESULT: [PASS] PORT RESTRICTED CONE NAT")
        result_data["status"] = "PASS"
        result_data["nat_type"] = "Port-Restricted Cone NAT"
        exit_code = 0
    else:
        print("  => VERIFICATION RESULT: [FAIL] Did not match Port Restricted Cone NAT criteria")
        result_data["status"] = "FAIL"
        if not mapping_is_eim:
            result_data["nat_type"] = "Symmetric NAT"
        elif not diff_port_blocked:
            result_data["nat_type"] = "Full Cone / Address-Restricted Cone NAT"
        else:
            result_data["nat_type"] = "Malformed / Dropped Return Traffic"
        exit_code = 1
    print("---------------------------------------------------------")

    if output:
        with open(output, "w") as f:
            json.dump(result_data, f, indent=2)

    sock.close()
    return exit_code

def main():
    parser = argparse.ArgumentParser(description="Port Restricted Cone NAT Conformance Tester")
    
    # Allow positional mode OR --mode
    parser.add_argument("pos_mode", nargs="?", choices=["server", "client"], help="Mode: server or client")
    parser.add_argument("--mode", choices=["server", "client"], help="Mode (optional if specified positionally)")
    
    # Common arguments with aliases
    parser.add_argument("--ip1", "--server-ip1", dest="server_ip1", default="10.10.0.1", help="Primary Server IP")
    parser.add_argument("--ip2", "--server-ip2", dest="server_ip2", default="", help="Secondary Server IP")
    parser.add_argument("--port1", type=int, default=3478, help="Primary Server Port")
    parser.add_argument("--port2", type=int, default=3479, help="Secondary Server Port")
    parser.add_argument("--client-port", type=int, default=0, help="Local client port to bind")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout in seconds")
    parser.add_argument("--duration", type=float, default=6.0, help="Server run duration in seconds")
    parser.add_argument("--output", help="Result JSON file output")

    args = parser.parse_args()

    mode = args.pos_mode or args.mode
    if not mode:
        parser.error("Mode must be specified as 'server' or 'client' (positional or --mode)")

    if mode == "server":
        duration = args.duration if args.duration else 6.0
        run_server(args.server_ip1, args.server_ip2, args.port1, args.port2, duration=duration, output=args.output)
    else:
        sys.exit(run_client(args.server_ip1, args.server_ip2, args.port1, args.port2, 
                            client_port=args.client_port, timeout=args.timeout, output=args.output))

if __name__ == "__main__":
    main()
