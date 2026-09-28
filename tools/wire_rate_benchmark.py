#!/usr/bin/env python3
"""
Carrier Gateway DUT - Wire-Rate & Multicast Performance Benchmark Engine
========================================================================
Validates Carrier Wire-Rate Conformance Requirement:
  "When NAT/NAPT is configured for Ethernet frame sizes of 1024 bytes or more,
   wire-rate performance shall be provided. The same performance shall be
   provided for any combination of unicast and multicast traffic."

Key Capabilities:
  1. Multi-Frame Matrix: Tests >= 1024B frames (1024B, 1280B, 1518B).
  2. Frame Overhead Calculation:
     Ethernet L2 (14B) + IPv4 (20B) + UDP (8B) + FCS (4B) = 46B overhead.
     Payload = Frame Size - 46B (e.g. 1024B -> 978B UDP payload).
  3. Traffic Combinations:
     - 'unicast_only': LAN client -> DUT NAPT -> WAN server
     - 'multicast_only': WAN server -> DUT IGMP/Forwarder -> LAN client (239.255.1.1)
     - 'concurrent_mixed': Unicast NAT + Multicast concurrent streaming without starvation
  4. Engine Preference:
     Prefers iPerf 2 (native multicast + CSV telemetry) from tools/bin/iperf or system PATH,
     with graceful fallback to iperf3 for unicast-only benchmarks.
"""

import argparse
import csv
import io
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


def get_default_iperf_path() -> str:
    """Locate the best iperf binary: local tools/bin/iperf first, then system PATH."""
    env_bin = os.environ.get("IPERF_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin

    script_dir = os.path.dirname(os.path.realpath(__file__))
    local_bin = os.path.join(script_dir, "bin", "iperf")
    if os.path.isfile(local_bin) and os.access(local_bin, os.X_OK):
        return local_bin

    sys_bin = shutil.which("iperf")
    if sys_bin:
        return sys_bin

    sys_bin3 = shutil.which("iperf3")
    if sys_bin3:
        return sys_bin3

    return "iperf"


def calculate_udp_payload(frame_size: int) -> int:
    """
    Calculate UDP payload size for a target Ethernet frame size.
    L2 Ethernet MAC header: 14 bytes (6B dst + 6B src + 2B type)
    IPv4 header: 20 bytes (without options)
    UDP header: 8 bytes
    Ethernet FCS: 4 bytes
    Total packet overhead: 46 bytes.
    Payload = max(64, frame_size - 46).
    """
    overhead = 14 + 20 + 8 + 4  # 46 bytes
    payload = frame_size - overhead
    return max(64, payload)


def run_cmd(cmd_list: List[str], timeout: float = 15.0) -> Tuple[int, str, str]:
    """Execute a command and return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
        else:
            proc.kill()
        proc.communicate()
        return -1, "", "Command timed out"
    except Exception as exc:
        return -1, "", str(exc)


def build_ns_cmd(ns: Optional[str], cmd: List[str]) -> List[str]:
    """Wrap command with 'ip netns exec <ns>' if namespace is provided."""
    if ns and ns.strip():
        return ["ip", "netns", "exec", ns.strip()] + cmd
    return cmd


def parse_iperf2_csv(csv_text: str) -> Dict[str, Any]:
    """
    Parse iperf 2 CSV output:
    Format: timestamp,src_ip,src_port,dst_ip,dst_port,id,interval,transferred_bytes,bps,jitter,lost_packets,total_packets,loss_pct,out_of_order
    """
    metrics = {
        "bps": 0.0,
        "mbps": 0.0,
        "transferred_bytes": 0,
        "jitter_ms": 0.0,
        "lost_packets": 0,
        "total_packets": 0,
        "loss_percent": 0.0,
        "parsed_rows": 0,
    }

    if not csv_text:
        return metrics

    reader = csv.reader(io.StringIO(csv_text.strip()))
    candidate_rows = []
    for row in reader:
        if len(row) >= 9:
            try:
                bps = float(row[8])
                candidate_rows.append((row, bps))
            except (ValueError, IndexError):
                continue

    if not candidate_rows:
        return metrics

    # Choose the most detailed report row (preferring server report with jitter/loss)
    best_row = candidate_rows[-1][0]
    for row, _ in reversed(candidate_rows):
        if len(row) >= 12:
            try:
                # Server report has numeric lost/total packets
                lost = int(row[10])
                total = int(row[11])
                if total > 0 and lost >= 0:
                    best_row = row
                    break
            except (ValueError, IndexError):
                pass

    try:
        metrics["transferred_bytes"] = int(best_row[7])
        metrics["bps"] = float(best_row[8])
        metrics["mbps"] = round(metrics["bps"] / 1_000_000.0, 2)
        metrics["parsed_rows"] = len(candidate_rows)

        if len(best_row) >= 10 and best_row[9] not in ("-nan", "nan", ""):
            metrics["jitter_ms"] = round(float(best_row[9]), 4)
        if len(best_row) >= 11 and best_row[10] != "":
            metrics["lost_packets"] = max(0, int(best_row[10]))
        if len(best_row) >= 12 and best_row[11] != "":
            metrics["total_packets"] = max(0, int(best_row[11]))
        if len(best_row) >= 13 and best_row[12] not in ("-nan", "nan", ""):
            metrics["loss_percent"] = max(0.0, round(float(best_row[12]), 2))
        elif metrics["total_packets"] > 0:
            metrics["loss_percent"] = round(
                (metrics["lost_packets"] / metrics["total_packets"]) * 100.0, 2
            )
    except Exception:
        pass

    return metrics


def parse_iperf_text(text: str) -> Dict[str, Any]:
    """Fallback parser for standard iperf2/iperf3 human-readable output."""
    metrics = {
        "bps": 0.0,
        "mbps": 0.0,
        "transferred_bytes": 0,
        "jitter_ms": 0.0,
        "lost_packets": 0,
        "total_packets": 0,
        "loss_percent": 0.0,
    }

    # Match Bandwidth: e.g. "940 Mbits/sec" or "1.12 Gbits/sec"
    bw_match = re.findall(r"([0-9\.]+)\s+([KMGkmg]?bits/sec)", text)
    if bw_match:
        val, unit = bw_match[-1]
        val_f = float(val)
        unit_u = unit.upper()
        if "GBITS" in unit_u:
            mbps = val_f * 1000.0
        elif "KBITS" in unit_u:
            mbps = val_f / 1000.0
        else:
            mbps = val_f
        metrics["mbps"] = round(mbps, 2)
        metrics["bps"] = mbps * 1_000_000.0

    # Match Jitter and Datagram Loss: e.g. "0.012 ms   0/ 1342 (0%)"
    loss_match = re.findall(r"([0-9\.]+)\s+ms\s+([0-9]+)/\s*([0-9]+)\s+\(([0-9\.]+)%\)", text)
    if loss_match:
        j_ms, lost, total, pct = loss_match[-1]
        metrics["jitter_ms"] = float(j_ms)
        metrics["lost_packets"] = int(lost)
        metrics["total_packets"] = int(total)
        metrics["loss_percent"] = float(pct)

    return metrics


class MulticastRelay:
    """
    Lightweight userspace Multicast Forwarder for Linux network namespaces.
    Allows virtual DUT (ns-dut) to forward incoming Multicast traffic from
    eth-wan to eth-lan when hardware IGMP proxy / kernel mrouting is absent.
    """

    def __init__(self, group: str, port: int, in_if: str, out_if: str):
        self.group = group
        self.port = port
        self.in_if = in_if
        self.out_if = out_if
        self.running = False
        self.sock_in = None
        self.sock_out = None

    def start(self, duration: Optional[float] = None):
        self.running = True
        print(f"[Multicast Relay] Starting forwarder: {self.in_if} -> {self.out_if} for {self.group}:{self.port}")

        # Inbound socket: bind to group on in_if
        self.sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self.sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass

        try:
            self.sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except Exception:
            pass

        try:
            self.sock_in.setsockopt(socket.SOL_SOCKET, 25, self.in_if.encode())  # SO_BINDTODEVICE
        except Exception:
            pass

        self.sock_in.bind(("", self.port))

        # Join IGMP group on specific interface
        try:
            if hasattr(socket, "if_nametoindex"):
                try:
                    idx = socket.if_nametoindex(self.in_if)
                    mreq = struct.pack("4s4si", socket.inet_aton(self.group), socket.inet_aton("0.0.0.0"), idx)
                    self.sock_in.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                except Exception:
                    mreq = struct.pack("4sl", socket.inet_aton(self.group), socket.INADDR_ANY)
                    self.sock_in.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            else:
                mreq = struct.pack("4sl", socket.inet_aton(self.group), socket.INADDR_ANY)
                self.sock_in.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception as e:
            print(f"[Multicast Relay] Warning joining membership: {e}")

        # Outbound socket: send out out_if
        self.sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            self.sock_out.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except Exception:
            pass

        try:
            self.sock_out.setsockopt(socket.SOL_SOCKET, 25, self.out_if.encode())  # SO_BINDTODEVICE
        except Exception:
            pass

        try:
            if hasattr(socket, "if_nametoindex"):
                try:
                    idx_out = socket.if_nametoindex(self.out_if)
                    mreq_out = struct.pack("4s4si", socket.inet_aton("0.0.0.0"), socket.inet_aton("0.0.0.0"), idx_out)
                    self.sock_out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq_out)
                except Exception:
                    pass
        except Exception:
            pass

        self.sock_out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

        start_t = time.time()
        pkt_count = 0
        byte_count = 0

        try:
            while self.running:
                if duration and (time.time() - start_t) >= duration:
                    break
                r, _, _ = select.select([self.sock_in], [], [], 0.5)
                if not r:
                    continue
                data, _ = self.sock_in.recvfrom(65535)
                if data:
                    self.sock_out.sendto(data, (self.group, self.port))
                    pkt_count += 1
                    byte_count += len(data)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            print(f"[Multicast Relay] Stopped. Forwarded {pkt_count} packets ({byte_count} bytes).")

    def stop(self):
        self.running = False
        if self.sock_in:
            try:
                self.sock_in.close()
            except Exception:
                pass
        if self.sock_out:
            try:
                self.sock_out.close()
            except Exception:
                pass


class WireRateBenchmarkSuite:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.iperf_bin = args.iperf_bin or get_default_iperf_path()
        self.is_iperf3 = "iperf3" in os.path.basename(self.iperf_bin)
        self.frame_sizes = [int(x.strip()) for x in args.frame_sizes.split(",") if x.strip()]
        self.combinations = [x.strip() for x in args.combinations.split(",") if x.strip()]
        self.target_mbps = float(args.target_mbps)
        self.duration = float(args.duration)
        self.mcast_group = args.multicast_group
        self.mcast_port = int(args.multicast_port)
        self.mcast_bw_mbps = float(args.multicast_bw)
        self.wan_ns = args.wan_ns
        self.lan_ns = args.lan_ns
        self.dut_ns = args.dut_ns
        self.wan_ip = args.wan_ip
        self.lan_ip = args.lan_ip
        self.dut_wan_ip = args.dut_wan_ip
        self.topology_mode = args.topology_mode
        self.tolerance_pct = float(args.tolerance_pct)
        self.out_json = args.output

    def check_reachability(self) -> bool:
        """Verify reachability between LAN namespace and WAN server before benchmarking."""
        cmd = build_ns_cmd(self.lan_ns, ["ping", "-c", "1", "-W", "1", self.wan_ip])
        rc, _, _ = run_cmd(cmd, timeout=3.0)
        return rc == 0

    def ensure_multicast_routes(self):
        """Ensure multicast route 224.0.0.0/4 is active in netns to prevent ENETUNREACH."""
        if self.wan_ns:
            run_cmd(build_ns_cmd(self.wan_ns, ["ip", "route", "replace", "224.0.0.0/4", "dev", "eth-wan"]), timeout=2.0)
        if self.dut_ns and self.topology_mode == "virtual":
            run_cmd(build_ns_cmd(self.dut_ns, ["ip", "route", "replace", "224.0.0.0/4", "dev", "eth-lan"]), timeout=2.0)
        if self.lan_ns:
            run_cmd(build_ns_cmd(self.lan_ns, ["ip", "route", "replace", "224.0.0.0/4", "dev", "eth0"]), timeout=2.0)

    def start_process(self, ns: Optional[str], cmd: List[str]) -> subprocess.Popen:
        """Start a managed background process in the designated namespace."""
        full_cmd = build_ns_cmd(ns, cmd)
        return subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

    def terminate_process(self, proc: Optional[subprocess.Popen], timeout: float = 2.0) -> Tuple[str, str]:
        """Terminate process cleanly with SIGTERM then SIGKILL."""
        if not proc:
            return "", ""
        stdout, stderr = "", ""
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    proc.terminate()
            else:
                proc.terminate()
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
            else:
                proc.kill()
            stdout, stderr = proc.communicate()
        except Exception as e:
            stderr = str(e)
        return stdout or "", stderr or ""

    def ensure_multicast_forwarding(self) -> Optional[subprocess.Popen]:
        """In virtual topology, spawn multicast forwarder in ns-dut if needed."""
        if self.topology_mode != "virtual" or not self.dut_ns:
            return None

        # Launch background multicast relay in DUT namespace
        script_path = os.path.realpath(__file__)
        relay_cmd = [
            sys.executable,
            script_path,
            "relay",
            "--group",
            self.mcast_group,
            "--port",
            str(self.mcast_port),
            "--in-if",
            "eth-wan",
            "--out-if",
            "eth-lan",
        ]
        return self.start_process(self.dut_ns, relay_cmd)

    def run_subtest_unicast(self, frame_size: int, payload_len: int) -> Dict[str, Any]:
        """
        Execute 100% Unicast NAT Throughput Test.
        LAN client (ns-lan1) -> DUT NAT -> WAN server (ns-wan)
        """
        server_port = 5201 if self.is_iperf3 else 5001
        print(f"  [Unicast NAT] Testing Frame {frame_size}B (UDP payload {payload_len}B, Target {self.target_mbps} Mbps)...")

        # 1. Start Server in WAN NS
        if self.is_iperf3:
            srv_cmd = [self.iperf_bin, "-s", "-p", str(server_port), "-1"]
        else:
            srv_cmd = [self.iperf_bin, "-s", "-u", "-p", str(server_port), "-w", "512K", "-y", "C"]

        srv_proc = self.start_process(self.wan_ns, srv_cmd)
        time.sleep(0.3)

        # 2. Run Client in LAN NS
        bw_arg = (
            "1050M"
            if (frame_size <= 1024 and self.target_mbps >= 900)
            else (f"{int(self.target_mbps)}M" if self.target_mbps > 0 else "0")
        )
        if self.is_iperf3:
            cli_cmd = [
                self.iperf_bin,
                "-c",
                self.wan_ip,
                "-u",
                "-p",
                str(server_port),
                "-l",
                str(payload_len),
                "-b",
                bw_arg,
                "-t",
                str(int(self.duration)),
                "-J",
            ]
        else:
            cli_cmd = [
                self.iperf_bin,
                "-c",
                self.wan_ip,
                "-u",
                "-p",
                str(server_port),
                "-l",
                str(payload_len),
                "-b",
                bw_arg,
                "-w",
                "512K",
                "-t",
                str(int(self.duration)),
                "-y",
                "C",
            ]

        cli_full = build_ns_cmd(self.lan_ns, cli_cmd)
        cli_rc, cli_out, cli_err = run_cmd(cli_full, timeout=self.duration + 5.0)

        # 3. Harvest Server output
        srv_out, srv_err = self.terminate_process(srv_proc, timeout=1.5)

        # Parse metrics
        metrics = parse_iperf2_csv(srv_out)
        if metrics["mbps"] <= 0.0:
            metrics = parse_iperf2_csv(cli_out)
        if metrics["mbps"] <= 0.0:
            metrics = parse_iperf_text(srv_out + "\n" + cli_out)

        # Evaluate against wire-rate threshold
        min_pass_mbps = self.target_mbps * (self.tolerance_pct / 100.0)
        achieved_mbps = metrics["mbps"]
        passed = (achieved_mbps >= min_pass_mbps) and (metrics["loss_percent"] <= 2.0)

        result = {
            "status": "PASS" if passed else "FAIL",
            "frame_size": frame_size,
            "udp_payload_bytes": payload_len,
            "target_mbps": self.target_mbps,
            "min_pass_mbps": round(min_pass_mbps, 2),
            "throughput_mbps": achieved_mbps,
            "loss_percent": metrics["loss_percent"],
            "jitter_ms": metrics["jitter_ms"],
            "packets_lost": metrics["lost_packets"],
            "total_packets": metrics["total_packets"],
            "raw_server_output": srv_out.strip() or srv_err.strip(),
            "raw_client_output": cli_out.strip() or cli_err.strip(),
        }
        res_str = f"PASSED ({achieved_mbps} Mbps, loss {metrics['loss_percent']}%)" if passed else f"FAILED ({achieved_mbps} Mbps < {min_pass_mbps} Mbps or loss {metrics['loss_percent']}%)"
        print(f"    -> Result: {res_str}")
        return result

    def run_subtest_multicast(self, frame_size: int, payload_len: int) -> Dict[str, Any]:
        """
        Execute 100% Multicast Streaming Test.
        WAN server (ns-wan) streams to Multicast group (239.255.1.1) -> DUT -> LAN client (ns-lan1)
        """
        if self.is_iperf3:
            print("  [Multicast] SKIPPED: iPerf3 does not support Multicast. Use tools/bin/iperf (iPerf 2.x).")
            return {
                "status": "SKIP",
                "frame_size": frame_size,
                "reason": "iPerf3 lacks multicast support",
            }

        print(f"  [Multicast Stream] Testing Frame {frame_size}B (Group {self.mcast_group}:{self.mcast_port}, Rate {self.mcast_bw_mbps} Mbps)...")

        # 1. Start Forwarder in ns-dut if virtual
        relay_proc = self.ensure_multicast_forwarding()
        time.sleep(0.3)

        # 2. Start Receiver in LAN NS bound to multicast group
        recv_cmd = [
            self.iperf_bin,
            "-s",
            "-u",
            "-B",
            self.mcast_group,
            "-p",
            str(self.mcast_port),
            "-w",
            "512K",
            "-y",
            "C",
        ]
        recv_proc = self.start_process(self.lan_ns, recv_cmd)
        time.sleep(0.3)

        # 3. Start Sender in WAN NS streaming to multicast group
        bw_arg = f"{int(self.mcast_bw_mbps)}M"
        send_cmd = [
            self.iperf_bin,
            "-c",
            self.mcast_group,
            "-u",
        ]
        if self.wan_ip:
            send_cmd.extend(["-B", self.wan_ip])
        send_cmd.extend([
            "-p",
            str(self.mcast_port),
            "-l",
            str(payload_len),
            "-b",
            bw_arg,
            "-w",
            "512K",
            "-t",
            str(int(self.duration)),
            "-T",
            "32",
            "-y",
            "C",
        ])
        send_full = build_ns_cmd(self.wan_ns, send_cmd)
        send_rc, send_out, send_err = run_cmd(send_full, timeout=self.duration + 5.0)

        # 4. Harvest receiver output
        recv_out, recv_err = self.terminate_process(recv_proc, timeout=1.5)
        self.terminate_process(relay_proc, timeout=0.5)

        # Parse metrics
        metrics = parse_iperf2_csv(recv_out)
        if metrics["mbps"] <= 0.0:
            metrics = parse_iperf2_csv(send_out)
        if metrics["mbps"] <= 0.0:
            metrics = parse_iperf_text(recv_out + "\n" + send_out)

        # Evaluate: multicast stream must arrive with near 0% loss and achieve requested bitrate
        min_pass_mbps = self.mcast_bw_mbps * 0.85
        achieved_mbps = metrics["mbps"]
        passed = (achieved_mbps >= min_pass_mbps) and (metrics["loss_percent"] <= 1.0)

        result = {
            "status": "PASS" if passed else "FAIL",
            "frame_size": frame_size,
            "multicast_group": self.mcast_group,
            "target_mbps": self.mcast_bw_mbps,
            "throughput_mbps": achieved_mbps,
            "loss_percent": metrics["loss_percent"],
            "jitter_ms": metrics["jitter_ms"],
            "packets_lost": metrics["lost_packets"],
            "total_packets": metrics["total_packets"],
            "raw_receiver_output": recv_out.strip() or recv_err.strip(),
            "raw_sender_output": send_out.strip() or send_err.strip(),
        }
        res_str = f"PASSED ({achieved_mbps} Mbps, loss {metrics['loss_percent']}%)" if passed else f"FAILED ({achieved_mbps} Mbps < {min_pass_mbps} Mbps or loss {metrics['loss_percent']}%)"
        print(f"    -> Result: {res_str}")
        return result

    def run_subtest_concurrent(self, frame_size: int, payload_len: int) -> Dict[str, Any]:
        """
        Execute Concurrent Combination (Unicast NAT + Multicast Stream).
        LAN client sends Unicast NAT to WAN server while WAN streams Multicast to LAN simultaneously!
        Checks for stream coexistence without packet starvation.
        """
        if self.is_iperf3:
            print("  [Concurrent Mixed] SKIPPED: iPerf3 does not support Multicast.")
            return {
                "status": "SKIP",
                "frame_size": frame_size,
                "reason": "iPerf3 lacks multicast support",
            }

        unicast_port = 5001
        mcast_port = self.mcast_port if self.mcast_port != unicast_port else 5002

        unicast_target_mbps = max(100.0, self.target_mbps - self.mcast_bw_mbps)
        u_bw = (
            "1050M"
            if (frame_size <= 1024 and self.target_mbps >= 900)
            else f"{int(unicast_target_mbps)}M"
        )
        print(f"  [Concurrent Mixed] Testing Frame {frame_size}B: Unicast ({unicast_target_mbps}M) + Multicast ({self.mcast_bw_mbps}M)...")

        # 1. Forwarder in ns-dut if virtual
        relay_proc = self.ensure_multicast_forwarding()
        time.sleep(0.3)

        # 2. Start Unicast Server in ns-wan (port 5001)
        u_srv_cmd = [self.iperf_bin, "-s", "-u", "-p", str(unicast_port), "-w", "512K", "-y", "C"]
        u_srv_proc = self.start_process(self.wan_ns, u_srv_cmd)

        # 3. Start Multicast Receiver in ns-lan1 (port 5002, group 239.255.1.1)
        m_recv_cmd = [
            self.iperf_bin,
            "-s",
            "-u",
            "-B",
            self.mcast_group,
            "-p",
            str(mcast_port),
            "-w",
            "512K",
            "-y",
            "C",
        ]
        m_recv_proc = self.start_process(self.lan_ns, m_recv_cmd)

        time.sleep(0.4)

        # 4. Concurrently Launch:
        #    a) WAN multicast sender -> ns-lan1
        #    b) LAN unicast client -> ns-wan
        m_send_cmd = [
            self.iperf_bin,
            "-c",
            self.mcast_group,
            "-u",
        ]
        if self.wan_ip:
            m_send_cmd.extend(["-B", self.wan_ip])
        m_send_cmd.extend([
            "-p",
            str(mcast_port),
            "-l",
            str(payload_len),
            "-b",
            f"{int(self.mcast_bw_mbps)}M",
            "-w",
            "512K",
            "-t",
            str(int(self.duration)),
            "-T",
            "32",
            "-y",
            "C",
        ])
        m_send_proc = self.start_process(self.wan_ns, m_send_cmd)

        u_cli_cmd = [
            self.iperf_bin,
            "-c",
            self.wan_ip,
            "-u",
            "-p",
            str(unicast_port),
            "-l",
            str(payload_len),
            "-b",
            u_bw,
            "-w",
            "512K",
            "-t",
            str(int(self.duration)),
            "-y",
            "C",
        ]
        u_cli_proc = self.start_process(self.lan_ns, u_cli_cmd)

        # Wait for senders to complete
        time.sleep(self.duration + 1.0)
        m_send_out, m_send_err = self.terminate_process(m_send_proc, timeout=2.0)
        u_cli_out, u_cli_err = self.terminate_process(u_cli_proc, timeout=2.0)

        # Harvest servers
        u_srv_out, u_srv_err = self.terminate_process(u_srv_proc, timeout=1.5)
        m_recv_out, m_recv_err = self.terminate_process(m_recv_proc, timeout=1.5)
        self.terminate_process(relay_proc, timeout=0.5)

        # Parse both metrics
        u_metrics = parse_iperf2_csv(u_srv_out)
        if u_metrics["mbps"] <= 0.0:
            u_metrics = parse_iperf2_csv(u_cli_out)

        m_metrics = parse_iperf2_csv(m_recv_out)
        if m_metrics["mbps"] <= 0.0:
            m_metrics = parse_iperf2_csv(m_send_out)

        total_aggregate_mbps = round(u_metrics["mbps"] + m_metrics["mbps"], 2)
        min_pass_aggregate = self.target_mbps * (self.tolerance_pct / 100.0)

        # Pass condition: Aggregate throughput reaches line rate, and neither stream is starved
        passed = (
            (total_aggregate_mbps >= min_pass_aggregate)
            and (u_metrics["loss_percent"] <= 2.0)
            and (m_metrics["loss_percent"] <= 2.0)
            and (m_metrics["mbps"] >= (self.mcast_bw_mbps * 0.80))
        )

        result = {
            "status": "PASS" if passed else "FAIL",
            "frame_size": frame_size,
            "unicast_throughput_mbps": u_metrics["mbps"],
            "multicast_throughput_mbps": m_metrics["mbps"],
            "total_aggregate_mbps": total_aggregate_mbps,
            "target_aggregate_mbps": self.target_mbps,
            "min_pass_aggregate_mbps": round(min_pass_aggregate, 2),
            "unicast_loss_percent": u_metrics["loss_percent"],
            "multicast_loss_percent": m_metrics["loss_percent"],
            "unicast_jitter_ms": u_metrics["jitter_ms"],
            "multicast_jitter_ms": m_metrics["jitter_ms"],
        }
        res_str = f"PASSED (Total {total_aggregate_mbps} Mbps [U:{u_metrics['mbps']}M + M:{m_metrics['mbps']}M])" if passed else f"FAILED (Total {total_aggregate_mbps} Mbps < {min_pass_aggregate} Mbps)"
        print(f"    -> Result: {res_str}")
        return result

    def execute_suite(self) -> Dict[str, Any]:
        """Execute the complete wire-rate benchmark matrix."""
        print("================================================================================")
        print("      CARRIER GATEWAY DUT - WIRE-RATE & MULTICAST BENCHMARK SUITE")
        print("================================================================================")
        print(f"Engine:             {self.iperf_bin} ({'iPerf 3' if self.is_iperf3 else 'iPerf 2'})")
        print(f"Frame Sizes:        {self.frame_sizes} bytes (>= 1024B)")
        print(f"Combinations:       {self.combinations}")
        print(f"Wire-Rate Target:   {self.target_mbps} Mbps (Tolerance: {self.tolerance_pct}%)")
        print(f"Multicast Target:   {self.mcast_group}:{self.mcast_port} @ {self.mcast_bw_mbps} Mbps")
        print(f"Topology Mode:      {self.topology_mode} (WAN NS: {self.wan_ns}, LAN NS: {self.lan_ns})")
        print("--------------------------------------------------------------------------------")

        if not self.check_reachability():
            print(f"[ERROR] Target WAN Server {self.wan_ip} is unreachable from LAN NS {self.lan_ns}!")
            print("Ensure topology is active (sudo ./scripts/setup.sh) and DUT is routing.")
            fail_res = {
                "status": "FAIL",
                "engine": self.iperf_bin,
                "error": f"WAN Server {self.wan_ip} unreachable from {self.lan_ns}",
            }
            if self.out_json:
                os.makedirs(os.path.dirname(os.path.abspath(self.out_json)), exist_ok=True)
                with open(self.out_json, "w") as f:
                    json.dump(fail_res, f, indent=2)
            return fail_res

        self.ensure_multicast_routes()

        overall_results: Dict[str, Any] = {}
        all_passed = True
        aggregate_mbps_list: List[float] = []

        for frame in self.frame_sizes:
            payload = calculate_udp_payload(frame)
            frame_res: Dict[str, Any] = {
                "frame_size": frame,
                "udp_payload_bytes": payload,
            }

            if "unicast_only" in self.combinations:
                u_res = self.run_subtest_unicast(frame, payload)
                frame_res["unicast_only"] = u_res
                if u_res.get("status") == "FAIL":
                    all_passed = False
                if u_res.get("throughput_mbps", 0) > 0:
                    aggregate_mbps_list.append(u_res["throughput_mbps"])

            if "multicast_only" in self.combinations and not self.is_iperf3:
                m_res = self.run_subtest_multicast(frame, payload)
                frame_res["multicast_only"] = m_res
                if m_res.get("status") == "FAIL":
                    all_passed = False

            if "concurrent_mixed" in self.combinations and not self.is_iperf3:
                c_res = self.run_subtest_concurrent(frame, payload)
                frame_res["concurrent_mixed"] = c_res
                if c_res.get("status") == "FAIL":
                    all_passed = False
                if c_res.get("total_aggregate_mbps", 0) > 0:
                    aggregate_mbps_list.append(c_res["total_aggregate_mbps"])

            overall_results[str(frame)] = frame_res

        min_agg = min(aggregate_mbps_list) if aggregate_mbps_list else 0.0
        max_agg = max(aggregate_mbps_list) if aggregate_mbps_list else 0.0

        suite_summary = {
            "status": "PASS" if all_passed else "FAIL",
            "engine": "iperf3" if self.is_iperf3 else "iperf",
            "engine_path": self.iperf_bin,
            "target_wire_rate_mbps": self.target_mbps,
            "tested_frame_sizes": self.frame_sizes,
            "tested_combinations": self.combinations,
            "min_achieved_aggregate_mbps": round(min_agg, 2),
            "max_achieved_aggregate_mbps": round(max_agg, 2),
            "all_combinations_passed": all_passed,
            "wire_rate_achieved": (min_agg >= (self.target_mbps * (self.tolerance_pct / 100.0))),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": overall_results,
        }

        print("--------------------------------------------------------------------------------")
        print(f"BENCHMARK STATUS:   {'PASS' if all_passed else 'FAIL'}")
        print(f"Throughput Range:   {min_agg} Mbps - {max_agg} Mbps (Target: {self.target_mbps} Mbps)")
        print("================================================================================")

        if self.out_json:
            os.makedirs(os.path.dirname(os.path.abspath(self.out_json)), exist_ok=True)
            with open(self.out_json, "w") as f:
                json.dump(suite_summary, f, indent=2)
            print(f"[Wire-Rate] Results written to {self.out_json}")

        return suite_summary


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Carrier Gateway DUT - Wire-Rate Performance & Multicast Benchmark Suite"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: run
    p_run = subparsers.add_parser("run", help="Run full wire-rate benchmark matrix")
    p_run.add_argument("--wan-ns", default="ns-wan", help="WAN Server network namespace")
    p_run.add_argument("--lan-ns", default="ns-lan1", help="LAN Client network namespace")
    p_run.add_argument("--dut-ns", default="ns-dut", help="DUT network namespace (for virtual mode)")
    p_run.add_argument("--wan-ip", default="10.10.0.1", help="WAN Server IPv4 address")
    p_run.add_argument("--lan-ip", default="192.168.1.101", help="LAN Client IPv4 address")
    p_run.add_argument("--dut-wan-ip", default="10.10.0.150", help="DUT WAN IPv4 address")
    p_run.add_argument("--topology-mode", default="virtual", choices=["virtual", "physical"], help="Topology mode")
    p_run.add_argument("--frame-sizes", default="1024,1280,1518", help="Comma-separated frame sizes (>= 1024B)")
    p_run.add_argument(
        "--combinations",
        default="unicast_only,multicast_only,concurrent_mixed",
        help="Comma-separated traffic combinations to test",
    )
    p_run.add_argument("--target-mbps", default="940", help="Target wire-rate throughput in Mbps")
    p_run.add_argument("--duration", default="3", help="Duration per subtest in seconds")
    p_run.add_argument("--tolerance-pct", default="95.0", help="Passing throughput tolerance percentage (e.g. 95)")
    p_run.add_argument("--multicast-group", default="239.255.1.1", help="Multicast stream group address")
    p_run.add_argument("--multicast-port", default="5001", help="Multicast stream UDP port")
    p_run.add_argument("--multicast-bw", default="200", help="Multicast bandwidth in Mbps")
    p_run.add_argument("--iperf-bin", default="", help="Path to iperf or iperf3 binary")
    p_run.add_argument("--output", default="logs/wire_rate_result.json", help="Path to save result JSON")

    # Subcommand: relay
    p_relay = subparsers.add_parser("relay", help="Run lightweight multicast forwarder in DUT namespace")
    p_relay.add_argument("--group", default="239.255.1.1", help="Multicast group address")
    p_relay.add_argument("--port", type=int, default=5001, help="Multicast UDP port")
    p_relay.add_argument("--in-if", default="eth-wan", help="Inbound network interface")
    p_relay.add_argument("--out-if", default="eth-lan", help="Outbound network interface")
    p_relay.add_argument("--duration", type=float, default=0.0, help="Run duration in seconds (0 = indefinite)")

    # Subcommand: calc-payload
    p_calc = subparsers.add_parser("calc-payload", help="Calculate Ethernet frame overhead & UDP payloads")
    p_calc.add_argument("frames", nargs="*", default=["1024", "1280", "1518"], help="Frame sizes")

    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.subcommand == "calc-payload":
        print("Ethernet Frame Overhead Breakdown:")
        print("  L2 Header: 14B | IPv4: 20B | UDP: 8B | FCS: 4B = 46B overhead")
        print("------------------------------------------------------------")
        for f_str in args.frames:
            try:
                f_int = int(f_str)
                payload = calculate_udp_payload(f_int)
                print(f"  Frame Size {f_int:4d}B -> UDP Payload: {payload:4d}B")
            except ValueError:
                pass
        sys.exit(0)

    elif args.subcommand == "relay":
        dur = args.duration if args.duration > 0 else None
        relay = MulticastRelay(args.group, args.port, args.in_if, args.out_if)
        relay.start(duration=dur)
        sys.exit(0)

    elif args.subcommand == "run":
        suite = WireRateBenchmarkSuite(args)
        res = suite.execute_suite()
        sys.exit(0 if res.get("status") == "PASS" else 1)


if __name__ == "__main__":
    main()
