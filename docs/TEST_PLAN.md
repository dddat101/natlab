# Test Plan & Traceability Matrix - NAT Lab Gateway Conformance

This document defines the comprehensive test case matrix, verification methodology, and PASS/FAIL criteria for testing the Carrier Gateway DUT (Gateway/CPE DUT) against carrier-grade NAT, routing, performance, VoIP, and security specifications.

---

## 1. Requirements Traceability Matrix

| Test ID | Requirement Clause | Technical Specification / RFC | Test Methodology | Evaluation / PASS Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | **NAT and PAT/NAPT Functions** | RFC 3022 (Traditional NAT & NAPT) | Bidirectional TCP, UDP, ICMP traffic generation from LAN to WAN and vice versa. | LAN private IPs (`192.168.1.0/24`) correctly translated to AP WAN IP (`10.10.0.150`); unique source ports allocated; return packets accurately mapped back to originating LAN host. |
| **TC-02** | **Wire-rate Performance ($\ge$ 1024B)** | Carrier Wire-Rate Benchmarking | iPerf3 UDP/TCP traffic with frame sizes $\ge 1024$ bytes concurrent with Multicast streaming (IGMP snooping/IPTV). | 100% line rate (~987+ Mbps on 1GbE) achieved for frame sizes $\ge 1024$ bytes without frame drop or jitter degradation; no starvation between unicast and multicast streams. |
| **TC-03** | **RTCP Port = RTP Port + 1** | RFC 3550 Section 11, SIP/VoIP SSW Interworking | Wi-Fi Phone (`ns-lan1`) initiates RTP on even port $N$ and RTCP on $N+1$ to Softswitch (SSW) on WAN. | AP translates external ports such that $P_{\text{rtcp}} = P_{\text{rtp}} + 1$. Inbound RTCP replies from SSW to $P_{\text{rtcp}}$ correctly reach LAN client port $N+1$. |
| **TC-04** | **Port-Restricted Cone NAT** | RFC 3489 Section 5 / RFC 4787 (EIM + APDF) | 4-step STUN characterization: Probing two distinct WAN IP/ports and attempting reverse delivery from unauthorized port. | 1. Mapping is Endpoint-Independent (EIM): external port is identical regardless of destination WAN IP.<br>2. Filtering is Port-Dependent (APDF): packets from alternate port on the same WAN IP are dropped by DUT. |
| **TC-05** | **Maximum Concurrent Sessions** | Conntrack Scalability & NAT Stress | Burst and sustained concurrent TCP/UDP sessions up to device capacity (e.g. 8192, 16384, 30000, 32768). | AP conntrack table maintains up to 32,768 concurrent active sessions (matching kernel `nf_conntrack_max = 32768`) without kernel crash, connection dropping, or memory leak. |
| **TC-06** | **Sequential Port Allocation & Blacklist Skip** | Carrier Security & Allocation Policy | Multiple LAN terminals transmit to same WAN destination device to induce NAT port conflicts. | External port allocation starts sequentially from port **1026**. Blacklisted ports (**1433, 1434, 4444, 9898, 1900, 2869, 3702, 57321, 3127, 2745, 17300**) are strictly skipped and NEVER allocated. |
| **TC-07** | **Internet Services Compatibility** | Application-Layer Performance (Gaming, Streaming, Cloud, Banking) | Simulated domestic services: Low-latency UDP gaming, HLS HTTP streaming, Cloud PUT/POST, TLS 1.3 persistent banking sessions. | Zero broken SSL sessions, smooth streaming with zero buffer underruns, gaming UDP jitter $< 2\text{ ms}$, PKI authentication uninterrupted. |
| **TC-08** | **Wired Process Delay $\le 1\text{ ms}$ (DSCP 46)** | RFC 2474 / RFC 2598 (Expedited Forwarding - EF) | Precision latency probes tagged with DSCP 46 (`IP TOS = 0xB8` / 184) sent WAN-to-LAN and LAN-to-WAN. | Processing latency through the DUT is $\le 1.0\text{ ms}$ at 99th percentile under both idle and background traffic conditions. |
| **TC-09** | **Uniform 4-Port LAN Performance** | L2 Switching & L3 Forwarding Uniformity | Throughput and latency measured independently across all four physical LAN ports (LAN1..LAN4). | Variance in throughput across all 4 LAN ports is $< 1\%$; latency variance $< 0.05\text{ ms}$. |
| **TC-10** | **Super DMZ (TWIN IP) & DMZ** | Public IP Passthrough / 1:1 NAT Mode | Designated LAN terminal with specific MAC (`02:50:f2:aa:bb:cc`) receives WAN Public IP directly; unsolicited WAN probes tested. | Unsolicited inbound WAN traffic on all unmapped ports routes directly to designated client; normal LAN clients continue to use private IPs with NAPT. |
| **TC-11** | **Port Forwarding (Virtual Server)** | Static Destination Port Translation | External WAN host sends requests to designated WAN ports (e.g. 8080 $\rightarrow$ LAN 192.168.1.101:80). | Packets forwarded accurately to private server; reverse replies translated back to WAN public IP:port. |
| **TC-12** | **Hub / Bridge Mode** | IEEE 802.1D Transparent Bridging | AP configured in Bridge mode; DHCP and routing disabled. | LAN terminals receive WAN subnet DHCP leases directly from Upstream WAN DHCP server without NAT. |
| **TC-13** | **Out-of-Order Fragmentation Reassembly** | RFC 791 / RFC 815, VoLTE Femtocell (Home eNodeB) | Large 1800-byte UDP datagram split into Fragment 1 (MF=1, offset=0) and Fragment 2 (MF=0, offset=185). Fragment 2 is sent **FIRST**, Fragment 1 sent **SECOND**. | AP buffers and correctly reassembles the out-of-order IP fragments; WAN destination receives the intact 1800-byte UDP datagram without loss. |

---

## 2. In-Depth Analysis of Special Clauses

### 2.1. RTCP Port = RTP + 1 (RFC 3550 Section 11)
- **Problem**: When a Wi-Fi phone establishes a SIP call, it transmits RTP voice packets on an even port (e.g. 20000) and RTCP control reports on the adjacent odd port (e.g. 20001). Under standard symmetric or random-port NAPT, the AP might assign arbitrary WAN ports (e.g., RTP mapped to WAN:1026 and RTCP mapped to WAN:1045).
- **Impact**: Carrier Softswitches (SSW) and Session Border Controllers (SBC) reject or fail to pair the RTCP stream because RFC 3550 dictates that RTCP must reside on $RTP + 1$.
- **Verification Rule**: The AP NAT engine or SIP ALG must reserve and allocate contiguous pairs: if $P_{\text{rtp}} = 1026$, then $P_{\text{rtcp}}$ MUST be $1027$.

### 2.2. Port Allocation Sequence & Blacklist Skipping (Item 6)
- **Start Port $\ge 1026$**:
  - Ports $1 - 1023$ are IANA Well-Known Ports.
  - Ports $1024 - 1025$ are reserved in many carrier gateways for internal diagnostic or management services.
  - Dynamic external port allocation sequentially assigns $1026, 1027, 1028, \dots$.
- **Blacklisted Ports (Security & Protocol Protection)**:
  - `1433, 1434`: Microsoft SQL Server / SQL Monitor (target of SQL Slammer worm).
  - `4444`: Metasploit default payload / Blaster worm backdoors.
  - `9898`: Monkeycom worm / backdoor.
  - `1900`: SSDP (Simple Service Discovery Protocol) / UPnP reflection DDoS vector.
  - `2869`: UPnP Eventing / Windows ICS.
  - `3702`: WS-Discovery (Web Services Dynamic Discovery) amplification.
  - `3127`: MyDoom worm backdoor port.
  - `2745`: Bagle worm backdoor port.
  - `17300`: Kuang2 Trojan virus port.
  - `57321`: Carrier diagnostic / TR-069 vendor reservation.
- **Clarification on Customer Note (`MVN ⇒ Needs more detail for this item`)**:
  - *Context*: "MVN" refers to **Multi-Vendor Network** or **Mobile Virtual Network (MVNO)** interworking guidelines established by Carrier.
  - *Engineering Requirement*: The AP firmware MUST provide an administrative parameter (via Web GUI, CLI, or TR-069 `Device.NAT.X_VENDOR_PortBlacklist`) allowing the carrier to dynamically add, remove, or modify this list. During testing, the lab verifies that blacklisted ports are never assigned, and adding a new port (e.g. 8888) immediately skips it in subsequent allocations.

### 2.3. Super DMZ (TWIN IP) vs Standard DMZ
- **Standard DMZ**: All incoming unsolicited traffic on unmapped ports is forwarded to a single private LAN IP (`192.168.1.x`) with destination IP rewritten (DNAT).
- **Super DMZ (TWIN IP)**:
  - The designated client (identified by MAC address) is leased the AP's actual WAN Public IP via DHCP.
  - The AP acts as a proxy/bridge for this specific terminal, bypassing NAPT.
  - Crucial test check: While Super DMZ client uses the public IP, all other LAN clients must simultaneously have full Internet connectivity via private IPs and NAPT!

### 2.4. Out-of-Order IP Fragmentation & VoLTE Femtocell Interworking (Item 13)
- **Why Femtocell VoLTE fails on inferior routers**:
  - VoLTE traffic over LTE Femtocells (Home eNodeBs) uses IPsec (ESP / UDP 4500) or GTP-U tunneling.
  - Large packets exceed standard MTU (1500 bytes) and are fragmented by the Femtocell into multiple IP datagrams.
  - Network jitter or multi-core packet hashing frequently causes Fragment #2 to arrive at the AP before Fragment #1.
  - Inferior gateways lack reassembly queues, inspect only the first fragment, and drop Fragment #2, causing VoLTE voice call muting or complete tunnel teardown.
- **Verification Rule**: The DUT must maintain an active defragmentation cache (`net.ipv4.ip_defrag_*`), reassemble or track out-of-order fragments, perform NAPT, and forward without packet drops.

### 2.5. Wire-Rate Performance ($\ge$ 1024B Frames) & Multicast Combination (Clause 2 / TC-09)
- **Carrier Requirement Statement**:
  > *"When NAT/NAPT is configured for Ethernet frame sizes of 1024 bytes or more, wire-rate performance shall be provided. The same performance shall be provided for any combination of unicast and multicast traffic."*
- **Technical & Business Rationale**:
  - **Carrier Wire-Rate SLA**: On a 1 Gbps physical Ethernet interface, carrier subscribers pay for full gigabit capability. When frames are $\ge 1024$ bytes (e.g. 1024B, 1280B, 1518B standard MTU), the gateway's packet processor and switch fabric must forward traffic at hardware wire-speed without CPU bottleneck or dropping packets.
  - **Multi-Service Triple-Play Coexistence**: In modern subscriber networks, unicast data (HTTP/TCP/UDP downloads, gaming) runs simultaneously with multicast IPTV streams (IGMP snooping / multicast forwarding). Gateway hardware must allocate forwarding resources so that high-rate unicast transfers do not starve the IPTV multicast stream, and multicast does not stall unicast NAPT.
- **Ethernet Frame Overhead & UDP Payload Sizing**:
  $$\text{Overhead} = \text{L2 Ethernet MAC } (14\text{B}) + \text{IPv4 Header } (20\text{B}) + \text{UDP Header } (8\text{B}) + \text{FCS } (4\text{B}) = 46\text{ Bytes}$$
  - **Frame 1024B**: UDP Payload = $1024 - 46 = 978\text{ Bytes}$. Max PPS on 1GE $\approx 119,732\text{ pps}$; wire-rate L4 payload $\approx 936.8\text{ Mbps}$.
  - **Frame 1280B**: UDP Payload = $1280 - 46 = 1234\text{ Bytes}$. Max PPS on 1GE $\approx 96,153\text{ pps}$; wire-rate L4 payload $\approx 949.2\text{ Mbps}$.
  - **Frame 1518B**: UDP Payload = $1518 - 46 = 1472\text{ Bytes}$ (1500B IP MTU). Max PPS on 1GE $\approx 81,274\text{ pps}$; wire-rate L4 payload $\approx 957.0\text{ Mbps}$.
- **Throughput Benchmark Engine**:
  - The lab prefers **iPerf 2.2.1** (`tools/bin/iperf`) as the default throughput benchmark engine because it natively supports multicast binding (`-B <group>`), bidirectional reports, and CSV machine telemetry (`-y C`).
- **Test Combinations**:
  1. `unicast_only`: LAN client (`ns-lan1`) sends UDP traffic through DUT NAPT to WAN server (`ns-wan`).
  2. `multicast_only`: WAN server streams UDP to Multicast group `239.255.1.1:5001`; received by LAN client via IGMP group join.
  3. `concurrent_mixed`: LAN sends Unicast NAT while WAN streams Multicast simultaneously.
- **PASS Criteria**:
  - Measured aggregate throughput $\ge \text{WIRE\_RATE\_TARGET\_MBPS}$ (default 940 Mbps on 1GE) across all tested frame sizes ($1024\text{B}, 1280\text{B}, 1518\text{B}$).
  - Multicast packet loss $\le 0.5\%$, jitter $\le 2\text{ ms}$, zero stream starvation.

---

## 3. Test Execution Workflow

### Step 1: Pre-Flight Diagnostics
```bash
./scripts/diagnose.sh
```

### Step 2: Initialize Topology
```bash
# For simulation mode (no physical AP needed):
sudo ./scripts/setup.sh --virtual

# For physical Gateway DUT hardware:
sudo ./scripts/setup.sh --single
```

### Step 3: Run Full Automated Verification Suite
```bash
sudo ./scripts/scenario.sh all
```

### Step 4: Verify PCAP Evidence & Inspect Timeline
```bash
./scripts/verify_compliance.sh
```

### Step 5: Teardown Lab
```bash
sudo ./scripts/cleanup.sh
```
