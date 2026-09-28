#!/usr/bin/env bash
# ==============================================================================
# CARRIER GATEWAY DUT - AUTOMATED TEST SCENARIO RUNNER
# Orchestrates test phases for all Carrier NAT & Gateway Conformance Requirements
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
    cat <<'USAGE'
==================================================================
  Carrier Gateway DUT - Automated Scenario Runner
==================================================================

Description:
  Automates multi-phase test scenarios, initiates packet capture,
  executes protocol verification tools, and hands off to automated PCAP verification.

Usage:
  sudo ./scripts/scenario.sh [SCENARIO]

Supported Scenarios:
  all             (Default) Run complete Carrier Conformance Suite
  nat_basic       Phase 1: Basic IPv4 NAT & NAPT validation (RFC 3022)
  rtcp_port       Phase 2: RTCP Port = RTP + 1 validation (RFC 3550) [optional: python|sipp]
  rtcp_port_sipp  Phase 2: Full VoIP emulation via SIPp (SIP INVITE + G.711 RTP/RTCP)
  cone_nat        Phase 3: Port-Restricted Cone NAT check (RFC 3489 / RFC 4787)
  port_alloc      Phase 4: Sequential port allocation starting from 1026 & blacklist skip [count]
  fragmentation   Phase 5: Out-of-order IP fragmentation reassembly (Femto VoLTE)
  dscp46_latency  Phase 6: Wired process delay <= 1 ms on DSCP 46 packets
  super_dmz       Phase 7: Super DMZ (TWIN IP) & Port Forwarding validation
  concurrency     Phase 8: Maximum concurrent sessions [count] [bidirectional|oneway]
  wire_rate       Phase 9: Wire-rate throughput (>= 1024B) Unicast + Multicast
  -h, --help      Show this help message and exit

Examples:
  sudo ./scripts/scenario.sh rtcp_port
  sudo ./scripts/scenario.sh rtcp_port sipp
  sudo ./scripts/scenario.sh rtcp_port_sipp
  sudo ./scripts/scenario.sh port_alloc
  sudo ./scripts/scenario.sh port_alloc 500
  sudo ./scripts/scenario.sh concurrency 8192
  sudo ./scripts/scenario.sh concurrency 8192 bidirectional
  sudo ./scripts/scenario.sh all

Suggested Next Steps:
  1. Inspect verification report: ./scripts/verify_compliance.sh
  2. Inspect capture state:       ./scripts/show_state.sh
  3. Teardown when finished:      sudo ./scripts/cleanup.sh
==================================================================
USAGE
}

# ------------------------------------------------------------------------------
# Phase 1: Basic NAT & NAPT
# ------------------------------------------------------------------------------
run_phase_nat_basic() {
    log_step "[PHASE 1] Basic IPv4 NAT & NAPT Connectivity (RFC 3022)"
    log_info "Testing outbound ICMP and UDP translation from ${LAN1_NS:-ns-lan1} to ${WAN_SERVER_IP:-10.10.0.1}..."
    if ip netns exec "${LAN1_NS:-ns-lan1}" ping -c 3 -W 1 "${WAN_SERVER_IP:-10.10.0.1}" >/dev/null 2>&1; then
        log_success "Basic Outbound NAT & Ping verified."
    else
        log_warn "Ping from LAN1 to WAN server timed out."
    fi
}

# ------------------------------------------------------------------------------
# Phase 2: RTCP Port = RTP + 1 (RFC 3550)
# ------------------------------------------------------------------------------
run_phase_rtcp_port_python() {
    log_info "Executing RTCP conformance test via Python socket engine..."
    local ssw_out="${LOG_DIR}/rtcp_result.json"

    log_info "Starting SSW RTP/RTCP server listener in ${WAN_NS:-ns-wan}..."
    ip netns exec "${WAN_NS:-ns-wan}" python3 "${TOOLS_DIR}/rtp_rtcp_test.py" server \
        --bind-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --rtp-port "${SSW_RTP_PORT:-30000}" \
        --rtcp-port "${SSW_RTCP_PORT:-30001}" \
        --timeout 6.0 \
        --output "${ssw_out}" > "${LOG_DIR}/rtcp_server.log" 2>&1 &
    local srv_pid=$!

    sleep 0.5

    log_info "Launching Wi-Fi Phone client in ${LAN1_NS:-ns-lan1}..."
    ip netns exec "${LAN1_NS:-ns-lan1}" python3 "${TOOLS_DIR}/rtp_rtcp_test.py" client \
        --server-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --server-rtp-port "${SSW_RTP_PORT:-30000}" \
        --server-rtcp-port "${SSW_RTCP_PORT:-30001}" \
        --client-rtp-port "${RTP_CLIENT_PORT:-20000}" \
        --client-rtcp-port "${RTCP_CLIENT_PORT:-20001}" \
        --timeout 3.0 > "${LOG_DIR}/rtcp_client.log" 2>&1 || true

    wait "${srv_pid}" 2>/dev/null || true
}

run_phase_rtcp_port_sipp() {
    log_info "Executing full VoIP session emulation via SIPp engine (SIP INVITE + G.711 RTP/RTCP)..."
    local sipp_runner="${TOOLS_DIR}/sipp_voip_test.sh"
    if [[ ! -x "${sipp_runner}" ]]; then
        chmod +x "${sipp_runner}" 2>/dev/null || true
    fi

    "${sipp_runner}" \
        --wan-ns "${WAN_NS:-ns-wan}" \
        --lan-ns "${LAN1_NS:-ns-lan1}" \
        --server-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --client-ip "${LAN1_CLIENT_IP:-192.168.1.101}" \
        --server-port "${SIPP_SIP_PORT:-5060}" \
        --client-port "${SIPP_CLIENT_PORT:-5060}" \
        --media-server-port "${SSW_RTP_PORT:-30000}" \
        --media-client-port "${RTP_CLIENT_PORT:-20000}" \
        --output "${LOG_DIR}/rtcp_result.json" || true
}

run_phase_rtcp_port() {
    local engine="${1:-${VOIP_TEST_ENGINE:-python}}"
    log_step "[PHASE 2] RTCP Port = RTP + 1 Port Pairing (RFC 3550) [Engine: ${engine^^}]"
    local ssw_out="${LOG_DIR}/rtcp_result.json"

    if [[ "${engine}" == "sipp" ]]; then
        run_phase_rtcp_port_sipp
    else
        run_phase_rtcp_port_python
    fi

    if [[ -f "${ssw_out}" ]] && grep -q '"status": "PASS"' "${ssw_out}"; then
        log_success "RTCP Port == RTP Port + 1 verified! (RFC 3550 Compliant via ${engine^^})"
    else
        log_warn "RTCP port verification did not pass. Check ${ssw_out} and logs."
    fi
}

# ------------------------------------------------------------------------------
# Phase 3: Port-Restricted Cone NAT (RFC 3489 / RFC 4787)
# ------------------------------------------------------------------------------
run_phase_cone_nat() {
    log_step "[PHASE 3] Port-Restricted Cone NAT Characterization (RFC 3489 / RFC 4787)"
    local cone_out="${LOG_DIR}/cone_nat_result.json"

    log_info "Starting Cone NAT characterization server in ${WAN_NS:-ns-wan}..."
    ip netns exec "${WAN_NS:-ns-wan}" python3 "${TOOLS_DIR}/cone_nat_test.py" server \
        --ip1 "${WAN_SERVER_IP:-10.10.0.1}" \
        --ip2 "${WAN_SERVER2_IP:-10.10.0.2}" \
        --port1 3478 \
        --port2 3479 \
        --timeout 6.0 \
        --output "${cone_out}" > "${LOG_DIR}/cone_server.log" 2>&1 &
    local srv_pid=$!

    sleep 0.5

    log_info "Launching Cone NAT client in ${LAN1_NS:-ns-lan1}..."
    ip netns exec "${LAN1_NS:-ns-lan1}" python3 "${TOOLS_DIR}/cone_nat_test.py" client \
        --ip1 "${WAN_SERVER_IP:-10.10.0.1}" \
        --ip2 "${WAN_SERVER2_IP:-10.10.0.2}" \
        --port1 3478 \
        --port2 3479 \
        --client-port 15000 \
        --timeout 3.0 \
        --output "${cone_out}" > "${LOG_DIR}/cone_client.log" 2>&1 || true

    wait "${srv_pid}" 2>/dev/null || true

    if [[ -f "${cone_out}" ]] && grep -q '"status": "PASS"' "${cone_out}"; then
        log_success "Port-Restricted Cone NAT behavior verified!"
    else
        log_warn "Port-Restricted Cone NAT check reported warnings. Check ${cone_out}."
    fi
}

# ------------------------------------------------------------------------------
# Phase 4: Sequential Port Allocation from 1026 & Blacklist Skipping
# ------------------------------------------------------------------------------
run_phase_port_alloc() {
    local sweep_count="${1:-${PORT_SWEEP_COUNT:-500}}"
    local base_src_port="${PORT_COLLISION_BASE:-5000}"
    log_step "[PHASE 4] Sequential Port Allocation from 1026 & Blacklist Port Skipping (Probes + ${sweep_count}-Flow Sweep)"
    local port_out="${LOG_DIR}/port_alloc_result.json"

    local total_expected=$(( 11 + 2 * sweep_count ))
    local srv_timeout=15.0
    if (( sweep_count >= 1000 )); then
        srv_timeout=25.0
    fi

    log_info "Starting port allocation server in ${WAN_NS:-ns-wan} (Expecting ${total_expected} packets)..."
    ip netns exec "${WAN_NS:-ns-wan}" python3 "${TOOLS_DIR}/sequential_port_test.py" server \
        --bind-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --port 8888 \
        --start-port "${NAT_SEQ_PORT_START:-1026}" \
        --skip-ports "${NAT_SKIP_PORTS}" \
        --expected-count "${total_expected}" \
        --timeout "${srv_timeout}" \
        --output "${port_out}" > "${LOG_DIR}/port_alloc_server.log" 2>&1 &
    local srv_pid=$!

    sleep 0.4

    # Step 4A: Targeted Boundary Injection Probe
    log_info "[Step 4A] Injecting 11 targeted Blacklist boundary probes from ${LAN1_NS:-ns-lan1}..."
    ip netns exec "${LAN1_NS:-ns-lan1}" python3 "${TOOLS_DIR}/sequential_port_test.py" probe \
        --server-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --server-port 8888 \
        --client-id "LAN1" \
        --probe-ports "${NAT_SKIP_PORTS}" \
        --interval 0.005 > "${LOG_DIR}/port_alloc_probe.log" 2>&1 || true

    sleep 0.2

    # Step 4B: Large-scale Collision Sweep
    log_info "[Step 4B] Inducing ${sweep_count}-flow deterministic collision on base port ${base_src_port} (LAN1 vs LAN2)..."

    # LAN1 establishes baseline flows on ports [base..base+sweep_count-1] and holds them open
    ip netns exec "${LAN1_NS:-ns-lan1}" python3 "${TOOLS_DIR}/sequential_port_test.py" client \
        --server-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --server-port 8888 \
        --client-id "LAN1" \
        --count "${sweep_count}" \
        --base-src-port "${base_src_port}" \
        --hold-sec 4.0 \
        --interval 0.002 > "${LOG_DIR}/port_alloc_lan1.log" 2>&1 &
    local lan1_pid=$!

    # Stagger LAN2 slightly to guarantee collision on the identical source ports
    sleep 0.15

    ip netns exec "${LAN2_NS:-ns-lan2}" python3 "${TOOLS_DIR}/sequential_port_test.py" client \
        --server-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --server-port 8888 \
        --client-id "LAN2" \
        --count "${sweep_count}" \
        --base-src-port "${base_src_port}" \
        --hold-sec 2.0 \
        --interval 0.002 > "${LOG_DIR}/port_alloc_lan2.log" 2>&1 &
    local lan2_pid=$!

    wait "${lan1_pid}" "${lan2_pid}" "${srv_pid}" 2>/dev/null || true

    if [[ -f "${port_out}" ]] && grep -q '"status": "PASS"' "${port_out}"; then
        log_success "Sequential port allocation & Blacklist skip verified!"
    else
        log_warn "Port allocation check reported warnings. Check ${port_out}."
    fi
}

# ------------------------------------------------------------------------------
# Phase 5: Out-of-Order IP Fragmentation & Reassembly (Femtocell VoLTE)
# ------------------------------------------------------------------------------
run_phase_fragmentation() {
    log_step "[PHASE 5] Out-of-Order IP Fragmentation & Reassembly (Femto VoLTE)"
    local frag_out="${LOG_DIR}/fragmentation_result.json"

    log_info "Starting reassembled datagram receiver in ${WAN_NS:-ns-wan}..."
    ip netns exec "${WAN_NS:-ns-wan}" python3 "${TOOLS_DIR}/fragmentation_test.py" receiver \
        --bind-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --port 7777 \
        --expected-bytes 1800 \
        --timeout 6.0 \
        --output "${frag_out}" > "${LOG_DIR}/frag_receiver.log" 2>&1 &
    local recv_pid=$!

    sleep 0.5

    log_info "Transmitting reversed fragments from Femtocell client (${LAN3_NS:-ns-lan3})..."
    ip netns exec "${LAN3_NS:-ns-lan3}" python3 "${TOOLS_DIR}/fragmentation_test.py" sender \
        --src-ip "${LAN3_CLIENT_IP:-192.168.1.103}" \
        --dst-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --src-port 17777 \
        --dst-port 7777 \
        --total-payload 1800 \
        --reverse-order > "${LOG_DIR}/frag_sender.log" 2>&1 || true

    wait "${recv_pid}" 2>/dev/null || true

    if [[ -f "${frag_out}" ]] && grep -q '"status": "PASS"' "${frag_out}"; then
        log_success "Out-of-order IP fragment reassembly successful!"
    else
        log_warn "Fragment reassembly check failed. Check ${frag_out}."
    fi
}

# ------------------------------------------------------------------------------
# Phase 6: DSCP 46 Process Delay <= 1.0 ms
# ------------------------------------------------------------------------------
run_phase_dscp46_latency() {
    log_step "[PHASE 6] Wired Processing Delay on Packets with DSCP 46 (<= 1.0 ms)"
    local dscp_out="${LOG_DIR}/dscp46_result.json"

    log_info "Starting DSCP 46 reflector in ${WAN_NS:-ns-wan}..."
    ip netns exec "${WAN_NS:-ns-wan}" python3 "${TOOLS_DIR}/dscp46_latency_test.py" reflector \
        --bind-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --port 9999 \
        --timeout 6.0 > /dev/null 2>&1 &
    local ref_pid=$!

    sleep 0.5

    log_info "Probing latency from ${LAN1_NS:-ns-lan1} with DSCP 46 / EF..."
    ip netns exec "${LAN1_NS:-ns-lan1}" python3 "${TOOLS_DIR}/dscp46_latency_test.py" prober \
        --target-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --port 9999 \
        --count "${DSCP46_PROBE_COUNT:-100}" \
        --interval 0.01 \
        --max-delay-ms "${DSCP46_MAX_LATENCY_MS:-1.0}" \
        --output "${dscp_out}" > "${LOG_DIR}/dscp46_prober.log" 2>&1 || true

    wait "${ref_pid}" 2>/dev/null || true

    if [[ -f "${dscp_out}" ]] && grep -q '"status": "PASS"' "${dscp_out}"; then
        log_success "DSCP 46 processing delay <= 1.0 ms verified!"
    else
        log_warn "DSCP 46 latency test reported delay threshold violation. Check ${dscp_out}."
    fi
}

# ------------------------------------------------------------------------------
# Phase 7: Super DMZ (TWIN IP) & Port Forwarding
# ------------------------------------------------------------------------------
run_phase_super_dmz() {
    log_step "[PHASE 7] Super DMZ (TWIN IP) & Port Forwarding Validation"
    local dmz_out="${LOG_DIR}/super_dmz_result.json"
    local wan_out="${LOG_DIR}/super_dmz_wan.json"

    log_info "Listening inside Super DMZ designated host (${LAN4_NS:-ns-lan4})..."
    ip netns exec "${LAN4_NS:-ns-lan4}" python3 "${TOOLS_DIR}/super_dmz_test.py" listen \
        --port 5555 \
        --timeout 5.0 \
        --output "${dmz_out}" > "${LOG_DIR}/super_dmz_listen.log" 2>&1 &
    local dmz_pid=$!

    sleep 0.5

    log_info "Sending unsolicited inbound WAN packet to Public IP ${DUT_WAN_IP:-10.10.0.150}:5555..."
    # In virtual simulation mode, set up a temporary DNAT / DMZ rule in ns-dut if running virtual
    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" && -n "${DUT_NS:-}" ]] && ns_exists "${DUT_NS}"; then
        ip netns exec "${DUT_NS}" iptables -t nat -A PREROUTING -p udp --dport 5555 -j DNAT --to-destination "${LAN4_CLIENT_IP:-192.168.1.104}:5555" 2>/dev/null || true
    fi

    ip netns exec "${WAN_NS:-ns-wan}" python3 "${TOOLS_DIR}/super_dmz_test.py" send \
        --target-ip "${DUT_WAN_IP:-10.10.0.150}" \
        --port 5555 \
        --timeout 3.0 \
        --output "${wan_out}" > "${LOG_DIR}/super_dmz_send.log" 2>&1 || true

    wait "${dmz_pid}" 2>/dev/null || true

    if [[ -f "${dmz_out}" ]] && grep -q '"status": "PASS"' "${dmz_out}"; then
        log_success "Super DMZ / Port Forwarding packet delivery verified!"
    else
        log_warn "Super DMZ test reported warnings. Check ${dmz_out}."
    fi
}

# ------------------------------------------------------------------------------
# Phase 8: Concurrency & Session Scalability
# ------------------------------------------------------------------------------
run_phase_concurrency() {
    local target_sessions="${1:-${CONCURRENT_SESSION_TARGET:-8192}}"
    local direction="${2:-bidirectional}"
    log_step "[PHASE 8] Maximum Concurrent Sessions Stress Test (Target: ${target_sessions}, Mode: ${direction^^}, DUT Max: ${MAX_CONCURRENT_SESSIONS:-32768})"
    local conn_out="${LOG_DIR}/concurrency_result.json"

    local min_required=$(( target_sessions * 95 / 100 ))
    local duration=10.0
    if (( target_sessions >= 15000 )); then
        duration=18.0
    fi

    log_info "Starting Conntrack server in ${WAN_NS:-ns-wan} (${direction^^} mode, expecting >= ${min_required} flows)..."
    ip netns exec "${WAN_NS:-ns-wan}" python3 "${TOOLS_DIR}/concurrent_sessions_test.py" server \
        --bind-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --port 60000 \
        --min-sessions "${min_required}" \
        --duration "${duration}" \
        --direction "${direction}" \
        --output "${conn_out}" > "${LOG_DIR}/concurrency_server.log" 2>&1 &
    local srv_pid=$!

    sleep 0.5

    log_info "Spawning ${target_sessions} concurrent sessions from ${LAN1_NS:-ns-lan1} (${direction^^} mode)..."
    ip netns exec "${LAN1_NS:-ns-lan1}" python3 "${TOOLS_DIR}/concurrent_sessions_test.py" client \
        --target-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --port 60000 \
        --sessions "${target_sessions}" \
        --direction "${direction}" \
        --rate 3000 \
        --hold-sec 3.0 > "${LOG_DIR}/concurrency_client.log" 2>&1 || true

    wait "${srv_pid}" 2>/dev/null || true

    if [[ -f "${conn_out}" ]] && grep -q '"status": "PASS"' "${conn_out}"; then
        local detected
        detected="$(grep '"unique_sessions_detected"' "${conn_out}" | grep -o '[0-9]*' || echo "${target_sessions}")"
        log_success "Concurrent session stability verified! (${detected} active sessions tracked in ${direction^^} mode)"
    else
        log_warn "Concurrency stress test reported warnings. Check ${conn_out}."
    fi
}

# ------------------------------------------------------------------------------
# Phase 9: Wire-Rate Performance (>= 1024B Frames)
# ------------------------------------------------------------------------------
run_phase_wire_rate() {
    log_step "[PHASE 9] Wire-Rate Performance (>= 1024B Frames) & Multicast Combination"
    local json_out="${LOG_DIR}/wire_rate_result.json"
    local log_out="${LOG_DIR}/iperf_1024b.log"

    # Locate iperf binary (tools/bin/iperf first, then system PATH or fallback)
    local iperf_bin="${TOOLS_DIR}/bin/iperf"
    if [[ ! -x "${iperf_bin}" ]]; then
        iperf_bin="$(command -v iperf 2>/dev/null || command -v iperf3 2>/dev/null || echo "")"
    fi

    if [[ -z "${iperf_bin}" ]]; then
        log_error "Neither iperf nor iperf3 is installed or available in tools/bin/."
        return 0
    fi

    # Check reachability to WAN server before attempting benchmark
    if ! ip netns exec "${LAN1_NS:-ns-lan1}" ping -c 1 -W 1 "${WAN_SERVER_IP:-10.10.0.1}" >/dev/null 2>&1; then
        log_error "WAN Server ${WAN_SERVER_IP:-10.10.0.1} is not reachable from ${LAN1_NS:-ns-lan1}."
        log_error "Ensure topology is active (sudo ./scripts/setup.sh) and DUT is routing traffic."
        echo "iperf: error - unable to connect to server - No route to host" > "${log_out}"
        return 0
    fi

    local engine_type="iperf"
    if [[ "${iperf_bin}" == *"iperf3"* ]]; then
        engine_type="iperf3"
    fi

    log_info "Executing Wire-Rate & Multicast benchmark suite (Engine: ${engine_type^^}, Frames: ${WIRE_RATE_FRAMES:-1024,1280,1518}, Target: ${WIRE_RATE_TARGET_MBPS:-940} Mbps)..."

    local py_bench="${TOOLS_DIR}/wire_rate_benchmark.py"
    if python3 "${py_bench}" run \
        --wan-ns "${WAN_NS:-ns-wan}" \
        --lan-ns "${LAN1_NS:-ns-lan1}" \
        --dut-ns "${DUT_NS:-ns-dut}" \
        --wan-ip "${WAN_SERVER_IP:-10.10.0.1}" \
        --lan-ip "${LAN1_CLIENT_IP:-192.168.1.101}" \
        --dut-wan-ip "${DUT_WAN_IP:-10.10.0.150}" \
        --topology-mode "${TOPOLOGY_MODE:-virtual}" \
        --frame-sizes "${WIRE_RATE_FRAMES:-1024,1280,1518}" \
        --combinations "unicast_only,multicast_only,concurrent_mixed" \
        --target-mbps "${WIRE_RATE_TARGET_MBPS:-940}" \
        --tolerance-pct "${WIRE_RATE_TOLERANCE_PCT:-95.0}" \
        --duration "${WIRE_RATE_DURATION_SEC:-3}" \
        --multicast-group "${MULTICAST_GROUP:-239.255.1.1}" \
        --multicast-port "${MULTICAST_PORT:-5001}" \
        --multicast-bw "${MULTICAST_BANDWIDTH_MBPS:-200}" \
        --iperf-bin "${iperf_bin}" \
        --output "${json_out}" > "${log_out}" 2>&1; then
        
        local min_tput
        min_tput="$(grep '"min_achieved_aggregate_mbps":' "${json_out}" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ,' | tr -d ' ' || echo "${WIRE_RATE_TARGET_MBPS:-940}")"
        log_success "Wire-Rate throughput & multicast benchmark PASSED (Achieved min ${min_tput} Mbps across tested frames)."
    else
        log_error "Wire-Rate benchmark reported failures or below threshold. See ${log_out} and ${json_out}."
    fi
}

main() {
    local scenario="${1:-all}"
    if [[ "${scenario}" == "-h" || "${scenario}" == "--help" ]]; then
        usage
        exit 0
    fi

    require_root
    load_config
    ensure_runtime_dirs

    # Ensure upstream WAN DHCP server is active
    if [[ "${ENABLE_WAN_DHCP:-1}" == "1" && -x "${SCRIPT_DIR}/wan_server.sh" ]]; then
        "${SCRIPT_DIR}/wan_server.sh" start "${WAN_DHCP_BACKEND:-auto}" >/dev/null 2>&1 || true
    fi

    print_header "STARTING Carrier CONFORMANCE TEST: [${scenario^^}]"

    # Clean previous result json files (only wipe all logs when running full regression suite)
    if [[ "${scenario}" == "all" ]]; then
        rm -f "${LOG_DIR}"/*.json "${LOG_DIR}"/*.log 2>/dev/null || true
    fi

    # Phase 0: Start Background Capture
    if [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
        bash "${SCRIPT_DIR}/capture.sh" start
        trap 'bash "${SCRIPT_DIR}/capture.sh" stop >/dev/null 2>&1 || true' EXIT INT TERM
    fi

    case "${scenario}" in
        all)
            run_phase_nat_basic
            run_phase_rtcp_port
            run_phase_cone_nat
            run_phase_port_alloc
            run_phase_fragmentation
            run_phase_dscp46_latency
            run_phase_super_dmz
            run_phase_concurrency
            run_phase_wire_rate
            ;;
        nat_basic)      run_phase_nat_basic ;;
        rtcp_port)      run_phase_rtcp_port "${2:-${VOIP_TEST_ENGINE:-python}}" ;;
        rtcp_port_sipp|voip_sipp) run_phase_rtcp_port "sipp" ;;
        cone_nat)       run_phase_cone_nat ;;
        port_alloc)     run_phase_port_alloc "${2:-500}" ;;
        fragmentation)  run_phase_fragmentation ;;
        dscp46_latency) run_phase_dscp46_latency ;;
        super_dmz)      run_phase_super_dmz ;;
        concurrency)    run_phase_concurrency "${2:-}" "${3:-bidirectional}" ;;
        wire_rate)      run_phase_wire_rate ;;
        *)              log_error "Unknown scenario: ${scenario}"; usage; exit 1 ;;
    esac

    # Stop capture cleanly (grace delay to flush packet sniffer buffers)
    sleep 0.8
    if [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
        trap - EXIT INT TERM
        bash "${SCRIPT_DIR}/capture.sh" stop
    fi

    log_info "Scenario execution completed. Proceeding to compliance verification..."
    if [[ -x "${SCRIPT_DIR}/verify_compliance.sh" ]]; then
        bash "${SCRIPT_DIR}/verify_compliance.sh"
    fi
}

main "$@"
