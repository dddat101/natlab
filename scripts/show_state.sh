#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - RUNTIME STATE OBSERVER
# Non-root graceful degradation, stale PID detection & topology inspection
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
    cat <<'USAGE'
Description:
  Inspects and reports current runtime state of the network test lab,
  including active namespaces, bridges, interface addresses, daemons,
  and captured PCAP evidence.

Usage:
  ./scripts/show_state.sh [options]
  ./scripts/show_state.sh -h | --help

Options:
  -h, --help  Show this help message and exit

Suggested Next Steps:
  - Run test scenarios:    sudo ./scripts/scenario.sh all
  - Verify compliance:     ./scripts/verify_compliance.sh
  - Teardown when done:    sudo ./scripts/cleanup.sh
USAGE
}

main() {
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    load_config
    print_header "NETWORK TEST LAB RUNTIME STATE"

    # 1. Topology State
    print_section "TOPOLOGY METADATA"
    if [[ -f "${STATE_DIR}/topology_state.env" ]]; then
        cat "${STATE_DIR}/topology_state.env"
    else
        printf 'No active topology state found (run sudo ./scripts/setup.sh).\n'
    fi

    # 2. Linux Bridges
    print_section "BRIDGES & PORTS"
    local br
    for br in "${WAN_BRIDGE:-br-test-wan}" "${LAN_BRIDGE:-br-test-lan}"; do
        if bridge_exists "${br}"; then
            printf 'Bridge: %s (State: UP)\n' "${br}"
            ip link show master "${br}" 2>/dev/null | awk -F': ' '/^[0-9]+/ {print $2}' | awk '{printf "  - Member: %s\n", $1}' || true
        else
            printf 'Bridge: %s (NOT FOUND)\n' "${br}"
        fi
    done

    # 3. Namespaces & Interfaces
    print_section "NETWORK NAMESPACES & INTERFACES"
    if is_root; then
        local ns
        for ns in "${WAN_NS:-ns-wan}" "${DUT_NS:-ns-dut}" "${LAN1_NS:-ns-lan1}" "${LAN2_NS:-ns-lan2}" "${LAN3_NS:-ns-lan3}" "${LAN4_NS:-ns-lan4}"; do
            if ns_exists "${ns}"; then
                printf 'Namespace: \e[1;36m%s\e[0m\n' "${ns}"
                ip netns exec "${ns}" ip -br -4 addr show 2>/dev/null | awk '{printf "  %-16s %s\n", $1, $3}' || true
                ip netns exec "${ns}" ip route show 2>/dev/null | awk '{printf "    route: %s\n", $0}' || true
                ip netns exec "${ns}" ip neigh show 2>/dev/null | awk '{printf "    neighbor: %s\n", $0}' || true
            fi
        done

        # Active End-to-End Connectivity Diagnostics
        print_section "ACTIVE END-TO-END CONNECTIVITY DIAGNOSTICS"
        if ns_exists "${LAN1_NS:-ns-lan1}"; then
            printf '  [1] LAN Client (ns-lan1) -> DUT Gateway (%s): ' "${DUT_LAN_IP:-192.168.1.1}"
            if ip netns exec "${LAN1_NS:-ns-lan1}" ping -c 1 -W 1 "${DUT_LAN_IP:-192.168.1.1}" >/dev/null 2>&1; then
                printf '\e[1;32m[PASS] REACHABLE\e[0m\n'
            else
                printf '\e[1;31m[FAIL] UNREACHABLE (Check DUT LAN IP / Cable)\e[0m\n'
            fi

            printf '  [2] LAN Client (ns-lan1) -> Upstream WAN Server (%s): ' "${WAN_SERVER_IP:-10.10.0.1}"
            if ip netns exec "${LAN1_NS:-ns-lan1}" ping -c 1 -W 1 "${WAN_SERVER_IP:-10.10.0.1}" >/dev/null 2>&1; then
                printf '\e[1;32m[PASS] REACHABLE (NAT & Routing Active)\e[0m\n'
            else
                printf '\e[1;31m[FAIL] UNREACHABLE (NAT / WAN link down)\e[0m\n'
            fi
        fi

        if ns_exists "${WAN_NS:-ns-wan}"; then
            local target_wan_ip="${DUT_WAN_IP:-10.10.0.100}"
            local learned_ip
            learned_ip="$(ip netns exec "${WAN_NS:-ns-wan}" ip -4 neigh show dev eth-wan 2>/dev/null | awk '/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}' | head -n1 || echo "")"
            if [[ -n "${learned_ip}" ]]; then
                target_wan_ip="${learned_ip}"
            fi

            printf '  [3] WAN Server (ns-wan) -> DUT WAN IP (%s): ' "${target_wan_ip}"
            if ip netns exec "${WAN_NS:-ns-wan}" ping -c 1 -W 1 "${target_wan_ip}" >/dev/null 2>&1; then
                printf '\e[1;32m[PASS] REACHABLE\e[0m\n'
            else
                printf '\e[1;33m[NOTE] UNREACHABLE (Device may drop WAN-side ICMP Echo, or lease pending)\e[0m\n'
            fi
        fi
    else
        printf 'Note: Run with sudo to inspect internal netns IPs, routing, and reachability.\n'
        ip netns list 2>/dev/null | awk '{printf "Namespace present: %s\n", $1}' || true
    fi

    # 4. Supervised Daemons & Stale PID Detection
    print_section "SUPERVISED DAEMONS & SERVICES"
    local pid_found=0
    local pid_file
    for pid_file in "${STATE_DIR}"/*.pid; do
        if [[ -f "${pid_file}" ]]; then
            pid_found=1
            local name pid
            name="$(basename "${pid_file}" .pid)"
            pid="$(cat "${pid_file}" 2>/dev/null || true)"
            if is_pidfile_running "${pid_file}"; then
                printf '  %-24s -> \e[1;32mRUNNING\e[0m (PID: %s)\n' "${name}" "${pid}"
            else
                printf '  %-24s -> \e[1;31mSTALE PID FILE\e[0m (Process dead)\n' "${name}"
            fi
        fi
    done
    if (( pid_found == 0 )); then
        printf 'No active daemon PID files registered.\n'
    fi

    # 5. Packet Captures
    print_section "PACKET CAPTURES"
    if [[ -d "${CAPTURE_DIR}" ]]; then
        local pcap_count=0
        while IFS= read -r pcap_path; do
            if [[ -f "${pcap_path}" ]]; then
                pcap_count=$((pcap_count + 1))
                local size
                size="$(du -h "${pcap_path}" | cut -f1)"
                printf '  [%s] %s\n' "${size}" "$(basename "${pcap_path}")"
            fi
        done < <(find "${CAPTURE_DIR}" -maxdepth 1 -name '*.pcap*' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk '{print $2}' | head -n 5)
        if (( pcap_count == 0 )); then
            printf 'No PCAP capture files found in %s.\n' "${CAPTURE_DIR}"
        fi
    fi
    printf '==================================================================\n'
}

main "$@"
