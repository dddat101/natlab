#!/usr/bin/env bash
# ==============================================================================
# CARRIER GATEWAY DUT - CLEANUP SCRIPT
# Idempotently tears down netns, veths, bridges, daemons,
# and restores physical interfaces.
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
  Carrier Gateway DUT - Topology Cleanup
==================================================================

Description:
  Gracefully stops test traffic, terminates namespaces (ns-wan, ns-dut,
  ns-lan1..4), deletes bridges, and restores physical interfaces.

Usage:
  sudo ./scripts/cleanup.sh [options]
  ./scripts/cleanup.sh [command]

Options:
  -r, --restore, --dhcp    Restore physical interfaces to UP and re-enable NM [Default]
  -d, --down, --no-restore Keep physical interfaces DOWN and flushed
  --logs                   Purge all test logs in logs/
  --captures               Purge all PCAP captures in captures/
  -a, --all                Teardown topology and purge state, logs, and captures
  -h, --help               Show this help message

Subcommands (Non-destructive to running topology):
  logs                     Purge logs/ without tearing down lab
  captures                 Purge captures/ without tearing down lab
  data                     Purge both logs/ and captures/ without tearing down lab

Examples:
  sudo ./scripts/cleanup.sh
  sudo ./scripts/cleanup.sh --all
==================================================================
USAGE
}

main() {
    local arg
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    load_config

    case "${1:-}" in
        logs)     clean_logs; exit 0 ;;
        captures) clean_captures; exit 0 ;;
        data)     clean_logs; clean_captures; exit 0 ;;
    esac

    require_root
    require_command ip

    local restore="${RESTORE_INTERFACES_ON_CLEANUP:-1}"
    local clean_logs_flag=0
    local clean_captures_flag=0

    while (( $# > 0 )); do
        case "$1" in
            -r|--restore|--dhcp)    restore=1; shift ;;
            -d|--down|--no-restore) restore=0; shift ;;
            --logs)                 clean_logs_flag=1; shift ;;
            --captures)             clean_captures_flag=1; shift ;;
            -a|--all)               clean_logs_flag=1; clean_captures_flag=1; shift ;;
            *)                      usage; exit 2 ;;
        esac
    done

    print_header "TEARING DOWN Carrier TEST TOPOLOGY"
    log_info "Initiating cleanup (restore_interfaces=${restore})..."

    # 1. Stop packet captures
    if [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
        "${SCRIPT_DIR}/capture.sh" stop 2>/dev/null || true
    fi

    # 1b. Stop Upstream WAN Server Daemons
    if [[ -x "${SCRIPT_DIR}/wan_server.sh" ]]; then
        "${SCRIPT_DIR}/wan_server.sh" stop >/dev/null 2>&1 || true
    fi

    # 2. Stop running PIDs
    local pidfile
    for pidfile in "${STATE_DIR}"/*.pid; do
        [[ -f "${pidfile}" ]] && stop_pidfile "${pidfile}"
    done

    # 3. Kill namespace processes
    local ALL_NS=(
        "${WAN_NS:-ns-wan}"
        "${DUT_NS:-ns-dut}"
        "${LAN1_NS:-ns-lan1}"
        "${LAN2_NS:-ns-lan2}"
        "${LAN3_NS:-ns-lan3}"
        "${LAN4_NS:-ns-lan4}"
        "${LAN_NS:-ns-lan}"
    )

    local ns
    for ns in "${ALL_NS[@]}"; do
        if ns_exists "${ns}"; then
            ip netns exec "${ns}" pkill -TERM tcpdump 2>/dev/null || true
            ip netns exec "${ns}" pkill -TERM python3 2>/dev/null || true
            ip netns exec "${ns}" pkill -TERM iperf3 2>/dev/null || true
        fi
    done

    # 4. Delete veth pairs
    local veths=(
        "veth-wansrv" "veth-lancli" "veth-dutwan" "veth-dutlan"
        "veth-lan1" "veth-lan2" "veth-lan3" "veth-lan4"
    )
    local veth
    for veth in "${veths[@]}"; do
        if ip link show dev "${veth}" >/dev/null 2>&1; then
            ip link del dev "${veth}" 2>/dev/null || true
        fi
    done

    # 5. Delete namespaces
    for ns in "${ALL_NS[@]}"; do
        if ns_exists "${ns}"; then
            ip netns del "${ns}" 2>/dev/null || true
        fi
    done

    # 6. Delete bridges
    local br
    for br in "${WAN_BRIDGE:-br-test-wan}" "${LAN_BRIDGE:-br-test-lan}"; do
        if bridge_exists "${br}"; then
            iptables -D FORWARD -i "${br}" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -o "${br}" -j ACCEPT 2>/dev/null || true
            ip link set dev "${br}" down 2>/dev/null || true
            ip link del dev "${br}" 2>/dev/null || true
        fi
    done

    # 7. Restore physical interfaces
    local ifaces=()
    local ifname
    for ifname in "${WAN_IF:-}" "${LAN_IF:-}"; do
        if [[ -n "${ifname}" ]] && iface_exists_root "${ifname}"; then
            if [[ ! " ${ifaces[*]:-} " =~ [[:space:]]${ifname}[[:space:]] ]]; then
                ifaces+=("${ifname}")
            fi
        fi
    done

    for ifname in "${ifaces[@]:-}"; do
        if (( restore == 1 )); then
            restore_physical_interface "${ifname}"
        else
            tear_down_physical_interface "${ifname}"
        fi
    done

    # 8. Clean runtime state
    rm -f "${STATE_DIR}/topology_state.env" "${STATE_DIR}/last_capture.env" 2>/dev/null || true
    rm -f "${STATE_DIR}"/*.pid "${STATE_DIR}"/*.state 2>/dev/null || true

    if (( clean_logs_flag == 1 )); then clean_logs; fi
    if (( clean_captures_flag == 1 )); then clean_captures; fi

    log_success "Cleanup completed successfully!"
}

main "$@"
