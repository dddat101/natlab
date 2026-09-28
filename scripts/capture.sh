#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - PACKET CAPTURE MANAGER
# Dual-Interface Packet Capture (WAN + LAN) using tcpdump (-U -s 0)
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
  Carrier Gateway DUT - Dual Packet Capture Manager
==================================================================

Description:
  Manages background packet capture on WAN and LAN interfaces concurrently.
  Captures pre-NAT and post-NAT traffic to dual PCAP files for automated
  conformance verification and forensic inspection.

Usage:
  sudo ./scripts/capture.sh start [--dual | target_ns target_if] [bpf_filter]
  sudo ./scripts/capture.sh stop
  ./scripts/capture.sh status
  ./scripts/capture.sh clean
  ./scripts/capture.sh -h | --help

Commands:
  start [--dual] [filter]    Start background packet capture (defaults to dual WAN + LAN)
  start <ns> <if> [filter]   Start capture on specific namespace & interface
  stop                       Stop all active background packet captures
  status                     Display capture daemons status and PCAP file sizes
  clean                      Stop captures and purge files in captures/
  -h, --help                 Show this help message and exit

Examples:
  sudo ./scripts/capture.sh start
  sudo ./scripts/capture.sh start --dual
  sudo ./scripts/capture.sh start ns-wan eth-wan "udp"
  ./scripts/capture.sh status
  sudo ./scripts/capture.sh stop
  ./scripts/capture.sh clean

Suggested Next Steps:
  - Run scenario:           sudo ./scripts/scenario.sh cone_nat
  - Verify compliance:      ./scripts/verify_compliance.sh
==================================================================
USAGE
}

start_single_sniffer() {
    local target_ns="$1"
    local target_if="$2"
    local pcap_file="$3"
    local pid_file="$4"
    local log_file="$5"
    local bpf_filter="${6:-}"
    local cap_tool="${7:-tcpdump}"

    local cap_cmd=()
    if [[ "${cap_tool}" == "tcpdump" ]]; then
        cap_cmd=("tcpdump" "-ni" "${target_if}" "-s" "0" "-U" "--immediate-mode" "-w" "${pcap_file}")
        if [[ -n "${bpf_filter}" ]]; then
            local -a filter_parts=()
            read -r -a filter_parts <<< "${bpf_filter}"
            cap_cmd+=("${filter_parts[@]}")
        fi
    else
        cap_cmd=("tshark" "-i" "${target_if}" "-l" "-w" "${pcap_file}")
        if [[ -n "${bpf_filter}" ]]; then
            cap_cmd+=("-f" "${bpf_filter}")
        fi
    fi

    local exec_prefix=()
    if [[ -n "${target_ns}" ]] && ns_exists "${target_ns}"; then
        exec_prefix=("ip" "netns" "exec" "${target_ns}")
    fi

    local target_desc="${target_ns:+${target_ns}:}${target_if}"
    log_info "Starting packet capture on ${target_desc} (${cap_tool})..."
    "${exec_prefix[@]}" nohup "${cap_cmd[@]}" > "${log_file}" 2>&1 &
    local cap_pid=$!
    printf '%s\n' "${cap_pid}" > "${pid_file}"
    chmod 0666 "${pid_file}" "${log_file}" 2>/dev/null || true

    sleep 0.4
    if ! is_pidfile_running "${pid_file}"; then
        log_error "Capture failed on ${target_desc}. Log output:"
        tail -n 20 "${log_file}" >&2 || true
        return 1
    fi
    log_success "Capture active on ${target_desc} -> ${pcap_file} [PID: ${cap_pid}]"
    return 0
}

start_capture() {
    require_root
    load_config
    stop_capture

    local bpf_filter="${CAPTURE_FILTER:-}"
    local is_dual=1
    local custom_ns=""
    local custom_if=""

    if [[ "${1:-}" == "--dual" ]]; then
        is_dual=1
        bpf_filter="${2:-${CAPTURE_FILTER:-}}"
    elif [[ -n "${1:-}" && -n "${2:-}" ]]; then
        is_dual=0
        custom_ns="$1"
        custom_if="$2"
        bpf_filter="${3:-${CAPTURE_FILTER:-}}"
    fi

    local timestamp ext cap_tool
    timestamp="$(date +%Y%m%d_%H%M%S)"

    # Prefer tcpdump for capturing to prevent dumpcap privilege drop
    if command -v "${TCPDUMP_BIN:-tcpdump}" >/dev/null 2>&1; then
        cap_tool="tcpdump"; ext="pcap"
    elif command -v "${TSHARK_BIN:-tshark}" >/dev/null 2>&1; then
        cap_tool="tshark"; ext="pcapng"
    else
        die "Neither tcpdump nor tshark is installed."
    fi

    ensure_runtime_dirs

    if (( is_dual == 1 )); then
        local pcap_wan="${CAPTURE_DIR}/capture_${timestamp}_wan.${ext}"
        local pcap_lan="${CAPTURE_DIR}/capture_${timestamp}_lan.${ext}"
        local pid_wan="${STATE_DIR}/capture_wan.pid"
        local pid_lan="${STATE_DIR}/capture_lan.pid"
        local log_wan="${LOG_DIR}/capture_${timestamp}_wan.log"
        local log_lan="${LOG_DIR}/capture_${timestamp}_lan.log"

        # 1. Start WAN Sniffer (in ns-wan on eth-wan)
        local wan_ns="${WAN_NS:-ns-wan}"
        local wan_if="eth-wan"
        if ! ns_exists "${wan_ns}"; then
            if bridge_exists "${WAN_BRIDGE:-br-test-wan}"; then
                wan_ns=""
                wan_if="${WAN_BRIDGE:-br-test-wan}"
            fi
        fi
        start_single_sniffer "${wan_ns}" "${wan_if}" "${pcap_wan}" "${pid_wan}" "${log_wan}" "${bpf_filter}" "${cap_tool}"

        # 2. Start LAN Sniffer (on br-test-lan on host or in ns-lan1 on eth0)
        local lan_ns=""
        local lan_if="${LAN_BRIDGE:-br-test-lan}"
        if ! bridge_exists "${lan_if}"; then
            lan_ns="${LAN1_NS:-ns-lan1}"
            lan_if="eth0"
        fi
        start_single_sniffer "${lan_ns}" "${lan_if}" "${pcap_lan}" "${pid_lan}" "${log_lan}" "${bpf_filter}" "${cap_tool}"

        # Save state environment
        cat >"${STATE_DIR}/last_capture.env" <<EOF
LAST_PCAP='${pcap_wan}'
LAST_PCAP_WAN='${pcap_wan}'
LAST_PCAP_LAN='${pcap_lan}'
CAPTURE_TIMESTAMP='$(date -Iseconds)'
CAPTURE_TOOL='${cap_tool}'
CAPTURE_MODE='dual'
EOF
        printf '%s\n' "${pcap_wan}" > "${STATE_DIR}/latest_capture.txt"
        cp -f "${pid_wan}" "${STATE_DIR}/capture.pid" 2>/dev/null || true
    else
        local pcap_single="${CAPTURE_DIR}/capture_${timestamp}.${ext}"
        local pid_single="${STATE_DIR}/capture.pid"
        local log_single="${LOG_DIR}/capture_${timestamp}.log"

        start_single_sniffer "${custom_ns}" "${custom_if}" "${pcap_single}" "${pid_single}" "${log_single}" "${bpf_filter}" "${cap_tool}"

        cat >"${STATE_DIR}/last_capture.env" <<EOF
LAST_PCAP='${pcap_single}'
LAST_PCAP_WAN='${pcap_single}'
LAST_PCAP_LAN=''
CAPTURE_TIMESTAMP='$(date -Iseconds)'
CAPTURE_TOOL='${cap_tool}'
CAPTURE_MODE='single'
CAPTURE_NS='${custom_ns}'
CAPTURE_IF='${custom_if}'
EOF
        printf '%s\n' "${pcap_single}" > "${STATE_DIR}/latest_capture.txt"
    fi
}

stop_capture() {
    require_root
    load_config

    local pidfile
    for pidfile in "${STATE_DIR}/capture_wan.pid" "${STATE_DIR}/capture_lan.pid" "${STATE_DIR}/capture.pid"; do
        if [[ -f "${pidfile}" ]]; then
            stop_pidfile "${pidfile}" "Packet Capture"
        fi
    done

    # Ensure PCAPs are accessible by regular non-root users
    find "${CAPTURE_DIR}" -maxdepth 1 -name '*.pcap*' -type f -exec chmod 0666 {} + 2>/dev/null || true
}

show_status() {
    load_config
    print_header "CAPTURE STATUS"

    local running=0
    if is_pidfile_running "${STATE_DIR}/capture_wan.pid"; then
        printf '  WAN Capture: \e[1;32mRUNNING\e[0m (PID %s)\n' "$(cat "${STATE_DIR}/capture_wan.pid")"
        running=1
    fi
    if is_pidfile_running "${STATE_DIR}/capture_lan.pid"; then
        printf '  LAN Capture: \e[1;32mRUNNING\e[0m (PID %s)\n' "$(cat "${STATE_DIR}/capture_lan.pid")"
        running=1
    fi
    if (( running == 0 )); then
        if is_pidfile_running "${STATE_DIR}/capture.pid"; then
            printf '  Single Capture: \e[1;32mRUNNING\e[0m (PID %s)\n' "$(cat "${STATE_DIR}/capture.pid")"
            running=1
        fi
    fi

    if (( running == 0 )); then
        printf '  Status: \e[1;33mSTOPPED\e[0m\n'
    fi

    if [[ -f "${STATE_DIR}/last_capture.env" ]]; then
        # shellcheck disable=SC1090
        source "${STATE_DIR}/last_capture.env"
        printf '\n--- [LAST CAPTURE ARTIFACTS] ---\n'
        if [[ -n "${LAST_PCAP_WAN:-}" && -f "${LAST_PCAP_WAN}" ]]; then
            printf '  WAN PCAP: %s (%s)\n' "$(basename "${LAST_PCAP_WAN}")" "$(du -h "${LAST_PCAP_WAN}" | cut -f1)"
        fi
        if [[ -n "${LAST_PCAP_LAN:-}" && -f "${LAST_PCAP_LAN}" ]]; then
            printf '  LAN PCAP: %s (%s)\n' "$(basename "${LAST_PCAP_LAN}")" "$(du -h "${LAST_PCAP_LAN}" | cut -f1)"
        fi
        printf '  Captured: %s\n' "${CAPTURE_TIMESTAMP:-<unknown>}"
    fi
}

main() {
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    load_config
    case "${1:-status}" in
        start)  shift; start_capture "$@" ;;
        stop)   stop_capture ;;
        status) show_status ;;
        clean)  stop_capture; clean_captures ;;
        *)      usage; exit 2 ;;
    esac
}

main "$@"
