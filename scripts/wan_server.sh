#!/usr/bin/env bash
# ==============================================================================
# CARRIER GATEWAY DUT - UPSTREAM WAN SERVER EMULATOR
# Controls Kea DHCPv4 and dnsmasq DHCP server in ns-wan (with automated fallback)
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

readonly NS_WAN="${WAN_NS:-ns-wan}"
readonly NS_IF="eth-wan"

usage() {
    cat <<'USAGE'
==================================================================
  Carrier Gateway DUT - Upstream WAN Server Emulator
==================================================================

Description:
  Controls upstream mock WAN servers (Kea DHCPv4, dnsmasq DHCP server)
  inside the ns-wan network namespace to provide dynamic WAN addressing
  and carrier core services to the physical or virtual DUT.

Usage:
  sudo ./scripts/wan_server.sh start [backend]
  sudo ./scripts/wan_server.sh stop
  ./scripts/wan_server.sh status
  ./scripts/wan_server.sh -h | --help

Commands:
  start [backend]   Start WAN DHCP server ('kea', 'dnsmasq', or auto) [Default: auto]
  stop              Stop all running WAN daemons
  status            Inspect status of WAN emulator daemons and DHCP leases
  -h, --help        Show this help message and exit

Examples:
  ./scripts/wan_server.sh -h
  sudo ./scripts/wan_server.sh start
  sudo ./scripts/wan_server.sh start dnsmasq
  ./scripts/wan_server.sh status
  sudo ./scripts/wan_server.sh stop

Suggested Next Steps:
  1. Inspect running leases:   ./scripts/wan_server.sh status
  2. Run test scenario:        sudo ./scripts/scenario.sh all
  3. Verify compliance:        ./scripts/verify_compliance.sh
==================================================================
USAGE
}

prepare_kea_runtime() {
    # 1. Unload AppArmor profiles if active on host (prevents logger_lockfile & pidfile EACCES)
    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -R /etc/apparmor.d/usr.sbin.kea-dhcp4 2>/dev/null || true
    fi

    # 2. Ensure Kea runtime directories exist with full permissions
    install -d -m 0777 /run/kea /run/lock/kea "${STATE_DIR}/kea"
    chmod 0777 /run/kea /run/lock/kea "${STATE_DIR}/kea" 2>/dev/null || true
    rm -f /run/kea/logger_lockfile /var/run/kea/logger_lockfile /run/lock/kea/logger_lockfile 2>/dev/null || true
    rm -f /run/kea/*.pid /run/lock/kea/*.pid 2>/dev/null || true
}

stop_services() {
    require_root
    load_config
    log_info "Stopping WAN server daemons in ${NS_WAN}..."

    stop_pidfile "${STATE_DIR}/kea-dhcp4.pid"
    stop_pidfile "${STATE_DIR}/dnsmasq-dhcp4.pid"

    if ns_exists "${NS_WAN}"; then
        ip netns exec "${NS_WAN}" pkill -TERM kea-dhcp4 2>/dev/null || true
        ip netns exec "${NS_WAN}" pkill -TERM dnsmasq 2>/dev/null || true
    fi
}

start_dhcp4_dnsmasq() {
    local pidfile="${STATE_DIR}/dnsmasq-dhcp4.pid"
    local conffile="${STATE_DIR}/dnsmasq-dhcp4.conf"
    local leasefile="${STATE_DIR}/dnsmasq-dhcp4.leases"
    local logfile="${LOG_DIR}/dnsmasq-dhcp4.log"

    require_command dnsmasq
    stop_pidfile "${pidfile}"

    {
        printf 'port=0\n'
        printf 'no-resolv\n'
        printf 'no-hosts\n'
        printf 'bind-interfaces\n'
        printf 'interface=%s\n' "${NS_IF}"
        printf 'dhcp-range=%s,%s,255.255.255.0,%ss\n' \
            "${WAN_DHCP_POOL_START:-10.10.0.100}" \
            "${WAN_DHCP_POOL_END:-10.10.0.200}" \
            "${DHCP_VALID_LIFETIME_SEC:-43200}"
        printf 'dhcp-option=option:router,%s\n' "${WAN_SERVER_IP:-10.10.0.1}"
        printf 'dhcp-option=option:dns-server,%s\n' "${WAN_SERVER_IP:-10.10.0.1}"
        if [[ -n "${DUT_WAN_IP:-}" && -n "${DUT_WAN_MAC:-}" ]]; then
            printf 'dhcp-host=%s,%s\n' "${DUT_WAN_MAC}" "${DUT_WAN_IP}"
        fi
        printf 'dhcp-authoritative\n'
        printf 'dhcp-leasefile=%s\n' "${leasefile}"
        printf 'log-facility=%s\n' "${logfile}"
        printf 'log-dhcp\n'
    } > "${conffile}"

    touch "${leasefile}"
    chmod 0666 "${leasefile}" 2>/dev/null || true

    nohup ip netns exec "${NS_WAN}" dnsmasq --conf-file="${conffile}" --pid-file="${pidfile}" > "${logfile}" 2>&1 &
    sleep 0.5

    if ! is_pidfile_running "${pidfile}"; then
        log_error "dnsmasq (IPv4 DHCP) failed to start. Check ${logfile}"
        tail -n 20 "${logfile}" >&2 || true
        die "Failed to start IPv4 DHCP server."
    fi
    log_success "dnsmasq (IPv4 DHCP server) active in ${NS_WAN} [PID: $(cat "${pidfile}")]"
}

start_dhcp4_kea() {
    prepare_kea_runtime

    local src="${PROJECT_ROOT}/config/kea/kea-dhcp4.conf.in"
    local dst="${STATE_DIR}/kea-dhcp4.conf"
    local pidfile="${STATE_DIR}/kea-dhcp4.pid"
    local logfile="${LOG_DIR}/kea-dhcp4.log"

    if ! command -v kea-dhcp4 >/dev/null 2>&1; then
        log_warn "kea-dhcp4 binary not found; falling back to dnsmasq."
        start_dhcp4_dnsmasq
        return 0
    fi

    # Render template
    render_template "${src}" "${dst}" "${NS_IF}"
    stop_pidfile "${pidfile}"

    nohup ip netns exec "${NS_WAN}" \
        env KEA_PIDFILE_DIR="/run/kea" KEA_LOCKFILE_DIR="/run/lock/kea" \
        kea-dhcp4 -c "${dst}" > "${logfile}" 2>&1 &
    printf '%s\n' "$!" > "${pidfile}"
    sleep 0.5

    if is_pidfile_running "${pidfile}"; then
        log_success "kea-dhcp4 server active in ${NS_WAN} [PID: $(cat "${pidfile}")]"
        return 0
    fi

    log_warn "kea-dhcp4 failed to start. Activating robust dnsmasq DHCP fallback..."
    tail -n 10 "${logfile}" >&2 || true
    start_dhcp4_dnsmasq
}

show_status() {
    load_config
    print_header "UPSTREAM WAN SERVER STATUS"
    printf 'Namespace: %s (Interface: %s)\n\n' "${NS_WAN}" "${NS_IF}"

    local daemons=(
        "kea-dhcp4:Kea DHCPv4 Server"
        "dnsmasq-dhcp4:dnsmasq DHCPv4 Server"
    )

    local entry name desc pidfile
    for entry in "${daemons[@]}"; do
        name="${entry%%:*}"
        desc="${entry#*:}"
        pidfile="${STATE_DIR}/${name}.pid"

        if is_pidfile_running "${pidfile}"; then
            printf '  \e[1;32m[RUNNING]\e[0m %-28s (PID: %s)\n' "${desc}" "$(cat "${pidfile}")"
        else
            printf '  \e[1;30m[STOPPED]\e[0m %-28s\n' "${desc}"
        fi
    done

    # Show active leases if available
    printf '\n--- [ACTIVE WAN DHCP LEASES] ---\n'
    local leasefile="${STATE_DIR}/dnsmasq-dhcp4.leases"
    if [[ -f "${leasefile}" && -s "${leasefile}" ]]; then
        printf '%-18s %-16s %-20s\n' "MAC Address" "Leased IP" "Hostname"
        printf '%s\n' "------------------------------------------------------------"
        awk '{printf "%-18s %-16s %-20s\n", $2, $3, $4}' "${leasefile}"
    else
        printf 'No active DHCP leases recorded yet.\n'
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

    local cmd="${1:-start}"
    case "${cmd}" in
        start)
            require_root
            ensure_runtime_dirs
            if ! ns_exists "${NS_WAN}"; then
                die "Namespace ${NS_WAN} does not exist. Please run sudo ./scripts/setup.sh first."
            fi
            local backend="${2:-auto}"
            if [[ "${backend}" == "dnsmasq" ]]; then
                start_dhcp4_dnsmasq
            else
                start_dhcp4_kea
            fi
            ;;
        stop)
            stop_services
            ;;
        status)
            show_status
            ;;
        *)
            log_error "Unknown command: ${cmd}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
