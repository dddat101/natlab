#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - PRODUCTION COMMON HELPER LIBRARY
# Reusable utilities for lifecycle, namespaces, socket polling & network safety
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_LIB_DIR}/../.." && pwd -P)"
readonly CONFIG_FILE="${PROJECT_ROOT}/config.env"
readonly LOG_TAG="LAB-FRAMEWORK"

# 1. Logging & Terminal Output
log_info()    { printf '\e[1;32m[INFO]\e[0m    %s\n' "$*"; }
log_success() { printf '\e[1;32m[PASS]\e[0m    %s\n' "$*"; }
log_warn()    { printf '\e[1;33m[WARN]\e[0m    %s\n' "$*" >&2; }
log_error()   { printf '\e[1;31m[ERROR]\e[0m   %s\n' "$*" >&2; }
log_step()    { printf '\e[1;36m===> %s\e[0m\n' "$*"; }
die()         { log_error "$*"; exit 1; }

log_debug() {
    if [[ "${DEBUG:-0}" == "1" || "${VERBOSE:-0}" == "1" ]]; then
        printf '\e[1;34m[DEBUG]\e[0m   %s\n' "$*" >&2
    fi
}

print_header() {
    local title="$1"
    printf '==================================================================\n'
    printf '  %s\n' "${title}"
    printf '==================================================================\n'
}

print_section() {
    local section="$1"
    printf '\n--- [%s] ---\n' "${section}"
}

# 2. Privileges & Tool Availability
require_root() {
    if (( EUID != 0 )); then
        die "This command requires root/sudo privileges. Please run with sudo."
    fi
}
is_root() { (( EUID == 0 )); }

require_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        die "Required command is not installed: ${cmd}"
    fi
}
require_cmd() { require_command "$@"; }

check_command() {
    local cmd="$1"
    command -v "${cmd}" >/dev/null 2>&1
}

# 3. Config & Runtime Dirs
load_config() {
    local config_path="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${config_path}" ]]; then
        if [[ -f "${PROJECT_ROOT}/config.env.example" ]]; then
            log_warn "config.env not found. Auto-generating from config.env.example..."
            cp "${PROJECT_ROOT}/config.env.example" "${config_path}"
        else
            die "Missing configuration file: ${config_path}. Create it from config.env.example."
        fi
    fi

    # shellcheck disable=SC1090
    source "${config_path}"

    # Defaults
    : "${LAB_ROLE:=single}"
    : "${TOPOLOGY_MODE:=virtual}"
    : "${RESTORE_INTERFACES_ON_CLEANUP:=1}"
    : "${CAPTURE_DIR:=${PROJECT_ROOT}/captures}"
    : "${LOG_DIR:=${PROJECT_ROOT}/logs}"
    : "${STATE_DIR:=${PROJECT_ROOT}/state}"
    : "${NS_IF:=eth-wan}"

    # Auto-detect Python Virtualenv
    if [[ -z "${PYTHON_BIN:-}" ]]; then
        if [[ -x "${PROJECT_ROOT}/.venv/bin/python3" ]]; then
            PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python3"
        else
            PYTHON_BIN="python3"
        fi
    fi

    if [[ "${CAPTURE_DIR}" != /* ]]; then CAPTURE_DIR="${PROJECT_ROOT}/${CAPTURE_DIR}"; fi
    if [[ "${LOG_DIR}" != /* ]]; then LOG_DIR="${PROJECT_ROOT}/${LOG_DIR}"; fi
    if [[ "${STATE_DIR}" != /* ]]; then STATE_DIR="${PROJECT_ROOT}/${STATE_DIR}"; fi

    ensure_runtime_dirs
}

ensure_runtime_dirs() {
    install -d -m 0777 "${CAPTURE_DIR}" "${LOG_DIR}" "${STATE_DIR}"
    chmod 0777 "${CAPTURE_DIR}" "${LOG_DIR}" "${STATE_DIR}" 2>/dev/null || true
    chmod -R a+rw "${CAPTURE_DIR}" "${LOG_DIR}" "${STATE_DIR}" 2>/dev/null || true
}

clean_logs() {
    ensure_runtime_dirs
    log_info "Cleaning log files in ${LOG_DIR}..."
    find "${LOG_DIR}" -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
    log_info "Logs directory cleaned."
}

clean_captures() {
    ensure_runtime_dirs
    log_info "Cleaning PCAP capture files in ${CAPTURE_DIR}..."
    find "${CAPTURE_DIR}" -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
    rm -f "${STATE_DIR}/last_capture.env" "${STATE_DIR}/latest_capture.txt" 2>/dev/null || true
    log_info "Captures directory cleaned."
}

# 4. Network Safety & Namespaces
iface_exists_root() { ip link show dev "$1" >/dev/null 2>&1; }
iface_exists_ns()   { ip netns exec "$1" ip link show dev "$2" >/dev/null 2>&1; }
ns_exists()         { ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$1"; }
bridge_exists()     { ip link show dev "$1" >/dev/null 2>&1; }

assert_safe_test_if() {
    local iface="$1"
    [[ -n "${iface}" ]] || die "Interface name cannot be empty."
    [[ "${iface}" != "lo" ]] || die "Refusing to use loopback interface."
    iface_exists_root "${iface}" || die "Interface not found in root namespace: ${iface}"

    # Protect host default route (uplink)
    if ip route show default 2>/dev/null | grep -Eq "dev[[:space:]]+${iface}([[:space:]]|$)"; then
        die "Interface ${iface} carries host default route! Refusing to use primary interface."
    fi

    # NetworkManager smart unmanage & flush
    if ip -4 addr show dev "${iface}" 2>/dev/null | grep -q 'inet '; then
        log_warn "Interface ${iface} has host IPv4 address. Flushing and setting unmanaged..."
        command -v nmcli >/dev/null 2>&1 && nmcli device set "${iface}" managed no 2>/dev/null || true
        ip addr flush dev "${iface}" 2>/dev/null || true
    fi
}

namespace_ip() {
    local ns="${1:-ns-wan}"
    local iface="${2:-${NS_IF:-eth-wan}}"
    if ns_exists "${ns}"; then
        (ip netns exec "${ns}" ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    else
        (ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    fi
}

namespace_mac() {
    local ns="${1:-ns-wan}"
    local iface="${2:-${NS_IF:-eth-wan}}"
    if ns_exists "${ns}"; then
        (ip netns exec "${ns}" cat "/sys/class/net/${iface}/address" 2>/dev/null || true) | head -n1 || echo ""
    else
        (cat "/sys/class/net/${iface}/address" 2>/dev/null || true) | head -n1 || echo ""
    fi
}

exec_in_ns() {
    local ns="$1"
    shift
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        ip netns exec "${ns}" "$@"
    else
        "$@"
    fi
}

is_ip_reachable() {
    local target="$1"
    local timeout="${2:-1}"
    local ns="${3:-}"
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        ip netns exec "${ns}" ping -c 1 -W "${timeout}" "${target}" >/dev/null 2>&1
    else
        ping -c 1 -W "${timeout}" "${target}" >/dev/null 2>&1
    fi
}

wait_for_ping() {
    local target="$1"
    local timeout="${2:-10}"
    local ns="${3:-}"
    local elapsed=0
    while ! is_ip_reachable "${target}" 1 "${ns}"; do
        sleep 1
        elapsed=$((elapsed + 1))
        if (( elapsed >= timeout )); then
            log_warn "Timeout waiting for ping response from ${target} after ${timeout}s"
            return 1
        fi
    done
    return 0
}

# 5. Bridges & Interface Recovery
bridge_create() {
    local bridge="$1"
    if ! bridge_exists "${bridge}"; then
        ip link add name "${bridge}" type bridge
    fi
    ip addr flush dev "${bridge}" 2>/dev/null || true
    sysctl -q -w "net.ipv6.conf.${bridge}.disable_ipv6=1" 2>/dev/null || true
    ip link set dev "${bridge}" type bridge stp_state 0 mcast_snooping 0 2>/dev/null || true
    ip link set dev "${bridge}" up
    # Ensure bridge forwarding is not dropped by host iptables / docker firewall
    iptables -C FORWARD -i "${bridge}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "${bridge}" -j ACCEPT 2>/dev/null || true
    iptables -C FORWARD -o "${bridge}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "${bridge}" -j ACCEPT 2>/dev/null || true
}

get_usb_network_interfaces() {
    local iface name
    local default_if
    default_if="$(ip route show default 2>/dev/null | awk '/dev/ {print $5}' | head -n1 || echo "")"
    local nics=()
    for iface in /sys/class/net/*; do
        [[ -e "${iface}" ]] || continue
        name="$(basename "${iface}")"
        [[ "${name}" != "lo" ]] || continue
        if [[ -d "${iface}/device" ]] && readlink -f "${iface}/device" 2>/dev/null | grep -q "usb"; then
            if [[ "${name}" != "${default_if}" ]]; then
                nics+=("${name}")
            fi
        fi
    done
    printf '%s\n' "${nics[@]:-}"
}

attach_physical_to_bridge() {
    local iface="$1"
    local bridge="$2"
    assert_safe_test_if "${iface}"
    command -v nmcli >/dev/null 2>&1 && nmcli device set "${iface}" managed no 2>/dev/null || true
    ip link set dev "${iface}" down
    ip addr flush dev "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" master "${bridge}"
    ip link set dev "${iface}" up
}

restore_physical_interface() {
    local iface="$1"
    require_root
    [[ -n "${iface}" ]] || return 0
    iface_exists_root "${iface}" || return 0

    log_info "Restoring interface ${iface} to UP state with DHCP..."
    ip link set dev "${iface}" nomaster 2>/dev/null || true
    ip addr flush dev "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" up

    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "${iface}" managed yes 2>/dev/null || true
        nmcli device set "${iface}" autoconnect yes 2>/dev/null || true
        nmcli device connect "${iface}" >/dev/null 2>&1 || true
    fi

    if ip link show dev "${iface}" 2>/dev/null | grep -q "LOWER_UP"; then
        local got_ip=0
        for (( i=0; i<4; i++ )); do
            if ip -4 -o addr show dev "${iface}" 2>/dev/null | grep -q 'inet '; then
                got_ip=1; break
            fi
            sleep 0.5
        done
        if (( got_ip == 0 )) && command -v dhclient >/dev/null 2>&1; then
            dhclient -4 -nw "${iface}" 2>/dev/null || true
        fi
    fi
}

tear_down_physical_interface() {
    local iface="$1"
    require_root
    [[ -n "${iface}" ]] || return 0
    iface_exists_root "${iface}" || return 0
    command -v dhclient >/dev/null 2>&1 && dhclient -x "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" nomaster 2>/dev/null || true
    ip addr flush dev "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" down 2>/dev/null || true
    command -v nmcli >/dev/null 2>&1 && nmcli device set "${iface}" managed yes 2>/dev/null || true
}

cleanup_bridge_and_nic() {
    local bridge="$1"
    local iface="${2:-}"
    local restore="${3:-${RESTORE_INTERFACES_ON_CLEANUP:-1}}"

    if [[ -n "${iface}" ]] && iface_exists_root "${iface}"; then
        if (( restore == 1 )); then
            restore_physical_interface "${iface}"
        else
            tear_down_physical_interface "${iface}"
        fi
    fi
    if bridge_exists "${bridge}"; then
        ip link set dev "${bridge}" down 2>/dev/null || true
        ip link del dev "${bridge}" 2>/dev/null || true
    fi
}

ns_create() {
    local ns="$1"
    if ! ns_exists "${ns}"; then ip netns add "${ns}"; fi
    ip -n "${ns}" link set lo up
}

create_veth_to_ns() {
    local ns="$1" host_if="$2" ns_if="$3" bridge="$4" cidr="$5" gateway="${6:-}"
    ns_create "${ns}"
    if ! iface_exists_ns "${ns}" "${ns_if}"; then
        ip link del dev "${host_if}" 2>/dev/null || true
        ip link add "${host_if}" type veth peer name "${ns_if}" netns "${ns}"
    fi
    ip link set dev "${host_if}" master "${bridge}"
    ip link set dev "${host_if}" up
    ip -n "${ns}" link set dev "${ns_if}" up
    ip -n "${ns}" -4 addr flush dev "${ns_if}" 2>/dev/null || true
    ip -n "${ns}" addr add "${cidr}" dev "${ns_if}"
    if [[ -n "${gateway}" ]]; then
        ip -n "${ns}" route replace default via "${gateway}" dev "${ns_if}" 2>/dev/null || true
    fi
}

# 6. Upstream WAN Services & DHCP Management (Kea Triad Standard: kea-dhcp4 + kea-dhcp6 + radvd)
prepare_kea_runtime() {
    # 1. Unload AppArmor profiles if active on host (prevents logger_lockfile & pidfile EACCES)
    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -R /etc/apparmor.d/usr.sbin.kea-dhcp4 2>/dev/null || true
        apparmor_parser -R /etc/apparmor.d/usr.sbin.kea-dhcp6 2>/dev/null || true
    fi

    # 2. Ensure Kea runtime directories exist with full permissions
    install -d -m 0777 /run/kea /run/lock/kea "${STATE_DIR}/kea"
    chmod 0777 /run/kea /run/lock/kea "${STATE_DIR}/kea" 2>/dev/null || true
    rm -f /run/kea/logger_lockfile /var/run/kea/logger_lockfile /run/lock/kea/logger_lockfile 2>/dev/null || true
    rm -f /run/kea/*.pid /run/lock/kea/*.pid 2>/dev/null || true
}

render_wan_template() {
    local src="$1"
    local dst="$2"
    local iface="${3:-eth0}"

    local v4_dns_list="${WAN_IPV4_DNS:-10.10.0.1}"
    if [[ -n "${WAN_IPV4_DNS2:-}" ]]; then
        v4_dns_list="${WAN_IPV4_DNS}, ${WAN_IPV4_DNS2}"
    fi

    local v6_dns_list="${WAN_IPV6_DNS:-2001:db8:10::1}"
    local v6_radvd_dns="${WAN_IPV6_DNS:-2001:db8:10::1}"
    if [[ -n "${WAN_IPV6_DNS2:-}" ]]; then
        v6_dns_list="${WAN_IPV6_DNS}, ${WAN_IPV6_DNS2}"
        v6_radvd_dns="${WAN_IPV6_DNS} ${WAN_IPV6_DNS2}"
    fi

    sed \
        -e "s|@DUT_IF@|${iface}|g" \
        -e "s|@WAN_IPV4_SUBNET@|${WAN_IPV4_SUBNET:-10.10.0.0/24}|g" \
        -e "s|@WAN_IPV4_POOL_START@|${WAN_IPV4_POOL_START:-10.10.0.100}|g" \
        -e "s|@WAN_IPV4_POOL_END@|${WAN_IPV4_POOL_END:-10.10.0.200}|g" \
        -e "s|@WAN_IPV4_ROUTER@|${WAN_IPV4_ROUTER:-10.10.0.1}|g" \
        -e "s|@WAN_IPV4_DNS@|${v4_dns_list}|g" \
        -e "s|@WAN_IPV4_DNS1@|${WAN_IPV4_DNS:-10.10.0.1}|g" \
        -e "s|@WAN_IPV4_DNS2@|${WAN_IPV4_DNS2:-}|g" \
        -e "s|@WAN_IPV6_PREFIX@|${WAN_IPV6_PREFIX:-2001:db8:10::/64}|g" \
        -e "s|@WAN_IPV6_POOL_START@|${WAN_IPV6_POOL_START:-2001:db8:10::1000}|g" \
        -e "s|@WAN_IPV6_POOL_END@|${WAN_IPV6_POOL_END:-2001:db8:10::1fff}|g" \
        -e "s|@PD_PREFIX@|${PD_PREFIX:-2001:db8:100::}|g" \
        -e "s|@PD_PREFIX_LEN@|${PD_PREFIX_LEN:-56}|g" \
        -e "s|@PD_DELEGATED_LEN@|${PD_DELEGATED_LEN:-60}|g" \
        -e "s|@WAN_IPV6_DNS@|${v6_dns_list}|g" \
        -e "s|@WAN_IPV6_RDNSS@|${v6_radvd_dns}|g" \
        -e "s|@AFTR_NAME@|${AFTR_NAME:-aftr.example.com}|g" \
        -e "s|@DHCP_VALID_LIFETIME_SEC@|${DHCP_VALID_LIFETIME_SEC:-43200}|g" \
        -e "s|@DHCP_RENEW_TIMER_SEC@|${DHCP_RENEW_TIMER_SEC:-21600}|g" \
        -e "s|@DHCP_REBIND_TIMER_SEC@|${DHCP_REBIND_TIMER_SEC:-34560}|g" \
        -e "s|@DHCP6_PREFERRED_LIFETIME_SEC@|${DHCP6_PREFERRED_LIFETIME_SEC:-28800}|g" \
        -e "s|@RA_LIFETIME_SEC@|${RA_LIFETIME_SEC:-1800}|g" \
        -e "s|@RA_MIN_INTERVAL_SEC@|${RA_MIN_INTERVAL_SEC:-3}|g" \
        -e "s|@RA_MAX_INTERVAL_SEC@|${RA_MAX_INTERVAL_SEC:-10}|g" \
        "${src}" > "${dst}"
}

wait_for_ipv6_dad() {
    local ns="${1:-}"
    local iface="${2:-eth0}"
    local max_wait="${3:-5}"
    local prefix=()
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        prefix=("ip" "netns" "exec" "${ns}")
    fi

    local i
    for (( i=0; i<max_wait*10; i++ )); do
        if ! "${prefix[@]}" ip -6 addr show dev "${iface}" 2>/dev/null | grep -q "tentative"; then
            return 0
        fi
        sleep 0.1
    done
    return 0
}

namespace_ipv6() {
    local ns="${1:-ns-wan}"
    local iface="${2:-eth0}"
    if ns_exists "${ns}"; then
        (ip netns exec "${ns}" ip -6 -o addr show dev "${iface}" scope global 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    else
        (ip -6 -o addr show dev "${iface}" scope global 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    fi
}

wan_dhcp_server() {
    local action="$1"
    local ip_version="${2:-${IP_VERSION:-4}}"
    local wan_ns="${3:-${WAN_NS:-ns-wan}}"
    local wan_if="${4:-eth0}"
    local pidfile_dnsmasq="${STATE_DIR}/dnsmasq-wan.pid"
    local pidfile_dnsmasq_v4="${STATE_DIR}/dnsmasq-wan-v4.pid"
    local pidfile_kea4="${STATE_DIR}/kea-dhcp4.pid"
    local pidfile_kea="${STATE_DIR}/kea-dhcp6.pid"
    local pidfile_radvd="${STATE_DIR}/radvd.pid"
    local conffile_dnsmasq="${STATE_DIR}/dnsmasq-wan.conf"
    local leasefile_dnsmasq="${STATE_DIR}/dnsmasq-wan.leases"
    local logfile_dnsmasq="${LOG_DIR}/dnsmasq-wan.log"

    case "${action}" in
        start)
            require_root
            wan_dhcp_server stop "${ip_version}" "${wan_ns}" "${wan_if}" >/dev/null 2>&1 || true

            local wan_v4_start="${WAN_IPV4_POOL_START:-${WAN_DHCP_START:-10.10.0.100}}"
            local wan_v4_end="${WAN_IPV4_POOL_END:-${WAN_DHCP_END:-10.10.0.200}}"
            local wan_v4_lease="${DHCP_VALID_LIFETIME_SEC:-${WAN_DHCP_LEASE:-12h}}"
            [[ "${wan_v4_lease}" =~ ^[0-9]+$ ]] && wan_v4_lease="${wan_v4_lease}s"
            local wan_v4_gw="${WAN_IPV4_ROUTER:-${WAN_NS_GW:-${WAN_NS_IP%/*}}}"
            local wan_v4_dns="${WAN_IPV4_DNS:-${wan_v4_gw}}"
            local wan_v4_dns2="${WAN_IPV4_DNS2:-}"

            local wan_v6_prefix="${WAN_IPV6_PREFIX:-${WAN_IPV6_CIDR:-${WAN_NS_IP6:-2001:db8:10::/64}}}"
            local wan_v6_base="${wan_v6_prefix%/*}"
            local wan_v6_start="${WAN_IPV6_POOL_START:-${WAN_DHCP6_START:-${wan_v6_base%::*}::1000}}"
            local wan_v6_end="${WAN_IPV6_POOL_END:-${WAN_DHCP6_END:-${wan_v6_base%::*}::1fff}}"
            local wan_v6_gw="${WAN_IPV6_DNS:-${WAN_NS_GW6:-${WAN_NS_IP6%/*}}}"
            local wan_v6_dns="${WAN_IPV6_DNS:-${wan_v6_gw}}"
            local wan_v6_dns2="${WAN_IPV6_DNS2:-}"

            local is_v6=0
            local is_v4=0
            if [[ "${ip_version}" == "dual" || "${ip_version}" == "dual-stack" || "${ip_version}" == "ds" ]]; then
                is_v6=1
                is_v4=1
            elif [[ "${ip_version}" == "6" ]]; then
                is_v6=1
            else
                is_v4=1
            fi

            local backend="${WAN_DHCP_BACKEND:-kea}"
            local use_kea=0
            if (( is_v6 == 1 )); then
                if [[ "${backend}" == "kea" || "${backend}" == "auto" ]]; then
                    if command -v kea-dhcp6 >/dev/null 2>&1 && command -v radvd >/dev/null 2>&1; then
                        use_kea=1
                    fi
                fi
            fi

            if (( use_kea == 1 )); then
                prepare_kea_runtime
                local kea_tmpl="${PROJECT_ROOT}/config/kea/kea-dhcp6.conf.in"
                local radvd_tmpl="${PROJECT_ROOT}/config/radvd/radvd.conf.in"
                local kea_conf="${STATE_DIR}/kea-dhcp6.conf"
                local radvd_conf="${STATE_DIR}/radvd.conf"

                # Ensure link-local exists on interface for raw socket binding
                if ! ip netns exec "${wan_ns}" ip -6 -o addr show dev "${wan_if}" scope link 2>/dev/null | grep -q 'inet6 '; then
                    ip -n "${wan_ns}" -6 addr add "fe80::254/64" dev "${wan_if}" nodad 2>/dev/null || true
                fi

                # Enable IPv6 forwarding in wan_ns
                ip netns exec "${wan_ns}" sysctl -q -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
                ip netns exec "${wan_ns}" sysctl -q -w net.ipv6.conf.default.forwarding=1 2>/dev/null || true
                ip netns exec "${wan_ns}" sysctl -q -w "net.ipv6.conf.${wan_if}.forwarding=1" 2>/dev/null || true

                render_wan_template "${kea_tmpl}" "${kea_conf}" "${wan_if}"
                render_wan_template "${radvd_tmpl}" "${radvd_conf}" "${wan_if}"
                chmod 0644 "${radvd_conf}" 2>/dev/null || true

                # Start radvd (M=1, O=1)
                ip netns exec "${wan_ns}" radvd -C "${radvd_conf}" -p "${pidfile_radvd}" -m logfile -l "${LOG_DIR}/radvd.log"
                log_info "radvd started in ${wan_ns} (M=1, O=1) [PID $(cat "${pidfile_radvd}" 2>/dev/null || echo '?')]"

                # Start Kea DHCPv6 (IA_NA + IA_PD)
                nohup ip netns exec "${wan_ns}" \
                    env KEA_PIDFILE_DIR="/run/kea" KEA_LOCKFILE_DIR="/run/lock/kea" \
                    kea-dhcp6 -c "${kea_conf}" > "${LOG_DIR}/kea-dhcp6.log" 2>&1 &
                printf '%s\n' "$!" > "${pidfile_kea}"
                sleep 0.5

                if is_pidfile_running "${pidfile_kea}" && ! grep -q "DHCPSRV_NO_SOCKETS_OPEN" "${LOG_DIR}/kea-dhcp6.log" 2>/dev/null; then
                    log_info "WAN DHCPv6 Server (kea-dhcp6) started in ${wan_ns} (IA_NA + IA_PD: ${PD_PREFIX:-2001:db8:100::}/${PD_PREFIX_LEN:-56} -> /${PD_DELEGATED_LEN:-60}) [PID $(cat "${pidfile_kea}")]"
                else
                    log_warn "kea-dhcp6 failed to start or bind sockets. Falling back to dnsmasq..."
                    stop_pidfile "${pidfile_kea}"
                    stop_pidfile "${pidfile_radvd}"
                    use_kea=0
                fi
            fi

            # Start IPv4 DHCP server
            if (( is_v4 == 1 )); then
                local kea4_started=0
                if [[ "${backend}" == "kea" || "${backend}" == "auto" ]] && command -v kea-dhcp4 >/dev/null 2>&1; then
                    prepare_kea_runtime
                    local kea4_tmpl="${PROJECT_ROOT}/config/kea/kea-dhcp4.conf.in"
                    local kea4_conf="${STATE_DIR}/kea-dhcp4.conf"
                    render_wan_template "${kea4_tmpl}" "${kea4_conf}" "${wan_if}"

                    nohup ip netns exec "${wan_ns}" \
                        env KEA_PIDFILE_DIR="/run/kea" KEA_LOCKFILE_DIR="/run/lock/kea" \
                        kea-dhcp4 -c "${kea4_conf}" > "${LOG_DIR}/kea-dhcp4.log" 2>&1 &
                    printf '%s\n' "$!" > "${pidfile_kea4}"
                    sleep 0.5

                    if is_pidfile_running "${pidfile_kea4}"; then
                        log_info "WAN DHCPv4 Server (kea-dhcp4) started in ${wan_ns} [PID $(cat "${pidfile_kea4}")]"
                        kea4_started=1
                    else
                        log_warn "kea-dhcp4 failed to start. Falling back to dnsmasq for IPv4..."
                        stop_pidfile "${pidfile_kea4}"
                    fi
                fi

                # If Kea4 wasn't used or failed, run dnsmasq for IPv4
                if (( kea4_started == 0 )); then
                    require_cmd dnsmasq
                    touch "${leasefile_dnsmasq}"
                    chmod 0666 "${leasefile_dnsmasq}" 2>/dev/null || true
                    local conf_v4="${STATE_DIR}/dnsmasq-wan-v4.conf"
                    cat >"${conf_v4}" <<EOF
port=0
no-resolv
no-hosts
bind-interfaces
interface=${wan_if}
dhcp-range=${wan_v4_start},${wan_v4_end},255.255.255.0,${wan_v4_lease}
dhcp-option=option:router,${wan_v4_gw}
dhcp-option=option:dns-server,${wan_v4_dns}
dhcp-authoritative
dhcp-leasefile=${leasefile_dnsmasq}
log-facility=${logfile_dnsmasq}
log-dhcp
EOF
                    if [[ -n "${DUT_WAN_MAC:-}" ]]; then
                        printf 'dhcp-host=%s,%s\n' "${DUT_WAN_MAC}" "${DUT_WAN_IP:-10.10.0.1}" >>"${conf_v4}"
                    fi
                    ip netns exec "${wan_ns}" dnsmasq --conf-file="${conf_v4}" --pid-file="${pidfile_dnsmasq_v4}"
                    log_info "WAN DHCPv4 Server (dnsmasq fallback) started in ${wan_ns} [PID $(cat "${pidfile_dnsmasq_v4}" 2>/dev/null || echo '?')]"
                fi
            fi

            # Fallback for IPv6 if Kea was not used/failed
            if (( is_v6 == 1 && use_kea == 0 )); then
                require_cmd dnsmasq
                wait_for_ipv6_dad "${wan_ns}" "${wan_if}" 5
                touch "${leasefile_dnsmasq}"
                chmod 0666 "${leasefile_dnsmasq}" 2>/dev/null || true
                local conf_v6="${STATE_DIR}/dnsmasq-wan-v6.conf"
                cat >"${conf_v6}" <<EOF
port=0
no-resolv
no-hosts
bind-interfaces
interface=${wan_if}
enable-ra
dhcp-range=${wan_v6_start},${wan_v6_end},slaac,ra-stateless,64,${wan_v4_lease}
dhcp-range=${wan_v6_start},${wan_v6_end},64,${wan_v4_lease}
dhcp-option=option6:dns-server,[${wan_v6_dns}]
dhcp-authoritative
dhcp-leasefile=${leasefile_dnsmasq}
log-facility=${logfile_dnsmasq}
log-dhcp
EOF
                if [[ -n "${AFTR_NAME:-}" ]]; then
                    printf 'dhcp-option=option6:64,%s\n' "${AFTR_NAME}" >>"${conf_v6}"
                fi
                if [[ -n "${DUT_WAN_MAC:-}" ]]; then
                    printf 'dhcp-host=%s,[%s]\n' "${DUT_WAN_MAC}" "${DUT_WAN_IP6:-2001:db8:10::1}" >>"${conf_v6}"
                fi
                ip netns exec "${wan_ns}" dnsmasq --conf-file="${conf_v6}" --pid-file="${pidfile_dnsmasq}"
                log_info "WAN DHCPv6 Server (dnsmasq fallback) started in ${wan_ns} [PID $(cat "${pidfile_dnsmasq}" 2>/dev/null || echo '?')]"
            fi
            ;;

        stop)
            stop_pidfile "${pidfile_kea4}"
            stop_pidfile "${pidfile_kea}"
            stop_pidfile "${pidfile_radvd}"
            stop_pidfile "${pidfile_dnsmasq_v4}"
            stop_pidfile "${pidfile_dnsmasq}"
            if ns_exists "${wan_ns}"; then
                ip netns exec "${wan_ns}" pkill -TERM kea-dhcp4 2>/dev/null || true
                ip netns exec "${wan_ns}" pkill -TERM kea-dhcp6 2>/dev/null || true
                ip netns exec "${wan_ns}" pkill -TERM radvd 2>/dev/null || true
                ip netns exec "${wan_ns}" pkill -TERM dnsmasq 2>/dev/null || true
            fi
            rm -f "${conffile_dnsmasq}" "${STATE_DIR}"/dnsmasq-wan-*.conf "${STATE_DIR}"/kea-dhcp*.conf "${STATE_DIR}/radvd.conf" 2>/dev/null || true
            log_info "WAN DHCP Server stopped."
            ;;

        status)
            local running=0
            if is_pidfile_running "${pidfile_kea4}"; then
                printf 'WAN DHCPv4 Server (kea-dhcp4): RUNNING (PID %s in %s)\n' "$(cat "${pidfile_kea4}")" "${wan_ns}"
                running=1
            fi
            if is_pidfile_running "${pidfile_kea}"; then
                printf 'WAN DHCPv6 Server (kea-dhcp6): RUNNING (PID %s in %s, IA_NA + IA_PD)\n' "$(cat "${pidfile_kea}")" "${wan_ns}"
                running=1
            fi
            if is_pidfile_running "${pidfile_radvd}"; then
                printf 'WAN Router Advertisements (radvd): RUNNING (PID %s in %s)\n' "$(cat "${pidfile_radvd}")" "${wan_ns}"
                running=1
            fi
            if is_pidfile_running "${pidfile_dnsmasq_v4}"; then
                printf 'WAN DHCPv4 Server (dnsmasq): RUNNING (PID %s in %s)\n' "$(cat "${pidfile_dnsmasq_v4}")" "${wan_ns}"
                running=1
            fi
            if is_pidfile_running "${pidfile_dnsmasq}"; then
                printf 'WAN DHCP Server (dnsmasq): RUNNING (PID %s in %s)\n' "$(cat "${pidfile_dnsmasq}")" "${wan_ns}"
                running=1
            fi

            if (( running == 0 )); then
                printf 'WAN DHCP Server: STOPPED\n'
            else
                if [[ -f "${leasefile_dnsmasq}" && -s "${leasefile_dnsmasq}" ]]; then
                    printf '== Active WAN dnsmasq Leases ==\n'
                    cat "${leasefile_dnsmasq}"
                fi
            fi
            ;;
    esac
}

# 7. Process & Daemon Management
is_pidfile_running() {
    local pidfile="$1" pid=""
    if [[ ! -f "${pidfile}" ]]; then return 1; fi
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ -z "${pid}" || "${pid}" =~ [^0-9] ]]; then return 1; fi
    kill -0 "${pid}" 2>/dev/null || [[ -d "/proc/${pid}" ]]
}

start_daemon() {
    local pid_file="$1" log_file="$2" service_name="$3" exec_ns="${4:-}"
    shift 4 || true
    local cmd=("$@")

    if is_pidfile_running "${pid_file}"; then
        log_warn "${service_name} is already running (PID: $(cat "${pid_file}"))."
        return 0
    fi
    log_info "Starting ${service_name}..."
    local prefix=()
    if [[ -n "${exec_ns}" ]] && ns_exists "${exec_ns}"; then
        prefix=("ip" "netns" "exec" "${exec_ns}")
    fi
    "${prefix[@]}" nohup "${cmd[@]}" > "${log_file}" 2>&1 &
    local daemon_pid=$!
    echo "${daemon_pid}" > "${pid_file}"
    chmod 0666 "${pid_file}" "${log_file}" 2>/dev/null || true
    sleep 0.2
    if kill -0 "${daemon_pid}" 2>/dev/null; then
        log_info "${service_name} running (PID: ${daemon_pid}, Log: ${log_file})"
        return 0
    else
        log_error "Failed to start ${service_name}! Check log: ${log_file}"
        return 1
    fi
}

stop_pidfile() {
    local pidfile="$1" name="${2:-process}" pid="" attempt
    if [[ ! -f "${pidfile}" ]]; then return 0; fi
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
        if kill -0 "${pid}" 2>/dev/null; then
            log_info "Stopping ${name} (PID: ${pid})..."
            kill -INT "${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
            for attempt in {1..15}; do
                if ! kill -0 "${pid}" 2>/dev/null; then break; fi
                sleep 0.1
            done
            if kill -0 "${pid}" 2>/dev/null; then kill -9 "${pid}" 2>/dev/null || true; fi
            log_info "${name} stopped."
        fi
    fi
    rm -f "${pidfile}"
}

stop_process_by_pattern() {
    local pattern="$1" name="${2:-processes matching '${pattern}'}"
    if pgrep -f "${pattern}" >/dev/null 2>&1; then
        log_info "Terminating ${name}..."
        pkill -INT -f "${pattern}" 2>/dev/null || true
        sleep 0.3
        pgrep -f "${pattern}" >/dev/null 2>&1 && pkill -TERM -f "${pattern}" 2>/dev/null || true
        sleep 0.5
        pgrep -f "${pattern}" >/dev/null 2>&1 && pkill -9 -f "${pattern}" 2>/dev/null || true
    fi
}

# 7. Socket & Port Synchronization
is_port_listening() {
    local port="$1" host="${2:-127.0.0.1}" ns="${3:-}"
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        ip netns exec "${ns}" python3 -c "import socket; s = socket.socket(); s.settimeout(0.5); s.connect(('${host}', int(${port}))); s.close()" >/dev/null 2>&1
    else
        python3 -c "import socket; s = socket.socket(); s.settimeout(0.5); s.connect(('${host}', int(${port}))); s.close()" >/dev/null 2>&1
    fi
}

wait_for_port() {
    local port="$1" host="${2:-127.0.0.1}" timeout="${3:-10}" ns="${4:-}" elapsed=0
    while ! is_port_listening "${port}" "${host}" "${ns}"; do
        sleep 0.5
        elapsed=$((elapsed + 1))
        if (( elapsed >= timeout * 2 )); then
            log_warn "Timeout waiting for port ${port} on ${host} after ${timeout}s"
            return 1
        fi
    done
    return 0
}

wait_for_http() {
    local url="$1" expected_code="${2:-200}" timeout="${3:-10}" ns="${4:-}" elapsed=0
    local curl_cmd=("curl" "-sk" "-o" "/dev/null" "-w" "%{http_code}" "--max-time" "1" "${url}")
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        curl_cmd=("ip" "netns" "exec" "${ns}" "${curl_cmd[@]}")
    fi
    while true; do
        local code
        code="$("${curl_cmd[@]}" 2>/dev/null || echo "000")"
        if [[ "${code}" == "${expected_code}" || ("${expected_code}" == "any" && "${code}" != "000") ]]; then return 0; fi
        sleep 0.5
        elapsed=$((elapsed + 1))
        if (( elapsed >= timeout * 2 )); then
            log_warn "Timeout waiting for HTTP URL ${url} (code: ${code}) after ${timeout}s"
            return 1
        fi
    done
}

# 8. DUT SSH Command Execution
run_dut_cmd() {
    local cmd="$1" timeout="${2:-10}"
    if [[ -z "${DUT_SSH_HOST:-}" || -z "${cmd}" ]]; then return 0; fi
    require_command ssh
    local ssh_opts=(-o ConnectTimeout="${timeout}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR)
    [[ -n "${DUT_SSH_PORT:-}" ]] && ssh_opts+=(-p "${DUT_SSH_PORT}")
    [[ -n "${DUT_SSH_KEY:-}" && -f "${DUT_SSH_KEY}" ]] && ssh_opts+=(-i "${DUT_SSH_KEY}")
    ssh "${ssh_opts[@]}" "${DUT_SSH_USER:-root}@${DUT_SSH_HOST}" "${cmd}"
}
is_dut_ssh_ready() {
    [[ -z "${DUT_SSH_HOST:-}" ]] && return 1
    run_dut_cmd "echo ok" 3 >/dev/null 2>&1
}

# 9. PCAP & Certificate Utilities
get_latest_pcap() {
    if [[ -f "${STATE_DIR}/last_capture.env" ]]; then
        local pcap_from_env
        pcap_from_env="$(grep '^LAST_PCAP=' "${STATE_DIR}/last_capture.env" 2>/dev/null | cut -d= -f2- | tr -d "'\"" || true)"
        if [[ -n "${pcap_from_env}" && -f "${pcap_from_env}" ]]; then
            printf '%s\n' "${pcap_from_env}"; return 0
        fi
    fi
    if [[ -d "${CAPTURE_DIR}" ]]; then
        local newest
        newest="$( (find "${CAPTURE_DIR}" -maxdepth 1 -name '*.pcap*' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{print $2}') || true)"
        if [[ -n "${newest}" && -f "${newest}" ]]; then
            printf '%s\n' "${newest}"; return 0
        fi
    fi
    return 1
}

format_bytes() {
    local bytes="${1:-0}"
    bytes="${bytes//[^0-9]/}"
    [[ -n "${bytes}" ]] || bytes=0
    if (( bytes < 1024 )); then printf '%d B' "${bytes}"
    elif (( bytes < 1048576 )); then printf '%.1f KB' "$((bytes * 10 / 1024))e-1"
    elif (( bytes < 1073741824 )); then printf '%.1f MB' "$((bytes * 10 / 1048576))e-1"
    else printf '%.1f GB' "$((bytes * 10 / 1073741824))e-1"; fi
}

detect_tshark_field() {
    local fields_cache="$1"; shift; local candidate
    for candidate in "$@"; do
        if grep -Fxq "${candidate}" <<< "${fields_cache}"; then
            printf '%s\n' "${candidate}"; return 0
        fi
    done
    return 1
}

validate_cert_expiry() {
    local cert_file="$1" days_check="${2:-7}"
    [[ -f "${cert_file}" ]] || return 1
    require_command openssl
    local seconds=$(( days_check * 86400 ))
    openssl x509 -checkend "${seconds}" -noout -in "${cert_file}" >/dev/null 2>&1
}

render_template() {
    local src="$1"
    local dst="$2"
    local iface="${3:-${NS_IF:-eth-wan}}"

    local v4_dns_list="${WAN_IPV4_DNS:-10.10.0.1}"
    if [[ -n "${WAN_IPV4_DNS2:-}" ]]; then
        v4_dns_list="${WAN_IPV4_DNS}, ${WAN_IPV4_DNS2}"
    fi

    local v6_dns_list="${WAN_IPV6_DNS:-}"
    local v6_radvd_dns="${WAN_IPV6_DNS:-}"
    if [[ -n "${WAN_IPV6_DNS2:-}" ]]; then
        v6_dns_list="${WAN_IPV6_DNS}, ${WAN_IPV6_DNS2}"
        v6_radvd_dns="${WAN_IPV6_DNS} ${WAN_IPV6_DNS2}"
    fi

    sed \
        -e "s|@DUT_IF@|${iface}|g" \
        -e "s|@WAN_IPV4_SUBNET@|${WAN_IPV4_SUBNET:-10.10.0.0/24}|g" \
        -e "s|@WAN_IPV4_POOL_START@|${WAN_IPV4_POOL_START:-10.10.0.100}|g" \
        -e "s|@WAN_IPV4_POOL_END@|${WAN_IPV4_POOL_END:-10.10.0.200}|g" \
        -e "s|@WAN_IPV4_ROUTER@|${WAN_IPV4_ROUTER:-10.10.0.1}|g" \
        -e "s|@WAN_IPV4_DNS@|${v4_dns_list}|g" \
        -e "s|@WAN_IPV4_DNS1@|${WAN_IPV4_DNS:-10.10.0.1}|g" \
        -e "s|@WAN_IPV4_DNS2@|${WAN_IPV4_DNS2:-}|g" \
        -e "s|@WAN_IPV6_PREFIX@|${WAN_IPV6_PREFIX:-}|g" \
        -e "s|@WAN_IPV6_DNS@|${v6_dns_list}|g" \
        -e "s|@WAN_IPV6_DNS1@|${WAN_IPV6_DNS:-}|g" \
        -e "s|@WAN_IPV6_DNS2@|${WAN_IPV6_DNS2:-}|g" \
        -e "s|@WAN_IPV6_RDNSS@|${v6_radvd_dns}|g" \
        -e "s|@PD_PREFIX@|${PD_PREFIX:-}|g" \
        -e "s|@PD_PREFIX_LEN@|${PD_PREFIX_LEN:-}|g" \
        -e "s|@PD_DELEGATED_LEN@|${PD_DELEGATED_LEN:-}|g" \
        -e "s|@AFTR_NAME@|${AFTR_NAME:-}|g" \
        -e "s|@RA_MIN_INTERVAL_SEC@|${RA_MIN_INTERVAL_SEC:-3}|g" \
        -e "s|@RA_MAX_INTERVAL_SEC@|${RA_MAX_INTERVAL_SEC:-10}|g" \
        -e "s|@RA_LIFETIME_SEC@|${RA_LIFETIME_SEC:-1800}|g" \
        -e "s|@DHCP_VALID_LIFETIME_SEC@|${DHCP_VALID_LIFETIME_SEC:-43200}|g" \
        -e "s|@DHCP_RENEW_TIMER_SEC@|${DHCP_RENEW_TIMER_SEC:-21600}|g" \
        -e "s|@DHCP_REBIND_TIMER_SEC@|${DHCP_REBIND_TIMER_SEC:-37800}|g" \
        -e "s|@DHCP6_PREFERRED_LIFETIME_SEC@|${DHCP6_PREFERRED_LIFETIME_SEC:-27000}|g" \
        "${src}" > "${dst}"
}

