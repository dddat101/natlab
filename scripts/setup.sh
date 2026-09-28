#!/usr/bin/env bash
# ==============================================================================
# CARRIER GATEWAY DUT - DUAL MODE TOPOLOGY SETUP SCRIPT
# Supports:
#   Mode 1: Virtual Simulation (Software netns DUT - zero hardware needed)
#   Mode 2: Physical Dual-USB Hardware (Single-PC with 2 USB-to-Ethernet adapters)
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SETUP_ACTIVE=0

usage() {
    cat <<'EOF'
==================================================================
  Carrier Gateway DUT - Dual Mode Topology Setup
==================================================================

Description:
  Initializes network topology, Linux bridges, network namespaces,
  and multi-client LAN interfaces for testing Carrier Gateway NAT & routing.
  Supports both Virtual Simulation and Physical Dual-USB Hardware modes.

Usage:
  sudo ./scripts/setup.sh [OPTIONS]

Dual Topology Options:
  --virtual, -v, --no-dut
      Mode 1: Pure software simulation using isolated Linux namespaces:
      - ns-wan  : Upstream carrier network, Softswitch (SSW), STUN servers
      - ns-dut  : Simulated Gateway Router performing NAT/NAPT & Port Forwarding
      - ns-lan1 : Primary LAN client / Wi-Fi Phone (RTP/RTCP)
      - ns-lan2 : Secondary LAN client (Sequential NAT port conflict)
      - ns-lan3 : VoLTE Femtocell client (Out-of-order fragmentation)
      - ns-lan4 : Super DMZ / TWIN IP designated client

  --single, -s, --dual, --physical, --hardware
      Mode 2: Physical Single-PC Dual-USB Hardware Mode:
      Connects 2 USB-to-Ethernet adapters to physical DUT:
      - WAN_IF (USB Adapter 1) -> DUT physical WAN port (bridged to ns-wan)
      - LAN_IF (USB Adapter 2) -> DUT physical LAN port (bridged to ns-lan1..4)

Adapter Options (For Physical Mode):
  --wan-if <iface>      Specify physical interface for WAN connection
  --lan-if <iface>      Specify physical interface for LAN connection
  --auto-detect         Scan and auto-assign connected USB-to-Ethernet adapters

General Options:
  -h, --help            Show this help message and exit

Examples:
  sudo ./scripts/setup.sh --virtual
  sudo ./scripts/setup.sh --dual
  sudo ./scripts/setup.sh --physical --wan-if enx6c1ff76608e2 --lan-if enx00e04c88293c
==================================================================
EOF
}

rollback_setup() {
    local exit_code="$1"
    local line_number="$2"
    if (( SETUP_ACTIVE == 0 )); then return; fi

    trap - ERR
    log_error "Setup failed near line ${line_number}; rolling back topology..."
    "${SCRIPT_DIR}/cleanup.sh" >/dev/null 2>&1 || true
    log_error "Rollback complete. Original error code: ${exit_code}"
    exit "${exit_code}"
}

setup_virtual_dut() {
    local ns_dut="${DUT_NS:-ns-dut}"
    log_info "Configuring Virtual DUT router in ${ns_dut}..."
    ns_create "${ns_dut}"

    # Veth to WAN bridge
    create_veth_to_ns "${ns_dut}" "veth-dutwan" "eth-wan" "${WAN_BRIDGE}" "${DUT_WAN_IP:-10.10.0.150}/24" ""

    # Veth to LAN bridge
    create_veth_to_ns "${ns_dut}" "veth-dutlan" "eth-lan" "${LAN_BRIDGE}" "${DUT_LAN_IP:-192.168.1.1}/24" ""

    # Enable IPv4 routing and fragment reassembly
    ip netns exec "${ns_dut}" sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || true
    ip netns exec "${ns_dut}" sysctl -q -w net.ipv4.ip_defrag_low_thresh=196608 2>/dev/null || true
    ip netns exec "${ns_dut}" sysctl -q -w net.ipv4.ip_defrag_high_thresh=262144 2>/dev/null || true

    # Default route via WAN Server / Gateway
    ip -n "${ns_dut}" route replace default via "${WAN_SERVER_IP:-10.10.0.1}" dev eth-wan 2>/dev/null || true

    # Base NAT setup with iptables
    ip netns exec "${ns_dut}" iptables -F 2>/dev/null || true
    ip netns exec "${ns_dut}" iptables -t nat -F 2>/dev/null || true
    ip netns exec "${ns_dut}" iptables -t raw -F 2>/dev/null || true
    ip netns exec "${ns_dut}" iptables -t mangle -F 2>/dev/null || true

    # Outbound MASQUERADE for LAN subnet
    ip netns exec "${ns_dut}" iptables -t nat -A POSTROUTING -s "${LAN_IPV4_SUBNET:-192.168.1.0/24}" -o eth-wan -j MASQUERADE 2>/dev/null || true

    # Allow forwarding
    ip netns exec "${ns_dut}" iptables -A FORWARD -i eth-lan -o eth-wan -j ACCEPT 2>/dev/null || true
    ip netns exec "${ns_dut}" iptables -A FORWARD -i eth-wan -o eth-lan -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    ip netns exec "${ns_dut}" iptables -A FORWARD -i eth-wan -o eth-lan -d 224.0.0.0/4 -j ACCEPT 2>/dev/null || true
}

setup_lan_clients() {
    log_info "Configuring LAN client namespaces (ns-lan1..4)..."
    
    # LAN1: Primary client / Wi-Fi Phone (RTP/RTCP)
    create_veth_to_ns "${LAN1_NS:-ns-lan1}" "veth-lan1" "eth0" "${LAN_BRIDGE}" "${LAN1_CLIENT_IP:-192.168.1.101}/24" "${DUT_LAN_IP:-192.168.1.1}"

    # LAN2: Secondary client (Sequential port conflict test)
    create_veth_to_ns "${LAN2_NS:-ns-lan2}" "veth-lan2" "eth0" "${LAN_BRIDGE}" "${LAN2_CLIENT_IP:-192.168.1.102}/24" "${DUT_LAN_IP:-192.168.1.1}"

    # LAN3: Femtocell VoLTE client (Out-of-order fragmentation)
    create_veth_to_ns "${LAN3_NS:-ns-lan3}" "veth-lan3" "eth0" "${LAN_BRIDGE}" "${LAN3_CLIENT_IP:-192.168.1.103}/24" "${DUT_LAN_IP:-192.168.1.1}"

    # LAN4: Super DMZ / TWIN IP client
    create_veth_to_ns "${LAN4_NS:-ns-lan4}" "veth-lan4" "eth0" "${LAN_BRIDGE}" "${LAN4_CLIENT_IP:-192.168.1.104}/24" "${DUT_LAN_IP:-192.168.1.1}"
    if [[ -n "${SUPER_DMZ_MAC:-}" ]]; then
        ip -n "${LAN4_NS:-ns-lan4}" link set dev eth0 address "${SUPER_DMZ_MAC}" 2>/dev/null || true
    fi
}

resolve_physical_interfaces() {
    log_info "Resolving physical network adapters for Dual-USB mode..."
    local detected_usb=()
    mapfile -t detected_usb < <(get_usb_network_interfaces)

    if (( ${#detected_usb[@]} > 0 )); then
        log_info "Detected USB network interfaces: ${detected_usb[*]}"
    fi

    # Auto-detection if requested or if interfaces are unconfigured
    if [[ "${AUTO_DETECT_USB_NICS:-1}" == "1" || -z "${WAN_IF:-}" || -z "${LAN_IF:-}" ]]; then
        if (( ${#detected_usb[@]} >= 2 )); then
            if [[ -z "${WAN_IF:-}" ]] || ! iface_exists_root "${WAN_IF}"; then
                WAN_IF="${detected_usb[0]}"
                log_info "Auto-assigned WAN_IF -> ${WAN_IF} (USB Adapter 1)"
            fi
            if [[ -z "${LAN_IF:-}" ]] || ! iface_exists_root "${LAN_IF}"; then
                # Select second USB NIC distinct from WAN_IF
                local nic
                for nic in "${detected_usb[@]}"; do
                    if [[ "${nic}" != "${WAN_IF}" ]]; then
                        LAN_IF="${nic}"
                        log_info "Auto-assigned LAN_IF -> ${LAN_IF} (USB Adapter 2)"
                        break
                    fi
                done
            fi
        elif (( ${#detected_usb[@]} == 1 )); then
            if [[ -z "${WAN_IF:-}" ]] || ! iface_exists_root "${WAN_IF}"; then
                WAN_IF="${detected_usb[0]}"
                log_info "Assigned available USB NIC to WAN_IF -> ${WAN_IF}"
            fi
        fi
    fi

    # Verify both interfaces exist and are safe
    if [[ -z "${WAN_IF:-}" ]] || ! iface_exists_root "${WAN_IF}"; then
        log_error "WAN physical interface not found: '${WAN_IF:-<unset>}."
        log_error "Available USB NICs: ${detected_usb[*]:-<none>}"
        die "Please plug in USB Adapter 1 for WAN, or run with --virtual."
    fi

    if [[ -z "${LAN_IF:-}" ]] || ! iface_exists_root "${LAN_IF}"; then
        log_error "LAN physical interface not found: '${LAN_IF:-<unset>}."
        log_error "Available USB NICs: ${detected_usb[*]:-<none>}"
        die "Please plug in USB Adapter 2 for LAN, or run with --virtual."
    fi

    if [[ "${WAN_IF}" == "${LAN_IF}" ]]; then
        die "WAN_IF and LAN_IF cannot be the same interface (${WAN_IF}). You need 2 distinct USB-to-Ethernet adapters."
    fi

    assert_safe_test_if "${WAN_IF}"
    assert_safe_test_if "${LAN_IF}"

    log_success "Physical Dual-USB Interface Validation: WAN=${WAN_IF} | LAN=${LAN_IF}"
}

main() {
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    require_root
    require_command ip

    load_config

    local mode="${TOPOLOGY_MODE:-virtual}"
    local role="${LAB_ROLE:-single}"

    while (( $# > 0 )); do
        case "$1" in
            --virtual|-v|--no-dut)
                mode="virtual"
                shift
                ;;
            --single|-s|--dual|--physical|--hardware)
                mode="physical"
                role="single"
                shift
                ;;
            --wan-if)
                WAN_IF="$2"
                shift 2
                ;;
            --lan-if)
                LAN_IF="$2"
                shift 2
                ;;
            --auto-detect)
                AUTO_DETECT_USB_NICS="1"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    SETUP_ACTIVE=1
    trap 'rollback_setup $? ${LINENO}' ERR

    print_header "INITIALIZING GATEWAY TOPOLOGY: [MODE: ${mode^^}]"
    ensure_runtime_dirs

    # Create Bridges
    bridge_create "${WAN_BRIDGE}"
    bridge_create "${LAN_BRIDGE}"

    # Configure WAN Namespace
    log_info "Configuring WAN Namespace ${WAN_NS:-ns-wan}..."
    create_veth_to_ns "${WAN_NS:-ns-wan}" "veth-wansrv" "eth-wan" "${WAN_BRIDGE}" "${WAN_SERVER_IP:-10.10.0.1}/24" ""
    if [[ -n "${WAN_SERVER2_IP:-}" ]]; then
        ip -n "${WAN_NS:-ns-wan}" addr add "${WAN_SERVER2_IP}/24" dev eth-wan 2>/dev/null || true
    fi
    ip -n "${WAN_NS:-ns-wan}" route replace "${LAN_IPV4_SUBNET:-192.168.1.0/24}" via "${DUT_WAN_IP:-10.10.0.150}" dev eth-wan 2>/dev/null || true
    ip -n "${WAN_NS:-ns-wan}" route replace 224.0.0.0/4 dev eth-wan 2>/dev/null || true

    # Mode-Specific Deployment
    if [[ "${mode}" == "virtual" ]]; then
        log_info "Deploying Mode 1: Virtual Simulation (Software DUT)..."
        setup_virtual_dut
    elif [[ "${mode}" == "physical" ]]; then
        log_info "Deploying Mode 2: Physical Dual-USB Hardware Mode..."
        resolve_physical_interfaces
        attach_physical_to_bridge "${WAN_IF}" "${WAN_BRIDGE}"
        attach_physical_to_bridge "${LAN_IF}" "${LAN_BRIDGE}"

        # Upstream WAN DHCP server to lease IP to physical DUT WAN port
        if [[ "${ENABLE_WAN_DHCP:-1}" == "1" && -x "${SCRIPT_DIR}/wan_server.sh" ]]; then
            log_info "Activating upstream WAN DHCP server via wan_server.sh..."
            "${SCRIPT_DIR}/wan_server.sh" start "${WAN_DHCP_BACKEND:-auto}" || true
        fi
    fi

    # Setup LAN clients
    setup_lan_clients

    # Save state
    cat >"${STATE_DIR}/topology_state.env" <<EOF
TOPOLOGY_MODE='${mode}'
LAB_ROLE='${role}'
SETUP_TIMESTAMP='$(date -Iseconds)'
WAN_BRIDGE='${WAN_BRIDGE}'
LAN_BRIDGE='${LAN_BRIDGE}'
WAN_NS='${WAN_NS:-ns-wan}'
DUT_NS='${DUT_NS:-ns-dut}'
LAN1_NS='${LAN1_NS:-ns-lan1}'
LAN2_NS='${LAN2_NS:-ns-lan2}'
LAN3_NS='${LAN3_NS:-ns-lan3}'
LAN4_NS='${LAN4_NS:-ns-lan4}'
WAN_IF='${WAN_IF:-}'
LAN_IF='${LAN_IF:-}'
WAN_SERVER_IP='${WAN_SERVER_IP:-10.10.0.1}'
DUT_WAN_IP='${DUT_WAN_IP:-10.10.0.150}'
DUT_LAN_IP='${DUT_LAN_IP:-192.168.1.1}'
EOF

    SETUP_ACTIVE=0
    trap - ERR
    log_success "Topology setup completed successfully! [Mode: ${mode^^}]"
    if [[ -x "${SCRIPT_DIR}/show_state.sh" ]]; then
        bash "${SCRIPT_DIR}/show_state.sh" || true
    fi
}

main "$@"
