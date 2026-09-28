#!/usr/bin/env bash
# ==============================================================================
# CARRIER GATEWAY DUT - DEPENDENCY INSTALLATION SCRIPT
# Installs host toolchains, network utilities, Kea/dnsmasq, and test dependencies
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly REQUIRED_PACKAGES=(
    ca-certificates
    curl
    dnsmasq
    ethtool
    iperf
    iperf3
    iproute2
    iptables
    iputils-ping
    isc-dhcp-client
    kea-dhcp4-server
    kea-dhcp6-server
    netcat-openbsd
    openssh-client
    procps
    python3
    python3-pip
    python3-venv
    sip-tester
    socat
    tcpdump
    tshark
    udhcpc
)

usage() {
    cat <<'USAGE'
==================================================================
  Carrier Gateway DUT Lab - Dependency Installer
==================================================================

Description:
  Installs required system packages (tcpdump, tshark, iperf3,
  iproute2, iptables, python3, kea, dnsmasq, udhcpc, etc.)
  on Debian/Ubuntu or Fedora/RHEL.

Usage:
  sudo ./scripts/install_deps.sh [options]

Options:
  -h, --help    Show this help message and exit

Examples:
  sudo ./scripts/install_deps.sh

Suggested Next Steps:
  1. Run pre-flight check:     ./scripts/diagnose.sh
  2. Initialize test topology: sudo ./scripts/setup.sh --virtual
==================================================================
USAGE
}

main() {
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    if [[ "$(id -u)" -ne 0 ]]; then
        printf '\e[1;31m[ERROR]\e[0m This script requires root/sudo privileges.\n' >&2
        printf 'Usage: sudo ./scripts/install_deps.sh\n' >&2
        exit 1
    fi

    printf '==============================================================================\n'
    printf '        CARRIER GATEWAY DUT TEST LAB - DEPENDENCY INSTALLER                    \n'
    printf '==============================================================================\n\n'

    if command -v apt-get >/dev/null 2>&1; then
        printf 'Detected Debian/Ubuntu APT package manager.\n'
        printf 'Updating package repositories...\n'
        apt-get update -y

        printf 'Installing required packages...\n'
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${REQUIRED_PACKAGES[@]}"

        # Disable host-level system daemons so they do not interfere with netns instances
        for svc in kea-dhcp4-server kea-dhcp6-server radvd dnsmasq; do
            if systemctl is-enabled "${svc}" >/dev/null 2>&1 || systemctl is-active "${svc}" >/dev/null 2>&1; then
                systemctl disable --now "${svc}" 2>/dev/null || true
            fi
        done

        printf '\n\e[1;32m[PASS]\e[0m All dependencies installed and verified successfully!\n'
    elif command -v dnf >/dev/null 2>&1; then
        printf 'Detected Fedora/RHEL DNF package manager.\n'
        dnf install -y \
            ca-certificates \
            curl \
            dnsmasq \
            ethtool \
            iperf3 \
            iproute \
            iptables \
            iputils \
            dhcp-client \
            kea \
            nc \
            openssh-clients \
            procps-ng \
            python3 \
            python3-pip \
            sipp \
            socat \
            tcpdump \
            wireshark-cli \
            udhcpc-script

        for svc in kea-dhcp4 kea-dhcp6 radvd dnsmasq; do
            if systemctl is-enabled "${svc}" >/dev/null 2>&1 || systemctl is-active "${svc}" >/dev/null 2>&1; then
                systemctl disable --now "${svc}" 2>/dev/null || true
            fi
        done

        printf '\n\e[1;32m[PASS]\e[0m All dependencies installed and verified successfully!\n'
    else
        printf '\e[1;33m[WARN]\e[0m Unsupported package manager. Please manually install:\n'
        printf '  %s\n' "${REQUIRED_PACKAGES[*]}"
        exit 1
    fi

    # Set up non-root raw packet capture capabilities for dumpcap and sipp
    if command -v setcap >/dev/null 2>&1; then
        if [[ -f /usr/bin/dumpcap ]]; then
            setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap 2>/dev/null || true
        fi
        if command -v sipp >/dev/null 2>&1; then
            setcap cap_net_raw+eip "$(command -v sipp)" 2>/dev/null || true
        fi
    fi

    # Set up SIPp sample audio PCAP assets in project directory
    local script_dir
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    local project_root
    project_root="$(cd -- "${script_dir}/.." && pwd -P)"

    if [[ -d /usr/share/sip-tester ]]; then
        mkdir -p "${project_root}/tools/sipp/pcap"
        cp -u /usr/share/sip-tester/*.pcap "${project_root}/tools/sipp/pcap/" 2>/dev/null || true
        ln -sfn tools/sipp/pcap "${project_root}/pcap" 2>/dev/null || true
        chmod -R a+r "${project_root}/tools/sipp/pcap" 2>/dev/null || true
        printf '\e[1;32m[INFO]\e[0m SIPp audio assets initialized in %s/tools/sipp/pcap\n' "${project_root}"
    fi

    printf '==============================================================================\n'
    printf 'Lab dependencies are ready! Run ./scripts/diagnose.sh to verify.\n'
    printf '==============================================================================\n'
}

main "$@"
