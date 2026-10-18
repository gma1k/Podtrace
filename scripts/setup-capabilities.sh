#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BINARY="${1:-${PROJECT_ROOT}/bin/podtrace}"

REQUIRED_CAPS="cap_bpf,cap_perfmon,cap_sys_admin,cap_net_admin"
REQUIRED_CAPS+=",cap_sys_resource,cap_sys_ptrace"

usage() {
	echo "Usage: sudo $0 [path-to-podtrace-binary]" >&2
	echo "Default binary: ${PROJECT_ROOT}/bin/podtrace" >&2
}

check_binary_exists() {
	if [[ -L "${BINARY}" ]]; then
		echo "Error: ${BINARY} is a symlink;" \
			"refusing to grant capabilities to a symlink target" >&2
		exit 1
	fi

	if [[ ! -f "${BINARY}" ]]; then
		echo "Error: ${BINARY} not found" >&2
		echo "Build it first with: make build" >&2
		exit 1
	fi

	if [[ ! -x "${BINARY}" ]]; then
		echo "Error: ${BINARY} is not executable" >&2
		exit 1
	fi
}

check_root() {
	if [[ ${EUID} -ne 0 ]]; then
		echo "Error: This script must be run as root (use sudo)" >&2
		exit 1
	fi
}

set_capabilities() {
	echo "Setting capabilities on ${BINARY}..."
	echo "Capabilities: ${REQUIRED_CAPS}"
	echo ""

	if ! command -v setcap &>/dev/null; then
		echo "Error: setcap command not found. Install libcap2-bin package." >&2
		exit 1
	fi

	if [[ -L "${BINARY}" ]]; then
		echo "Error: ${BINARY} became a symlink before capabilities" \
			"were set; aborting" >&2
		exit 1
	fi

	if ! setcap "${REQUIRED_CAPS}+ep" "${BINARY}"; then
		echo "Error: Failed to set capabilities" >&2
		exit 1
	fi
}

verify_capabilities() {
	if ! command -v getcap &>/dev/null; then
		echo "Warning: getcap command not found, cannot verify capabilities" >&2
		return 0
	fi

	local current_caps
	current_caps=$(getcap "${BINARY}" 2>/dev/null || echo "")

	if [[ -z "${current_caps}" ]]; then
		echo "Error: Failed to verify capabilities were set" >&2
		exit 1
	fi

	local cap missing=() wanted=()
	IFS=',' read -ra wanted <<<"${REQUIRED_CAPS}"
	for cap in "${wanted[@]}"; do
		[[ "${current_caps}" == *"${cap}"* ]] || missing+=("${cap}")
	done
	if [[ ${#missing[@]} -gt 0 ]]; then
		echo "Error: capabilities missing after setcap: ${missing[*]}" >&2
		echo "  getcap reports: ${current_caps}" >&2
		exit 1
	fi

	echo "Verified capabilities:"
	echo "  ${current_caps}"
	echo ""
}

print_success_message() {
	echo "Capabilities set on ${BINARY}"
}

main() {
	if [[ $# -gt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
		usage
		[[ $# -gt 1 ]] && exit 2
		exit 0
	fi
	check_binary_exists
	check_root
	set_capabilities
	verify_capabilities
	print_success_message
}

main "$@"
