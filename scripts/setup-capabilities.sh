#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${PROJECT_ROOT}/bin/podtrace"

REQUIRED_CAPS="cap_bpf,cap_sys_admin,cap_sys_resource"

check_binary_exists() {
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

	echo "Verified capabilities:"
	echo "  ${current_caps}"
	echo ""
}

print_success_message() {
	echo "✓ Capabilities set successfully!"
	echo ""
	echo "You can now run podtrace without sudo:"
	echo "  ${BINARY} -n <namespace> <pod-name>"
	echo ""
	echo "To verify capabilities:"
	echo "  getcap ${BINARY}"
	echo ""
	echo "To remove capabilities:"
	echo "  sudo setcap -r ${BINARY}"
}

main() {
	check_binary_exists
	check_root
	set_capabilities
	verify_capabilities
	print_success_message
}

main "$@"
