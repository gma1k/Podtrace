#!/bin/bash
# Automated test runner for podtrace

set -e

NAMESPACE="podtrace-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
	echo -e "${BLUE}=== podtrace Test Runner ===${NC}"
	echo ""
}

check_dependencies() {
	if ! command -v kubectl &>/dev/null; then
		echo -e "${RED}Error: kubectl is not installed${NC}"
		exit 1
	fi

	if ! kubectl cluster-info &>/dev/null; then
		echo -e "${RED}Error: Cannot connect to Kubernetes cluster${NC}"
		exit 1
	fi

	if [[ ! -f "${PROJECT_ROOT}/bin/podtrace" ]]; then
		echo -e "${RED}Error: podtrace binary not found. Run 'make build' first.${NC}"
		exit 1
	fi
}

setup_test_environment() {
	echo -e "${YELLOW}[1/4] Setting up test pods...${NC}"
	"${SCRIPT_DIR}/setup-test-pods.sh" >/dev/null 2>&1
}

wait_for_pods() {
	echo -e "${YELLOW}[2/4] Waiting for pods to be active...${NC}"
	sleep 10
	echo ""
}

run_test() {
	local test_name="$1"
	local pod_name="$2"
	local duration="$3"

	echo -e "${BLUE}${test_name}${NC}"
	echo "Running: sudo ${PROJECT_ROOT}/bin/podtrace -n ${NAMESPACE} ${pod_name} --diagnose ${duration}"
	echo ""

	local test_output
	local test_exit_code
	set +e
	test_output=$(sudo "${PROJECT_ROOT}/bin/podtrace" -n "${NAMESPACE}" "${pod_name}" --diagnose "${duration}" 2>&1 | head -30 || true)
	test_exit_code=${PIPESTATUS[0]}
	set -e
	echo "${test_output}"
	if [[ ${test_exit_code} -eq 0 ]]; then
		echo -e "${GREEN}✓ ${test_name} passed${NC}"
	else
		echo -e "${RED}✗ ${test_name} failed${NC}"
	fi

	echo ""
}

cleanup_test_environment() {
	echo -e "${YELLOW}[4/4] Cleaning up...${NC}"
	"${SCRIPT_DIR}/cleanup-test-pods.sh" >/dev/null 2>&1
	echo ""
}

print_footer() {
	echo -e "${GREEN}=== Tests completed ===${NC}"
}

main() {
	print_header
	check_dependencies
	setup_test_environment
	wait_for_pods

	echo -e "${YELLOW}[3/4] Running tests...${NC}"
	echo ""

	run_test "Test 1: Basic tracing (nginx-test)" "nginx-test" "5s"
	run_test "Test 2: Diagnose mode (busybox-test)" "busybox-test" "10s"

	cleanup_test_environment
	print_footer
}

main "$@"
