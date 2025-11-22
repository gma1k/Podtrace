#!/bin/bash
# Setup script for podtrace test pods

set -e

NAMESPACE="podtrace-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
	echo "=== Setting up podtrace test environment ==="
	echo ""
}

check_kubectl_installed() {
	if ! command -v kubectl &>/dev/null; then
		echo -e "${RED}Error: kubectl is not installed${NC}"
		exit 1
	fi
}

check_cluster_access() {
	if ! kubectl cluster-info &>/dev/null; then
		echo -e "${RED}Error: Cannot connect to Kubernetes cluster${NC}"
		echo "Please verify: kubectl cluster-info"
		exit 1
	fi

	echo -e "${GREEN}✓ Kubernetes cluster accessible${NC}"
	echo ""
}

apply_test_resources() {
	echo "Creating test namespace and pods..."
	kubectl apply -f "${SCRIPT_DIR}/test-pods.yaml"
	echo ""
}

wait_for_pods_ready() {
	echo "Waiting for pods to be ready..."
	kubectl wait --for=condition=Ready pod/nginx-test -n "${NAMESPACE}" --timeout=120s || true
	kubectl wait --for=condition=Ready pod/busybox-test -n "${NAMESPACE}" --timeout=120s || true
	kubectl wait --for=condition=Ready pod/alpine-test -n "${NAMESPACE}" --timeout=120s || true
	echo ""
}

print_pod_status() {
	echo "=== Test Pods Status ==="
	kubectl get pods -n "${NAMESPACE}"
	echo ""
}

print_instructions() {
	echo -e "${GREEN}=== Test pods are ready! ===${NC}"
	echo ""
	echo "You can now test podtrace with:"
	echo ""
	echo "  # Test with nginx pod"
	echo "  sudo ./bin/podtrace -n ${NAMESPACE} nginx-test"
	echo ""
	echo "  # Test with busybox pod"
	echo "  sudo ./bin/podtrace -n ${NAMESPACE} busybox-test"
	echo ""
	echo "  # Test with alpine pod"
	echo "  sudo ./bin/podtrace -n ${NAMESPACE} alpine-test"
	echo ""
	echo "  # Test diagnose mode"
	echo "  sudo ./bin/podtrace -n ${NAMESPACE} nginx-test --diagnose 10s"
	echo ""
	echo "To clean up, run:"
	echo "  ./test/cleanup-test-pods.sh"
	echo ""
}

main() {
	print_header
	check_kubectl_installed
	check_cluster_access
	apply_test_resources
	wait_for_pods_ready
	print_pod_status
	print_instructions
}

main "$@"
