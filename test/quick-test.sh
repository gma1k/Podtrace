#!/bin/bash
set -e

NAMESPACE="podtrace-test"
POD_NAME="${1:-nginx-cpu-test}"
DURATION="${2:-20s}"

log() {
	echo "$@"
}

check_pod_exists() {
	local pod="$1"
	local ns="$2"

	if ! kubectl get pod "${pod}" -n "${ns}" &>/dev/null; then
		log "Error: Pod ${pod} not found in namespace ${ns}"
		log "Available pods:"
		kubectl get pods -n "${ns}" || log "Namespace ${ns} not found"
		exit 1
	fi
}

check_podtrace_binary() {
	if [[ ! -f "./bin/podtrace" ]]; then
		log "Error: ./bin/podtrace not found. Run 'make build' first."
		exit 1
	fi
}

run_diagnose() {
	local pod="$1"
	local ns="$2"
	local duration="$3"

	log "Running diagnose mode..."
	./bin/podtrace -n "${ns}" "${pod}" --diagnose "${duration}"
}

main() {
	log "=== Testing podtrace on ${POD_NAME} for ${DURATION} ==="
	log ""

	check_pod_exists "${POD_NAME}" "${NAMESPACE}"
	check_podtrace_binary
	run_diagnose "${POD_NAME}" "${NAMESPACE}" "${DURATION}"
}

main
