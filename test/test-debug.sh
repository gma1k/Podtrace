#!/bin/bash
set -e

NAMESPACE="${1:-podtrace-test}"
POD_NAME="${2:-nginx-cpu-test}"
DURATION="${3:-20s}"

log() {
	echo "$@"
}

check_pod_exists() {
	local ns="$1"
	local pod="$2"

	if ! kubectl get pod "${pod}" -n "${ns}" &>/dev/null; then
		log "Error: Pod ${pod} not found"
		exit 1
	fi
}

show_pod_info() {
	local ns="$1"
	local pod="$2"

	log "Pod Info:"
	kubectl get pod "${pod}" -n "${ns}" -o wide
	log ""
}

show_recent_logs() {
	local ns="$1"
	local pod="$2"

	log "Recent Pod Logs:"
	kubectl logs "${pod}" -n "${ns}" --tail=10 || log "No logs available"
	log ""
}

show_pod_activity() {
	local ns="$1"
	local pod="$2"

	log "Checking pod activity..."
	kubectl exec "${pod}" -n "${ns}" -- ps aux 2>/dev/null || log "Cannot exec into pod"
	log ""
}

run_podtrace() {
	local ns="$1"
	local pod="$2"
	local duration="$3"

	log "Running podtrace (check stderr for eBPF attachment info)..."
	log "---"
	./bin/podtrace -n "${ns}" "${pod}" --diagnose "${duration}" 2>&1
	log "---"
}

main() {
	log "=== Debug Test: ${POD_NAME} for ${DURATION} ==="
	log ""

	check_pod_exists "${NAMESPACE}" "${POD_NAME}"
	show_pod_info "${NAMESPACE}" "${POD_NAME}"
	show_recent_logs "${NAMESPACE}" "${POD_NAME}"
	show_pod_activity "${NAMESPACE}" "${POD_NAME}"
	run_podtrace "${NAMESPACE}" "${POD_NAME}" "${DURATION}"
}

main
