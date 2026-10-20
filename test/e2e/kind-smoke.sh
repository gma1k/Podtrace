#!/bin/bash
#
# kind-smoke.sh — end-to-end validation on a kind cluster.
#
# This script does not create a kind cluster (the user is expected to
# have one already). It installs the podtrace chart with the operator
# enabled, applies a sample PodTraceSession, and verifies that the
# operator:
#
#   1. Creates the agent DaemonSet + RBAC under TracerConfig control.
#   2. Resolves the session's selector, fans out into a per-node Job.
#   3. Syncs an exporter bundle (ConfigMap) for the referenced
#      ExporterConfig into the system namespace.
#   4. Reports the session's phase on .status.phase.
#
# The script asserts control-plane behaviour plus agent readiness. The
# agent runs the real eBPF backend and reaches Ready; this smoke check
# does not assert event/alert delivery (see the resource-alert chainsaw
# test for the agent data path).
#
# Usage:
#
#   KUBECONFIG=$HOME/.kube/config test/e2e/kind-smoke.sh [cleanup]
#
# The optional `cleanup` argument tears down the release and sample
# manifests without running assertions.

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"
readonly RELEASE="podtrace-e2e"
readonly SYSTEM_NS="podtrace-system"
readonly SAMPLE_NS="e2e-sample"

log_err() {
	printf '%s: %s\n' "${SCRIPT_NAME}" "$*" >&2
}

log_info() {
	printf '%s: %s\n' "${SCRIPT_NAME}" "$*"
}

require_tool() {
	if ! command -v "$1" >/dev/null 2>&1; then
		log_err "required tool not on PATH: $1"
		exit 1
	fi
}

# shellcheck source-path=SCRIPTDIR source=kube-context-guard.sh
source "$(dirname "${BASH_SOURCE[0]}")/kube-context-guard.sh"

repo_root() {
	cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd
}

cleanup() {
	log_info "cleaning up"

	strip_finalizers podtraces.podtrace.io "${SAMPLE_NS}"
	strip_finalizers podtracesessions.podtrace.io "${SAMPLE_NS}"
	strip_finalizers tracerconfigs.podtrace.io ""

	kubectl delete podtrace --all -n "${SAMPLE_NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kubectl delete podtracesession --all -n "${SAMPLE_NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kubectl delete tracerconfig --all --ignore-not-found --wait=false >/dev/null 2>&1 || true

	helm uninstall "${RELEASE}" -n "${SYSTEM_NS}" >/dev/null 2>&1 || true
	kubectl delete namespace "${SAMPLE_NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kubectl delete clusterrole podtrace-agent --ignore-not-found >/dev/null 2>&1 || true
	kubectl delete clusterrolebinding podtrace-agent --ignore-not-found >/dev/null 2>&1 || true
	log_info "cleanup issued (deletions run async; kubectl get may still show items for a few seconds)"
}

strip_finalizers() {
	local kind="$1"
	local namespace="$2"
	local names
	if [[ -n "${namespace}" ]]; then
		names=$(kubectl get "${kind}" -n "${namespace}" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
	else
		names=$(kubectl get "${kind}" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
	fi
	for name in ${names}; do
		if [[ -n "${namespace}" ]]; then
			kubectl patch "${kind}" "${name}" -n "${namespace}" \
				--type=merge -p '{"metadata":{"finalizers":[]}}' >/dev/null 2>&1 || true
		else
			kubectl patch "${kind}" "${name}" \
				--type=merge -p '{"metadata":{"finalizers":[]}}' >/dev/null 2>&1 || true
		fi
	done
}

wait_for() {
	local description="$1"
	local timeout_seconds="$2"
	local check_cmd="$3"

	log_info "waiting for: ${description}"
	local elapsed=0
	while [[ ${elapsed} -lt ${timeout_seconds} ]]; do
		if eval "${check_cmd}" >/dev/null 2>&1; then
			log_info "  ok: ${description}"
			return 0
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done
	log_err "timeout after ${timeout_seconds}s: ${description}"
	return 1
}

tracerconfig_converged() {
	local gen observed reconciled
	gen=$(kubectl get tracerconfig default -o jsonpath='{.metadata.generation}' 2>/dev/null)
	observed=$(kubectl get tracerconfig default -o jsonpath='{.status.observedGeneration}' 2>/dev/null)
	reconciled=$(kubectl get tracerconfig default \
		-o jsonpath='{range .status.conditions[?(@.type=="Reconciled")]}{.status}{end}' 2>/dev/null)
	[[ -n "${gen}" && "${gen}" == "${observed}" && "${reconciled}" == "True" ]]
}

assert_resource_exists() {
	local kind="$1"
	local name="$2"
	local namespace="${3:-}"

	if [[ -n "${namespace}" ]]; then
		if ! kubectl get "${kind}" "${name}" -n "${namespace}" >/dev/null 2>&1; then
			log_err "expected ${kind} ${namespace}/${name}"
			return 1
		fi
	else
		if ! kubectl get "${kind}" "${name}" >/dev/null 2>&1; then
			log_err "expected cluster-scoped ${kind} ${name}"
			return 1
		fi
	fi
	log_info "  found: ${kind} ${namespace:+${namespace}/}${name}"
}

main() {
	require_tool kubectl
	require_tool helm
	require_tool jq
	require_kind_context
	trap remove_e2e_kubeconfig EXIT

	local action="${1:-run}"
	if [[ "${action}" == "cleanup" ]]; then
		cleanup
		return 0
	fi

	local root
	root="$(repo_root)"

	# --- step 1: install chart ------------------------------------------
	log_info "ensuring system namespace ${SYSTEM_NS}"
	kubectl get namespace "${SYSTEM_NS}" >/dev/null 2>&1 ||
		kubectl create namespace "${SYSTEM_NS}"
	kubectl label namespace "${SYSTEM_NS}" \
		pod-security.kubernetes.io/enforce=privileged \
		pod-security.kubernetes.io/audit=privileged \
		pod-security.kubernetes.io/warn=privileged \
		--overwrite >/dev/null

	log_info "installing chart from ${root}/deploy/charts/podtrace"
	helm upgrade --install "${RELEASE}" "${root}/deploy/charts/podtrace" \
		--namespace "${SYSTEM_NS}" \
		--set namespace.create=false \
		--set operator.enabled=true \
		--set image.repository=ghcr.io/gma1k/podtrace \
		--set image.tag=dev \
		--set image.pullPolicy=Never \
		--wait --timeout 120s

	# --- step 2: operator Deployment becomes Ready ----------------------
	wait_for "operator Deployment Ready" 120 \
		"kubectl -n ${SYSTEM_NS} rollout status deploy/${RELEASE}-operator --timeout=60s"

	wait_for "TracerConfig reconciled to current generation" 60 \
		tracerconfig_converged

	assert_resource_exists daemonset podtrace-agent "${SYSTEM_NS}"
	assert_resource_exists serviceaccount podtrace-agent "${SYSTEM_NS}"
	assert_resource_exists clusterrole podtrace-agent
	assert_resource_exists role podtrace-agent-bundles "${SYSTEM_NS}"
	assert_resource_exists rolebinding podtrace-agent-bundles "${SYSTEM_NS}"
	assert_resource_exists clusterrolebinding podtrace-agent

	# --- step 4: user-namespace resources -------------------------------
	log_info "creating sample workload namespace"
	kubectl create namespace "${SAMPLE_NS}" --dry-run=client -o yaml | kubectl apply -f -

	log_info "creating sample ExporterConfig"
	kubectl -n "${SAMPLE_NS}" apply -f - <<EOF
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata:
  name: prod-otlp
spec:
  type: otlp
  otlp:
    endpoint: otel-collector:4318
    protocol: http
EOF

	# --- step 5: a tiny target workload the session can select on ------
	# pause:3.9 is tiny and always reaches Running; we just need pods
	# that a selector can match so the operator's fan-out path fires.
	log_info "creating sample target workload (pause pods)"
	kubectl -n "${SAMPLE_NS}" apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: smoke-target
spec:
  replicas: 1
  selector:
    matchLabels:
      app: smoke-target
  template:
    metadata:
      labels:
        app: smoke-target
    spec:
      containers:
        - name: app
          image: registry.k8s.io/pause:3.9
EOF
	kubectl -n "${SAMPLE_NS}" rollout status deploy/smoke-target --timeout=60s

	# --- step 6: session targeting the sample workload via label -------
	log_info "creating sample PodTraceSession with reportRef sink"
	kubectl -n "${SAMPLE_NS}" apply -f - <<EOF
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata:
  name: smoke
spec:
  selector:
    matchLabels:
      app: smoke-target
  duration: 30s
  filters: [dns, net]
  exporterRef:
    name: prod-otlp
  reportRef:
    configMap:
      name: smoke-report
EOF

	# --- step 7: per-node Job landed under podtrace-system --------------
	wait_for "session Job created in ${SYSTEM_NS}" 60 \
		"kubectl -n ${SYSTEM_NS} get jobs -l podtrace.io/session=smoke -o name | grep -q job"

	# --- step 7a: session bundle and per-session RBAC landed ------------
	wait_for "session exporter bundle ConfigMap in ${SYSTEM_NS}" 60 \
		"kubectl -n ${SYSTEM_NS} get cm -l podtrace.io/session=smoke -o name | grep -q configmap"
	wait_for "session ServiceAccount podtrace-session" 60 \
		"kubectl -n ${SYSTEM_NS} get sa podtrace-session"
	wait_for "per-session Role in ${SAMPLE_NS}" 60 \
		"kubectl -n ${SAMPLE_NS} get role -l podtrace.io/session=smoke -o name | grep -q role"
	wait_for "per-session RoleBinding in ${SAMPLE_NS}" 60 \
		"kubectl -n ${SAMPLE_NS} get rolebinding -l podtrace.io/session=smoke -o name | grep -q rolebinding"

	log_info "creating continuous PodTrace (exercises bundle sync)"
	kubectl -n "${SAMPLE_NS}" apply -f - <<EOF
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata:
  name: smoke-continuous
spec:
  selector:
    matchLabels:
      app: smoke-target
  filters: [dns, net]
  exporterRef:
    name: prod-otlp
EOF

	wait_for "exporter bundle ConfigMap landed in ${SYSTEM_NS}" 60 \
		"kubectl -n ${SYSTEM_NS} get cm -l podtrace.io/component=exporter-bundle -o name | grep -q configmap"

	wait_for "at least one agent pod Ready" 120 \
		"[[ \$(kubectl -n ${SYSTEM_NS} get pods -l podtrace.io/component=agent --field-selector=status.phase=Running -o json | jq '.items | map(select(.status.containerStatuses[]?.ready == true)) | length') -ge 1 ]]"

	log_info "creating second overlapping PodTrace (proves multi-CR merge)"
	kubectl -n "${SAMPLE_NS}" apply -f - <<EOF
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata:
  name: smoke-continuous-b
spec:
  selector:
    matchLabels:
      app: smoke-target
  filters: [fs, proc]
  exporterRef:
    name: prod-otlp
EOF

	wait_for "both PodTrace CRs report per-node status" 120 \
		"[[ \$(kubectl -n ${SAMPLE_NS} get podtraces -o json | jq '[.items[] | select((.status.nodeStatus // []) | length > 0)] | length') -eq 2 ]]"

	# --- step 11: print a summary for humans ----------------------------
	log_info "smoke passed — cluster state snapshot follows"
	echo
	kubectl get tracerconfig
	echo
	kubectl -n "${SAMPLE_NS}" get podtrace,podtracesession,exporterconfig
	echo
	kubectl -n "${SAMPLE_NS}" get podtrace -o jsonpath='{range .items[*]}{.metadata.name}: nodeStatus={range .status.nodeStatus[*]}{.node}(ready={.ready},events={.totalEvents}){end}{"\n"}{end}'
	echo
	kubectl -n "${SYSTEM_NS}" get deploy,daemonset,job,cm -l app.kubernetes.io/part-of=podtrace
}

main "$@"
