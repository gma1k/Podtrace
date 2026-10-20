#!/bin/bash
#
# kube-context-guard.sh — sourced by the e2e scripts before they touch a
# cluster.
require_kind_context() {
	local me="${0##*/}" current allowed="${PODTRACE_E2E_CONTEXT:-}" status=0
	current="$(kubectl config current-context 2>/dev/null || true)"

	if [[ -z "${current}" ]]; then
		printf '%s: no current kube context; point KUBECONFIG at kind\n' \
			"${me}" >&2
		exit 1
	fi

	if [[ "${current}" != kind-* && "${allowed}" != "${current}" ]]; then
		printf '%s: refusing kube context %q: it is not a kind cluster.\n' \
			"${me}" "${current}" >&2
		printf '%s: these scripts delete CRDs, namespaces and cluster RBAC.\n' \
			"${me}" >&2
		printf '%s: to run them there anyway, set PODTRACE_E2E_CONTEXT=%s\n' \
			"${me}" "${current}" >&2
		exit 1
	fi

	PODTRACE_E2E_KUBECONFIG="$(mktemp -t podtrace-e2e-kubeconfig.XXXXXX)"
	chmod 600 "${PODTRACE_E2E_KUBECONFIG}"
	kubectl config view --minify --flatten --context "${current}" \
		>"${PODTRACE_E2E_KUBECONFIG}" || status=$?
	if [[ "${status}" -ne 0 ]]; then
		rm -f "${PODTRACE_E2E_KUBECONFIG}"
		printf '%s: could not extract kube context %s\n' "${me}" "${current}" >&2
		exit 1
	fi
	export KUBECONFIG="${PODTRACE_E2E_KUBECONFIG}"
	printf '%s: using kube context %s\n' "${me}" "${current}"
}

remove_e2e_kubeconfig() {
	rm -f "${PODTRACE_E2E_KUBECONFIG:-}"
}
