#!/bin/sh
#
# agents-converged.sh [tracerconfig] [timeout-seconds]
#
# Wait until the operator has acted on the TracerConfig's current spec and
# its agent DaemonSet has fully rolled that out.
#
# Comparing updated and ready pods with the desired count straight after a
# patch passes on the previous generation, before the operator has even
# written the new pod template. So this first waits for the TracerConfig's
# observedGeneration to reach its generation (the operator records it only
# after the DaemonSet write succeeded), then for the DaemonSet controller to
# observe its own generation, and only then counts pods.
set -eu

tc="${1:-default}"
timeout="${2:-300}"
started=$(date +%s)
deadline=$((started + timeout))

tc_fields='{.metadata.generation} {.status.observedGeneration}'
ds_fields='{.metadata.generation} {.status.observedGeneration}'
ds_fields="${ds_fields} {.status.desiredNumberScheduled}"
ds_fields="${ds_fields} {.status.updatedNumberScheduled}"
ds_fields="${ds_fields} {.status.numberReady} {.status.numberAvailable}"

ns=$(kubectl get tracerconfig "${tc}" -o jsonpath='{.spec.systemNamespace}')
ns="${ns:-podtrace-system}"

state=""
now=$(date +%s)
while [ "${now}" -lt "${deadline}" ]; do
	fields=$(kubectl get tracerconfig "${tc}" -o jsonpath="${tc_fields}" ||
		true)
	read -r generation observed <<-STATE
		${fields}
	STATE
	state="tracerconfig ${tc}: generation=${generation:-?}"
	state="${state} observed=${observed:-?}"
	if [ -n "${generation:-}" ] && [ "${generation}" = "${observed:-}" ]; then
		ds=$(kubectl -n "${ns}" get daemonset \
			-l "podtrace.io/tracer-config=${tc}" -o name || true)
		ds="${ds%%[[:space:]]*}"
		if [ -n "${ds}" ]; then
			fields=$(kubectl -n "${ns}" get "${ds}" \
				-o jsonpath="${ds_fields}" || true)
			read -r generation observed desired updated ready available <<-STATE
				${fields}
			STATE
			state="${ds}: generation/observed/desired/updated/ready/available"
			state="${state} = ${fields}"
			# All six fields must be present: the API omits zero counts,
			# and a missing one shifts the rest into the wrong variables.
			done_rolling=no
			if [ -n "${available:-}" ]; then
				done_rolling=yes
				[ "${generation}" = "${observed}" ] || done_rolling=no
				[ "${desired}" -gt 0 ] || done_rolling=no
				[ "${updated}" = "${desired}" ] || done_rolling=no
				[ "${ready}" = "${desired}" ] || done_rolling=no
				[ "${available}" = "${desired}" ] || done_rolling=no
			fi
			if [ "${done_rolling}" = yes ]; then
				echo "all ${desired} agents of ${tc} run generation" \
					"${generation} and are ready"
				exit 0
			fi
		fi
	fi
	sleep 2
	now=$(date +%s)
done

echo "FAIL: agents of ${tc} did not converge within ${timeout}s" >&2
echo "      (${state})" >&2
kubectl -n "${ns}" get pods -l podtrace.io/component=agent -o wide >&2 ||
	true
exit 1
