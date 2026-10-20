#!/bin/sh
#
# scrape-agent-metrics.sh [namespace pod container]
#
# Print every running agent's /metrics. With a pod given, the scrape is made
# from that pod with curl, as a workload would.
set -eu

agents=$(kubectl -n podtrace-system get pod -l podtrace.io/component=agent \
	--field-selector=status.phase=Running \
	-o jsonpath='{range .items[*]}{.metadata.name},{.status.podIP} {end}')
if [ -z "${agents}" ]; then
	echo "no running agents to scrape" >&2
	exit 1
fi

failed=0
for agent in ${agents}; do
	name="${agent%,*}"
	ip="${agent#*,}"
	if [ "$#" -ge 3 ]; then
		body=$(kubectl -n "$1" exec "$2" -c "$3" -- \
			curl -sS --max-time 10 "http://${ip}:9090/metrics" 2>/dev/null) || body=""
	else
		proxy="/api/v1/namespaces/podtrace-system/pods/${name}:9090/proxy"
		body=$(kubectl get --raw "${proxy}/metrics" 2>/dev/null) || body=""
	fi
	case "${body}" in
	*podtrace_*) printf '%s\n' "${body}" ;;
	*)
		echo "agent ${name} (${ip}) did not answer with metrics" >&2
		failed=1
		;;
	esac
done
exit "${failed}"
