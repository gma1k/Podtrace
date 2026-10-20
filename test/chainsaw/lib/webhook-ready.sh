#!/bin/sh
#
# webhook-ready.sh — wait until the validating webhook admits writes, when the
# chart installed one.
#
# A TracerConfig patch made while the webhook Service has no endpoints is
# rejected (failurePolicy: Fail). Without the webhook there is nothing to
# wait for, and polling for a Service that will never exist cost every
# caller two minutes.
set -eu

ns=podtrace-system
svc=podtrace-webhook
ready='{.items[*].endpoints[?(@.conditions.ready==true)].addresses[*]}'

if ! kubectl -n "${ns}" get service "${svc}" >/dev/null 2>&1; then
	echo "validating webhook not installed; nothing to wait for"
	exit 0
fi

noop='{"metadata":{"annotations":{}}}'

for _ in $(seq 1 60); do
	endpoints=$(kubectl -n "${ns}" get endpointslices \
		-l "kubernetes.io/service-name=${svc}" -o jsonpath="${ready}" \
		2>/dev/null || true)
	admitted=no
	if [ -n "${endpoints}" ]; then
		kubectl patch tracerconfig default --type=merge --dry-run=server \
			-p "${noop}" >/dev/null 2>&1 && admitted=yes
	fi
	if [ "${admitted}" = yes ]; then
		echo "validating webhook admits writes"
		exit 0
	fi
	sleep 2
done

echo "FAIL: the validating webhook did not admit a write within 120s" >&2
kubectl -n "${ns}" get pods,endpointslices \
	-l app.kubernetes.io/component=operator >&2 || true
exit 1
