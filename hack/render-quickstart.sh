#!/usr/bin/env bash
#
# render-quickstart.sh — the single renderer for the quickstart manifest.
#
# Both .github/workflows/release.yml and test/e2e/quickstart-smoke.sh call this,
# so the artifact users apply is produced by the same code CI exercises. They
# used to render it separately, which is how the two drifted.
#
# Usage: render-quickstart.sh <chart-dir> <output-file> [extra helm args...]
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <chart-dir> <output-file> [extra helm args...]" >&2
	exit 2
fi

chart="$1"
out="$2"
shift 2

cat >"${out}" <<'NSEOF'
apiVersion: v1
kind: Namespace
metadata:
  name: podtrace-system
  labels:
    app.kubernetes.io/managed-by: podtrace-quickstart
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
NSEOF

drop_uninstall_hooks() {
	awk '
		function flush() {
			if (buf != "" && !drop) printf "%s", buf
			buf = ""
			drop = 0
		}
		/^---[[:space:]]*$/ { flush(); buf = $0 "\n"; next }
		{
			buf = buf $0 "\n"
			if ($0 ~ /helm\.sh\/hook:.*pre-delete/) drop = 1
		}
		END { flush() }
	'
}

echo "---" >>"${out}"
helm template podtrace "${chart}" \
	--namespace podtrace-system \
	--include-crds \
	--set namespace.create=false \
	--set operator.enabled=true \
	"$@" |
	drop_uninstall_hooks >>"${out}"

if grep -q "helm.sh/hook:.*pre-delete" "${out}"; then
	echo "render-quickstart.sh: pre-delete hooks survived the filter in ${out}" >&2
	exit 1
fi
if grep -q "namespace-bootstrap" "${out}"; then
	echo "render-quickstart.sh: namespace-bootstrap leaked into ${out}" >&2
	exit 1
fi
