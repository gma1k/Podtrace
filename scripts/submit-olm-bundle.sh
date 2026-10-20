#!/usr/bin/env bash
#
# submit-olm-bundle.sh — open a per-tag PR upstream to
# k8s-operatorhub/community-operators for podtrace.
#
# This is the automated counterpart to the manual fork-and-PR flow
# that produced the first community-operators submission. On every
# real-semver tag, release.yml invokes this script to:
#
#   1. Build bundle/<version>/ via scripts/build-olm-bundle.sh
#   2. Clone the user's fork of community-operators
#   3. Sync the fork's main with upstream/main (so the diff is clean)
#   4. Branch off and copy bundle/<version>/{manifests,metadata}
#      into operators/podtrace/<version>/
#   5. Commit with DCO sign-off as the bot identity
#   6. Push to the fork
#   7. Open a PR upstream with the canonical title format
#
# Inputs (env vars):
#   VERSION            Required. e.g. 0.11.9 (no leading 'v')
#   PREVIOUS_VERSION   Optional. Highest version already in upstream
#                      operators/podtrace/. Empty for first submission.
#                      Used by build-olm-bundle.sh for CSV `replaces:`.
#   FORK_OWNER         Owner of the community-operators fork (default: gma1k)
#   FORK_REPO          Fork repo name (default: community-operators)
#   UPSTREAM           Upstream repo (default: k8s-operatorhub/community-operators)
#   BOT_NAME           Commit author name (default: podtrace-release-bot)
#   BOT_EMAIL          Commit author email (default: ghassan+podtrace@malke.nl)
#   DRY_RUN            If "true", stop before push/PR-open. For local
#                      testing.
#
# Required tools on PATH: gh, git, helm, python3, jq.
# gh authentication: `gh auth login` or `GH_TOKEN`/`GITHUB_TOKEN` env var
# with `repo` scope on FORK_OWNER + public-repo access on UPSTREAM.

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"

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

VERSION="${VERSION:-}"
PREVIOUS_VERSION="${PREVIOUS_VERSION:-}"
FORK_OWNER="${FORK_OWNER:-gma1k}"
FORK_REPO="${FORK_REPO:-community-operators}"
UPSTREAM="${UPSTREAM:-k8s-operatorhub/community-operators}"
BOT_NAME="${BOT_NAME:-podtrace-release-bot}"
BOT_EMAIL="${BOT_EMAIL:-ghassan+podtrace@malke.nl}"
DRY_RUN="${DRY_RUN:-false}"

# Strip leading 'v' if present.
VERSION="${VERSION#v}"
PREVIOUS_VERSION="${PREVIOUS_VERSION#v}"

if [[ -z "${VERSION}" ]]; then
	log_err "VERSION is required (e.g. VERSION=0.11.9)"
	exit 2
fi

require_tool gh
require_tool git
require_tool helm
require_tool python3

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_DIR="${REPO_ROOT}/bundle/${VERSION}"
WORK_DIR="$(mktemp -d -t olm-bundle-submit.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

log_info "building bundle for ${VERSION} (replaces=${PREVIOUS_VERSION:-<none>})"
VERSION="${VERSION}" PREVIOUS_VERSION="${PREVIOUS_VERSION}" \
	"${REPO_ROOT}/scripts/build-olm-bundle.sh"

if [[ ! -d "${BUNDLE_DIR}/manifests" ]] || [[ ! -d "${BUNDLE_DIR}/metadata" ]]; then
	log_err "bundle missing after build: ${BUNDLE_DIR}"
	exit 1
fi

branch_head_sha() {
	gh api "repos/$1/branches/main" --jq .commit.sha
}

log_info "syncing fork ${FORK_OWNER}/${FORK_REPO}:main with ${UPSTREAM}:main"
if ! gh api --method POST "repos/${FORK_OWNER}/${FORK_REPO}/merge-upstream" \
	-f branch=main; then
	log_info "fast-forward sync failed — force-resetting fork main to upstream main"
	gh repo sync "${FORK_OWNER}/${FORK_REPO}" --source "${UPSTREAM}" --branch main --force
fi

in_sync=false
for attempt in 1 2 3 4 5; do
	fork_sha="$(branch_head_sha "${FORK_OWNER}/${FORK_REPO}")"
	upstream_sha="$(branch_head_sha "${UPSTREAM}")"
	if [[ "${fork_sha}" == "${upstream_sha}" ]]; then
		in_sync=true
		break
	fi
	log_info "fork main ${fork_sha:0:7} != upstream main ${upstream_sha:0:7} (attempt ${attempt}/5); force-syncing"
	gh repo sync "${FORK_OWNER}/${FORK_REPO}" --source "${UPSTREAM}" --branch main --force >/dev/null 2>&1 || true
	sleep "$((attempt * 2))"
done

if [[ "${in_sync}" != "true" ]]; then
	log_err "fork main HEAD (${fork_sha}) does not match ${UPSTREAM}:main HEAD (${upstream_sha})"
	log_err "after a forced sync; refusing to open a PR that would fail the"
	log_err "community-operators rebase check. Investigate the fork manually."
	exit 1
fi

log_info "cloning fork ${FORK_OWNER}/${FORK_REPO}"
gh repo clone "${FORK_OWNER}/${FORK_REPO}" "${WORK_DIR}/fork" -- --depth=1
cd "${WORK_DIR}/fork"

if [[ -n "${GH_TOKEN:-}" ]]; then
	git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${FORK_OWNER}/${FORK_REPO}.git"
else
	gh auth setup-git
fi

local_branch="add-podtrace-${VERSION}"
log_info "creating branch ${local_branch} from fork main"
git checkout -b "${local_branch}"

target="operators/podtrace/${VERSION}"
mkdir -p "${target}"
cp -r "${BUNDLE_DIR}/manifests" "${target}/"
cp -r "${BUNDLE_DIR}/metadata" "${target}/"

log_info "staged bundle into ${target}/"

git config user.name "${BOT_NAME}"
git config user.email "${BOT_EMAIL}"
git config commit.gpgsign false
git add "operators/podtrace/${VERSION}"
git commit -s -m "operator podtrace (${VERSION})"

if [[ "${DRY_RUN}" == "true" ]]; then
	log_info "DRY_RUN=true — stopping before push. Branch ${local_branch} prepared in ${WORK_DIR}/fork"
	echo "${WORK_DIR}/fork" >/tmp/olm-bundle-dry-run-path.txt
	trap - EXIT
	exit 0
fi

log_info "pushing branch to fork"
git push -u origin "${local_branch}"

pr_body="$(
	cat <<EOF
First-class auto-submission for podtrace ${VERSION}, generated by
\`scripts/submit-olm-bundle.sh\` from the gma1k/podtrace release pipeline.

### Submission details

| Field | Value |
|---|---|
| Bundle path | \`operators/podtrace/${VERSION}/\` |
| Operator image | \`ghcr.io/gma1k/podtrace:${VERSION}\` (cosign keyless signed) |
| \`updateGraph\` | \`replaces-mode\` (per existing \`operators/podtrace/ci.yaml\`) |
| Replaces | \`podtrace.v${PREVIOUS_VERSION}\` |
| Channels | \`stable\` (default) |
| Install modes | \`AllNamespaces\` only |
| Maintainer | Ghassan Malke (\`gma1k\`) |

### Local validation
- \`operator-sdk bundle validate ./bundle/${VERSION} --select-optional name=community\` ✓
- \`operator-sdk bundle validate ./bundle/${VERSION} --select-optional name=operatorhub\` ✓
- End-to-end on kind: \`operator-sdk run bundle\` reaches \`Succeeded\`, all 6 CRDs install, alm-examples reconcile.

### Source
- gma1k/podtrace tag: [\`v${VERSION}\`](https://github.com/gma1k/podtrace/releases/tag/v${VERSION})
- License: Apache 2.0
EOF
)"

log_info "opening upstream PR"
gh pr create \
	--repo "${UPSTREAM}" \
	--head "${FORK_OWNER}:${local_branch}" \
	--base main \
	--title "operator podtrace (${VERSION})" \
	--body "${pr_body}"

log_info "submission complete for podtrace ${VERSION}"
