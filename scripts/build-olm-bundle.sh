#!/usr/bin/env bash
# Build an OperatorHub-compliant OLM bundle from the Helm chart + CSV
# template. Output is written to bundle/<version>/.
#
# Inputs (env vars or args):
#   VERSION           Required. e.g. 0.11.7 (no leading 'v')
#   PREVIOUS_VERSION  Optional. Empty for first catalog submission;
#                     otherwise the version this release replaces.
#   IMAGE_DIGEST      Optional. sha256:... of the released image; when set,
#                     the CSV references the image by digest, not by tag.
#
# Outputs:
#   bundle/<version>/
#     manifests/
#       *.crd.yaml                              (copied from chart)
#       podtrace.clusterserviceversion.yaml     (rendered from template)
#     metadata/
#       annotations.yaml                        (copied)
#     bundle.Dockerfile                         (rendered from template)

set -euo pipefail

# --- inputs ------------------------------------------------------------

VERSION="${VERSION:-${1:-}}"
PREVIOUS_VERSION="${PREVIOUS_VERSION:-${2:-}}"

if [[ -z "${VERSION}" ]]; then
	echo "ERROR: VERSION is required (e.g. VERSION=0.11.7 $0)" >&2
	exit 2
fi

# Strip leading 'v' if present (release tags carry it; CSV name does not).
VERSION="${VERSION#v}"
PREVIOUS_VERSION="${PREVIOUS_VERSION#v}"
IMAGE_DIGEST="${IMAGE_DIGEST:-}"

readonly VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+$'
if [[ ! "${VERSION}" =~ ${VERSION_PATTERN} ]]; then
	echo "ERROR: VERSION ${VERSION} is not MAJOR.MINOR.PATCH" >&2
	exit 2
fi
prev="${PREVIOUS_VERSION}"
if [[ -n "${prev}" && ! "${prev}" =~ ${VERSION_PATTERN} ]]; then
	echo "ERROR: PREVIOUS_VERSION ${PREVIOUS_VERSION} is not X.Y.Z" >&2
	exit 2
fi
readonly DIGEST_PATTERN='^sha256:[a-f0-9]{64}$'
if [[ -n "${IMAGE_DIGEST}" && ! "${IMAGE_DIGEST}" =~ ${DIGEST_PATTERN} ]]; then
	echo "ERROR: IMAGE_DIGEST ${IMAGE_DIGEST} is not a sha256 digest" >&2
	exit 2
fi

# --- paths -------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_ROOT}/deploy/olm"
CHART_DIR="${REPO_ROOT}/deploy/charts/podtrace"
CRD_DIR="${CHART_DIR}/templates/crds"
ICON_PATH="${REPO_ROOT}/assets/podtrace-icon-olm.png"

OUT_DIR="${REPO_ROOT}/bundle/${VERSION}"
MANIFESTS_DIR="${OUT_DIR}/manifests"
METADATA_DIR="${OUT_DIR}/metadata"

# --- preflight ---------------------------------------------------------

for f in \
	"${SRC_DIR}/csv-template.yaml" \
	"${SRC_DIR}/annotations.yaml" \
	"${SRC_DIR}/bundle.Dockerfile.template" \
	"${ICON_PATH}"; do
	if [[ ! -f "${f}" ]]; then
		echo "ERROR: missing required file: ${f}" >&2
		exit 1
	fi
done

shopt -s nullglob
crd_files=("${CRD_DIR}"/*.yaml)
shopt -u nullglob
if [[ ! -d "${CRD_DIR}" || ${#crd_files[@]} -eq 0 ]]; then
	echo "ERROR: CRD directory empty or missing: ${CRD_DIR}" >&2
	exit 1
fi

# --- compute placeholders ----------------------------------------------

CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SKIP_RANGE_UPPER="${VERSION}"

# --- clean output ------------------------------------------------------

rm -rf "${OUT_DIR}"
mkdir -p "${MANIFESTS_DIR}" "${METADATA_DIR}"

# --- copy CRDs ---------------------------------------------------------

for src in "${crd_files[@]}"; do
	dst="${MANIFESTS_DIR}/$(basename "${src}")"
	grep -v -E '^\s*\{\{' "${src}" |
		grep -v -E '^\s*helm\.sh/resource-policy:' >"${dst}"
done

# --- render CSV --------------------------------------------------------

CSV_OUT="${MANIFESTS_DIR}/podtrace.clusterserviceversion.yaml"

# Use python for reliable multi-line/large-substring substitution.
python3 - "${SRC_DIR}/csv-template.yaml" "${CSV_OUT}" \
	"${VERSION}" "${PREVIOUS_VERSION}" "${CREATED_AT}" "${SKIP_RANGE_UPPER}" "${ICON_PATH}" "${IMAGE_DIGEST}" <<'PY'
import base64, sys

src, out, version, prev, created_at, skip_upper, icon_path, digest = sys.argv[1:]

with open(src) as f:
    csv = f.read()

if digest:
    csv = csv.replace("ghcr.io/gma1k/podtrace:__VERSION__", "ghcr.io/gma1k/podtrace@" + digest)

with open(icon_path, "rb") as f:
    icon_b64 = base64.b64encode(f.read()).decode()

csv = csv.replace("__VERSION__", version)
csv = csv.replace("__CREATED_AT__", created_at)
csv = csv.replace("__SKIP_RANGE_UPPER__", skip_upper)
csv = csv.replace("__ICON_BASE64__", icon_b64)

# `replaces` is per-version: empty for first catalog submission, set
# for subsequent. Drop the line entirely if PREVIOUS_VERSION is empty;
# OLM rejects a dangling/malformed replaces field.
if prev:
    csv = csv.replace("__PREVIOUS_VERSION__", prev)
else:
    csv = "\n".join(
        line for line in csv.splitlines()
        if "__PREVIOUS_VERSION__" not in line
    ) + "\n"

with open(out, "w") as f:
    f.write(csv)
PY

# --- render annotations.yaml + bundle.Dockerfile -----------------------

cp "${SRC_DIR}/annotations.yaml" "${METADATA_DIR}/annotations.yaml"

sed -e "s|__VERSION__|${VERSION}|g" \
	"${SRC_DIR}/bundle.Dockerfile.template" >"${OUT_DIR}/bundle.Dockerfile"

# --- summary -----------------------------------------------------------

echo "==> Bundle ready at ${OUT_DIR}"
echo "    Manifests:"
find "${MANIFESTS_DIR}" -maxdepth 1 -type f -exec basename {} \; | sed 's/^/      /' | sort
echo "    Metadata:"
find "${METADATA_DIR}" -maxdepth 1 -type f -exec basename {} \; | sed 's/^/      /' | sort
echo "    Dockerfile: bundle.Dockerfile"
echo
echo "Next: validate with 'operator-sdk bundle validate ${OUT_DIR} --select-optional name=community'"
