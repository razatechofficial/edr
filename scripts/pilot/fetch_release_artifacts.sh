#!/usr/bin/env bash
# Download prod release artifacts from GitHub and verify fleet rollout profiles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO="${EDR_GITHUB_REPO:-razatechofficial/edr}"
TAG="${1:-}"
OUT="${2:-${ROOT}/dist/release}"

if ! command -v gh >/dev/null 2>&1; then
	echo "ERROR: gh CLI required (https://cli.github.com/)" >&2
	exit 1
fi

mkdir -p "${OUT}"

if [[ -z "${TAG}" ]]; then
	TAG="$(gh release list --repo "${REPO}" --limit 20 --json tagName,isPrerelease,publishedAt \
		| python3 -c 'import json,sys; rels=json.load(sys.stdin); prod=[r["tagName"] for r in rels if r.get("isPrerelease")]; print(prod[0] if prod else "")')"
	if [[ -z "${TAG}" ]]; then
		echo "ERROR: no prerelease found on ${REPO}; pass an explicit tag" >&2
		exit 1
	fi
	echo "==> using latest prod prerelease: ${TAG}"
fi

echo "==> download ${REPO}@${TAG} -> ${OUT}"
gh release download "${TAG}" --repo "${REPO}" --dir "${OUT}" --pattern '*.deb' --pattern '*.rpm' --pattern '*.pkg' --pattern '*.msi' --clobber

echo "==> verify downloaded packages"
bash "${ROOT}/scripts/ci/verify_release_packages.sh" "${OUT}"

echo "release artifacts ready under ${OUT}"
