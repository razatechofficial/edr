#!/usr/bin/env bash
# Check Release workflow status on prod (or another branch) via gh.
set -euo pipefail

BRANCH="${1:-prod}"
WORKFLOW="${EDR_RELEASE_WORKFLOW:-Release}"
LIMIT="${EDR_RELEASE_RUN_LIMIT:-5}"

if ! command -v gh >/dev/null 2>&1; then
	echo "ERROR: gh CLI required (https://cli.github.com/)" >&2
	exit 1
fi

echo "==> Recent '${WORKFLOW}' runs on branch ${BRANCH}"
if ! gh run list --workflow="${WORKFLOW}" --branch="${BRANCH}" --limit="${LIMIT}"; then
	echo "ERROR: failed to list workflow runs (is gh authenticated?)" >&2
	exit 1
fi

RUN_ID="$(gh run list --workflow="${WORKFLOW}" --branch="${BRANCH}" --limit=1 --json databaseId,status,conclusion --jq '.[0].databaseId' 2>/dev/null || true)"
if [[ -z "${RUN_ID}" || "${RUN_ID}" == "null" ]]; then
	echo "WARNING: no runs found for ${WORKFLOW} on ${BRANCH}" >&2
	exit 1
fi

STATUS="$(gh run view "${RUN_ID}" --json status,conclusion,url,headSha,createdAt --jq '.status')"
CONCLUSION="$(gh run view "${RUN_ID}" --json status,conclusion,url,headSha,createdAt --jq '.conclusion // "in_progress"')"
URL="$(gh run view "${RUN_ID}" --json status,conclusion,url,headSha,createdAt --jq '.url')"
SHA="$(gh run view "${RUN_ID}" --json status,conclusion,url,headSha,createdAt --jq '.headSha')"
CREATED="$(gh run view "${RUN_ID}" --json status,conclusion,url,headSha,createdAt --jq '.createdAt')"

echo
echo "Latest run: ${URL}"
echo "  commit: ${SHA}"
echo "  created: ${CREATED}"
echo "  status: ${STATUS} (${CONCLUSION})"

case "${CONCLUSION}" in
success)
	echo "Release workflow OK"
	exit 0
	;;
failure|cancelled|timed_out|action_required|stale)
	echo "ERROR: latest release run did not succeed (${CONCLUSION})" >&2
	exit 1
	;;
*)
	echo "Release workflow still running or pending"
	exit 2
	;;
esac
