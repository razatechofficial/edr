#!/usr/bin/env bash
# Poll until the prod Release workflow succeeds (or fails / times out).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRANCH="${1:-prod}"
TIMEOUT="${EDR_RELEASE_WAIT_SEC:-3600}"
INTERVAL="${EDR_RELEASE_POLL_SEC:-30}"

if ! command -v gh >/dev/null 2>&1; then
	echo "ERROR: gh CLI required (https://cli.github.com/)" >&2
	exit 1
fi

deadline=$(( $(date +%s) + TIMEOUT ))
attempt=0

echo "==> waiting for Release workflow on ${BRANCH} (timeout ${TIMEOUT}s, poll ${INTERVAL}s)"
while true; do
	attempt=$((attempt + 1))
	set +e
	bash "${ROOT}/scripts/pilot/check_prod_release.sh" "${BRANCH}"
	code=$?
	set -e

	case "${code}" in
	0)
		echo "Release workflow succeeded"
		exit 0
		;;
	1)
		echo "ERROR: Release workflow failed" >&2
		exit 1
		;;
	2)
		if [[ $(date +%s) -ge ${deadline} ]]; then
			echo "ERROR: timed out waiting for Release workflow on ${BRANCH}" >&2
			exit 1
		fi
		echo "attempt ${attempt}: still running; sleeping ${INTERVAL}s"
		sleep "${INTERVAL}"
		;;
	*)
		echo "ERROR: check_prod_release exited ${code}" >&2
		exit "${code}"
		;;
	esac
done
