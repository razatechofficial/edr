#!/usr/bin/env bash
# Register notarytool credentials on the CI runner keychain.
#
# Option A (recommended on CI): set all three and optionally NOTARY_KEYCHAIN_PROFILE
#   APPLE_ID
#   APPLE_TEAM_ID
#   APPLE_APP_SPECIFIC_PASSWORD
#   NOTARY_KEYCHAIN_PROFILE   default: edr-notary
#
# Option B: pre-provisioned profile on a self-hosted runner (skip if profile exists)
set -euo pipefail

PROFILE="${NOTARY_KEYCHAIN_PROFILE:-edr-notary}"

if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
	xcrun notarytool store-credentials "${PROFILE}" \
		--apple-id "${APPLE_ID}" \
		--team-id "${APPLE_TEAM_ID}" \
		--password "${APPLE_APP_SPECIFIC_PASSWORD}"
	echo "Configured notarytool profile: ${PROFILE}"
	exit 0
fi

if xcrun notarytool history --keychain-profile "${PROFILE}" >/dev/null 2>&1; then
	echo "Using existing notarytool profile: ${PROFILE}"
	exit 0
fi

echo "Notary credentials not configured; set APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_SPECIFIC_PASSWORD" >&2
exit 0
