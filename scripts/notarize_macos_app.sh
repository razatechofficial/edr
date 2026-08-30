#!/usr/bin/env bash
# Notarize the attended Setup.app (zip upload). Staples the .app, then
# rebuilds zip + dmg. Does not use productsign (that is for .pkg only).
#
# Usage: ./scripts/notarize_macos_app.sh [path/to/EDR-Agent-Setup.app]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

APP=${1:-dist/EDR-Agent-Setup.app}
if [[ ! -d "${APP}" ]]; then
	echo "usage: $0 path/to/EDR-Agent-Setup.app" >&2
	exit 1
fi

if [[ "${NOTARY_SKIP:-}" == "1" || "${NOTARY_SKIP:-}" == "true" ]]; then
	echo "==> Skipping Apple notary (NOTARY_SKIP=${NOTARY_SKIP}); app is Developer ID signed"
	exit 0
fi

notary_auth=()
if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
	notary_auth=(--keychain-profile "${NOTARY_KEYCHAIN_PROFILE}")
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
	notary_auth=(--apple-id "${APPLE_ID}" --team-id "${APPLE_TEAM_ID}" --password "${APPLE_APP_SPECIFIC_PASSWORD}")
else
	echo "Set NOTARY_KEYCHAIN_PROFILE or APPLE_ID + APPLE_TEAM_ID + APPLE_APP_SPECIFIC_PASSWORD" >&2
	exit 1
fi

json_field() {
	python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$1" "$2"
}

LABEL=apple-silicon
case "$(basename "${APP}")" in
*intel* | *amd64*) LABEL=intel ;;
esac
# Prefer sibling zip name from package.sh (EDR-Agent-Setup_apple-silicon.zip).
if [[ -f dist/EDR-Agent-Setup_intel.zip && ! -f dist/EDR-Agent-Setup_apple-silicon.zip ]]; then
	LABEL=intel
elif [[ -f dist/EDR-Agent-Setup_apple-silicon.zip ]]; then
	LABEL=apple-silicon
fi
if [[ -f dist/EDR-Agent-Setup_intel.dmg && ! -f dist/EDR-Agent-Setup_apple-silicon.dmg ]]; then
	LABEL=intel
fi

ZIP="$(mktemp "${TMPDIR:-/tmp}/edr-setup-notary.XXXXXX").zip"
ditto -c -k --keepParent "${APP}" "${ZIP}"

SUBMIT_JSON="$(mktemp "${TMPDIR:-/tmp}/edr-notary-submit.XXXXXX")"
INFO_JSON="$(mktemp "${TMPDIR:-/tmp}/edr-notary-info.XXXXXX")"
trap 'rm -f "${SUBMIT_JSON}" "${INFO_JSON}" "${ZIP}"' EXIT

echo "==> Submitting Setup.app zip to Apple Notary Service"
submit_ok=0
for attempt in 1 2 3; do
	echo "==> notarytool submit (attempt ${attempt}/3)"
	if xcrun notarytool submit "${ZIP}" "${notary_auth[@]}" --output-format json | tee "${SUBMIT_JSON}"; then
		if [[ -n "$(json_field "${SUBMIT_JSON}" id)" ]]; then
			submit_ok=1
			break
		fi
	fi
	echo "submit attempt ${attempt} failed; retry in 30s" >&2
	sleep 30
done
if [[ "${submit_ok}" -ne 1 ]]; then
	echo "notarytool submit failed after retries" >&2
	exit 1
fi

SUBMISSION_ID="$(json_field "${SUBMIT_JSON}" id)"
if [[ "${NOTARY_ALLOW_TIMEOUT:-}" == "1" || "${NOTARY_ALLOW_TIMEOUT:-}" == "true" ]]; then
	POLL_MAX="${NOTARY_POLL_MAX:-40}"
else
	POLL_MAX="${NOTARY_POLL_MAX:-180}"
fi
POLL_SEC="${NOTARY_POLL_SEC:-30}"
echo "==> Submission ${SUBMISSION_ID}; polling Apple (up to $((POLL_MAX * POLL_SEC / 60)) min)"

NOTARY_STATUS=""
started="${SECONDS}"
for poll in $(seq 1 "${POLL_MAX}"); do
	if xcrun notarytool info "${SUBMISSION_ID}" "${notary_auth[@]}" --output-format json >"${INFO_JSON}"; then
		NOTARY_STATUS="$(json_field "${INFO_JSON}" status)"
		echo "    poll ${poll}/${POLL_MAX} (+$((SECONDS - started))s): ${NOTARY_STATUS}"
		case "${NOTARY_STATUS}" in
		Accepted) break ;;
		Invalid | Rejected) break ;;
		esac
	else
		echo "    poll ${poll}/${POLL_MAX}: network error, retrying"
	fi
	sleep "${POLL_SEC}"
done

if [[ "${NOTARY_STATUS}" != "Accepted" ]]; then
	if [[ "${NOTARY_STATUS}" == "In Progress" || -z "${NOTARY_STATUS}" ]]; then
		echo "notarization still In Progress after $((SECONDS - started))s id=${SUBMISSION_ID}" >&2
		if [[ "${NOTARY_ALLOW_TIMEOUT:-}" == "1" || "${NOTARY_ALLOW_TIMEOUT:-}" == "true" ]]; then
			echo "NOTARY_ALLOW_TIMEOUT: keeping Developer ID signed Setup.app" >&2
			exit 0
		fi
	fi
	echo "notarization failed: status=${NOTARY_STATUS} id=${SUBMISSION_ID}" >&2
	exit 1
fi

echo "==> Stapling ticket onto ${APP}"
xcrun stapler staple "${APP}"

ZIP_OUT="dist/EDR-Agent-Setup_${LABEL}.zip"
DMG_OUT="dist/EDR-Agent-Setup_${LABEL}.dmg"
rm -f "${ZIP_OUT}" "${DMG_OUT}"
ditto -c -k --keepParent "${APP}" "${ZIP_OUT}"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/edr-setup-dmg.XXXXXX")"
ditto "${APP}" "${STAGE}/EDR-Agent-Setup.app"
hdiutil create -volname "EDR Agent Setup" -srcfolder "${STAGE}" \
	-ov -format UDZO "${DMG_OUT}" >/dev/null
rm -rf "${STAGE}"
if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
	codesign --force --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${DMG_OUT}" || true
fi
xcrun stapler staple "${DMG_OUT}" || true

echo "==> Done (notarized + stapled): ${APP}"
echo "    ${ZIP_OUT}"
echo "    ${DMG_OUT}"
