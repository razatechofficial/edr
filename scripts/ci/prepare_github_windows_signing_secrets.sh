#!/usr/bin/env bash
# Validate a Windows code-signing PFX and print GitHub Actions secret checklist.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PFX="${1:-}"

if [[ -z "${PFX}" ]]; then
	echo "usage: $0 /path/to/codesign.pfx [pfx-password]" >&2
	exit 1
fi
if [[ ! -f "${PFX}" ]]; then
	echo "missing PFX: ${PFX}" >&2
	exit 1
fi

PASS="${2:-${WINDOWS_SIGN_PFX_PASSWORD:-}}"

echo "=== Validating PFX ==="
if command -v pwsh >/dev/null 2>&1; then
	if [[ -n "${PASS}" ]]; then
		pwsh -NoProfile -File "${ROOT}/scripts/ci/validate_windows_pfx_local.ps1" -PfxPath "${PFX}" -Password "${PASS}"
	else
		pwsh -NoProfile -File "${ROOT}/scripts/ci/validate_windows_pfx_local.ps1" -PfxPath "${PFX}"
	fi
else
	echo "pwsh not found; skipping local PFX parse (upload secrets manually)." >&2
fi

B64_FILE="$(mktemp)"
base64 < "${PFX}" | tr -d '\n' > "${B64_FILE}"

echo
echo "=== GitHub secrets checklist ==="
echo "Settings → Secrets and variables → Actions → New repository secret"
echo
echo "WINDOWS_SIGN_PFX_BASE64"
echo "  size: $(wc -c < "${B64_FILE}") bytes (base64, single line)"
echo "  gh:   gh secret set WINDOWS_SIGN_PFX_BASE64 < \"${B64_FILE}\""
echo
echo "WINDOWS_SIGN_PFX_PASSWORD"
echo "  gh:   gh secret set WINDOWS_SIGN_PFX_PASSWORD"
echo
echo "WINDOWS_SIGN_TIMESTAMP_URL  (optional; default http://timestamp.digicert.com)"
echo "  gh:   gh secret set WINDOWS_SIGN_TIMESTAMP_URL --body 'http://timestamp.digicert.com'"
echo
echo "After secrets are set, push to prod or tag v* to produce a signed MSI."
echo "Release workflow verifies Authenticode when WINDOWS_SIGN_PFX_BASE64 is present."

rm -f "${B64_FILE}"
