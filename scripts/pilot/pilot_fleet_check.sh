#!/usr/bin/env bash
# Optional edrctl fleet check when control plane API auth is configured.
set -euo pipefail

ACTIVE="${1:-}"
if [[ -z "${ACTIVE}" || ! -f "${ACTIVE}" ]]; then
	exit 0
fi
if [[ -z "${EDR_CONTROLPLANE_API_TOKEN:-}" ]]; then
	exit 0
fi
if ! command -v edrctl >/dev/null 2>&1; then
	exit 0
fi

CA="${EDR_CONTROLPLANE_CA:-}"
if [[ -z "${CA}" ]]; then
	CA="$(grep -E '^[[:space:]]*ca_cert:' "${ACTIVE}" | head -1 | sed -E 's/.*ca_cert:[[:space:]]*"?([^"]+)"?.*/\1/')"
fi

HTTPS_FLAG=()
if [[ "${EDR_CONTROLPLANE_HTTPS:-0}" == "1" || "${EDR_CONTROLPLANE_HTTPS:-0}" == "true" ]]; then
	HTTPS_FLAG=(--https)
fi

ARGS=(--config "${ACTIVE}" fleet check "${HTTPS_FLAG[@]}" --token "${EDR_CONTROLPLANE_API_TOKEN}")
if [[ -n "${CA}" ]]; then
	ARGS+=(--ca-cert "${CA}")
fi

echo "==> edrctl fleet check"
edrctl "${ARGS[@]}"
