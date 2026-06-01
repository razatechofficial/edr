#!/usr/bin/env bash
# Generate Ed25519 keypair for control plane policy bundle signing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-${EDR_POLICY_KEY_DIR:-/etc/edr/certs}}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo) when writing ${OUT}." >&2
	exit 1
fi

install -d -m 0750 "${OUT}"
(
	cd "${ROOT}"
	go run ./tools/generate_policy_signing_key/main.go -out "${OUT}"
)

echo
echo "Next:"
echo "  deploy ${OUT}/edr-policy.pub.pem to agents (policy_verify_pubkey_path)"
echo "  export EDR_POLICY_SIGN_KEY=${OUT}/edr-policy.seed"
echo "  sudo make stage-controlplane-policy"
