#!/usr/bin/env bash
# Run a command under Rosetta when building macOS amd64 on an Apple Silicon host.
set -euo pipefail

if [[ "${EDR_MACOS_USE_ROSETTA:-}" == "1" ]]; then
	exec arch -x86_64 /bin/bash -c 'cd "$1" && shift && exec "$@"' _ "$(pwd)" "$@"
fi

exec "$@"
