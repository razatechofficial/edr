#!/usr/bin/env bash
# Sanity-check macOS pkg staging paths (run after build/macos/package.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG_ROOT="${ROOT}/pkg/macos/root"
PLIST="${PKG_ROOT}/Library/LaunchDaemons/com.razatech.edr-agent.plist"
CFG="${PKG_ROOT}/Library/Application Support/EDR/config/agent.yaml"

fail() { echo "verify_macos_package: $*" >&2; exit 1; }

[[ -f "${PLIST}" ]] || fail "missing LaunchDaemon plist"
grep -q '/Library/Application Support/EDR/config/agent.yaml' "${PLIST}" || fail "plist must reference Application Support config"
grep -q '<string>run</string>' "${PLIST}" || fail "plist must invoke edr-agent run"

[[ -f "${CFG}" ]] || fail "missing staged agent.yaml"
grep -q 'data_dir: "/Library/Application Support/EDR"' "${CFG}" || fail "agent.yaml data_dir must use Application Support"
grep -q 'rules_file: "/Library/Application Support/EDR/config/rules/baseline.yaml"' "${CFG}" || fail "rules_file must be absolute under config/rules"

[[ -d "${PKG_ROOT}/Library/Application Support/EDR/config/rules" ]] || fail "missing bundled rules directory"
[[ -f "${PKG_ROOT}/Library/Application Support/EDR/config/rules/baseline.yaml" ]] || fail "missing baseline.yaml in staged rules"

echo "macOS package staging OK"
