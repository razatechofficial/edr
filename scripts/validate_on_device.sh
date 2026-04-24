#!/usr/bin/env bash
set -euo pipefail

BINARY="${1:-./edr-agent}"
CONFIG="${2:-configs/linux/config.yml}"

echo "=== EDR Hardware Validation ==="
echo "Binary:  $BINARY"
echo "Config:  $CONFIG"
echo "Host:    $(hostname)"
echo "OS:      $(uname -s)"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: must run as root for full validation"
    echo "  sudo bash scripts/validate_on_device.sh"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "ERROR: binary not found: $BINARY"
    echo "  Run: make build-linux"
    exit 1
fi

echo "Starting validation suite..."
"$BINARY" \
    --config "$CONFIG" \
    --test-mode \
    --log-level warn \
    2>&1

EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "All validation tests passed"
else
    echo ""
    echo "Some validation tests failed (exit code: $EXIT_CODE)"
    echo "Check: cat /var/lib/edr-agent/validation_report.json"
fi
exit $EXIT_CODE
