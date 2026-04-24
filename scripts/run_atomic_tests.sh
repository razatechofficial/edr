#!/usr/bin/env bash
set -euo pipefail

TECHNIQUES=(
    "T1059.001"
    "T1059.004"
    "T1547.001"
    "T1055"
    "T1486"
    "T1003.001"
    "T1021.002"
)

echo "=== Atomic Red Team + EDR Validation ==="

for technique in "${TECHNIQUES[@]}"; do
    echo "Testing $technique..."

    if command -v Invoke-AtomicTest >/dev/null 2>&1; then
        Invoke-AtomicTest "$technique" -TimeoutSeconds 30 2>/dev/null || true
    elif command -v atomic-runner >/dev/null 2>&1; then
        atomic-runner --technique "$technique" --timeout 30 2>/dev/null || true
    else
        echo "  (atomic-red-team not installed, skipping $technique)"
        continue
    fi

    sleep 2
    if curl -s -H "X-EDR-API-Key: $(cat /var/lib/edr-agent/management_api.key)" \
       http://127.0.0.1:8080/api/v1/detections 2>/dev/null | grep -q "$technique"; then
        echo "  $technique detected"
    else
        echo "  $technique not detected (check logs)"
    fi
done
