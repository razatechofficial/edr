#!/bin/bash
# edr/scripts/local_macos_e2e_probes.sh
set -euo pipefail
ALERT="${EDR_ALERT_FILE:-/tmp/edr-agent-xdr-e2e/alerts/alerts.jsonl}"
mkdir -p "$(dirname "$ALERT")"
BEFORE=$(wc -l < "$ALERT" 2>/dev/null || echo 0)

echo "== 1) FILE: script in /tmp (expect FILE-010) =="
PROBE="/tmp/edr_e2e_probe_$$.sh"
echo '#!/bin/sh' > "$PROBE"
echo "echo e2e-probe" >> "$PROBE"
chmod +x "$PROBE"

echo "== 2) FILE: LaunchAgent (expect FILE-006) =="
PLIST="$HOME/Library/LaunchAgents/com.edr.e2e.probe.plist"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.edr.e2e.probe</string>
  <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
  <key>RunAtLoad</key><false/>
</dict></plist>
EOF

echo "== 3) NET: listen on 4444 (expect NET-001) =="
nc -l 4444 >/dev/null 2>&1 &
NCPID=$!
sleep 1
echo e2e | nc -w 2 127.0.0.1 4444 || true
kill "$NCPID" 2>/dev/null || true

echo "== 4) AUTH: sudo (expect UL sudo Sigma) =="
sudo -n true 2>/dev/null || sudo true

echo "Waiting 8s for collectors…"
sleep 8

echo "== New alerts since start =="
tail -n +"$((BEFORE + 1))" "$ALERT" 2>/dev/null || echo "(no new lines yet)"

# cleanup
rm -f "$PROBE" "$PLIST"
echo "Done. Also check /logs for file/network/auth telemetry."