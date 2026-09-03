#!/bin/bash
set -e
mkdir -p /var/lib/edr-agent /var/lib/edr-agent/forensics /var/lib/edr-agent/quarantine /var/lib/edr-agent/alert-spool
mkdir -p /etc/edr-agent/rules
mkdir -p /var/lib/edr/bpf
chmod 700 /var/lib/edr-agent /var/lib/edr-agent/forensics /var/lib/edr-agent/quarantine /var/lib/edr-agent/alert-spool
chmod 755 /etc/edr-agent /etc/edr-agent/rules
systemctl daemon-reload
systemctl enable edr-agent
# Register only path still starts so local monitoring is available; enroll opens ingest.
systemctl start edr-agent || true
cat <<'MSG'

EDR agent installed (native deb). Enroll this host to open XDR ingest:
  sudo edrctl enroll --token <TOKEN>

Then verify:
  systemctl status edr-agent --no-pager
  sudo edrctl ui

MSG
