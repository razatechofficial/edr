# XDR Integration (enrollment + ingest)

The agent can talk to **xdr-enrollment** and **xdr-ingest** without using the API gateway.

## Enable

Merge `configs/linux/config.xdr.yml` into your agent config (or set env vars):

| Setting | Env | Purpose |
|---------|-----|---------|
| `xdr.enabled` | `XDR_ENABLED` | Turn on XDR path |
| `xdr.enrollment_host` | `XDR_ENROLLMENT_HOST` | `host:port` of enrollment bootstrap (`:50051`) |
| `xdr.enrollment_token` | `XDR_ENROLLMENT_TOKEN` | One-time token (prefer file/flag; cleared after Register) |
| `xdr.enrollment_token_file` | `XDR_ENROLLMENT_TOKEN_FILE` | Root-only sidecar (default `{config_dir}/enrollment.token`) |
| `xdr.secure_storage` | `XDR_SECURE_STORAGE` | `auto\|keychain\|dpapi\|file` |
| `xdr.insecure_skip_tls` | — | `true` for local/dev (plain gRPC) |
| `xdr.spool_max_age_days` | — | Default **7** (drop oldest spool segments) |
| `xdr.spool_max_bytes` | — | Default **1 GiB** |
| `xdr.renew_before_days` | — | Default **7** (cert watch) |

## Install + enroll (enterprise)

Install and enroll are separate steps; prefer fleet flags / token sidecar (no end-user prompt).

```bash
# Install + enroll in one shot (token written to enrollment.token, then cleared)
sudo ./edr-installer install \
  --enrollment-host enrollment.example.com:50051 \
  --enrollment-token "$TOKEN"

# Or install only, enroll later
sudo ./edr-installer install --enrollment-host ... --enrollment-token "$TOKEN" --delay-enroll
sudo edrctl enroll --host enrollment.example.com:50051 --token-file /etc/edr/enrollment.token

# Or start agent with bootstrap flags (enrolls then streams with cert)
sudo edr-agent run --config /etc/edr/agent.yaml \
  --enrollment-host enrollment.example.com:50051 \
  --enrollment-token "$TOKEN"
```

After Register: private key + cert live in OS secure storage; bootstrap token file/yaml field are wiped. Ingest uses the signed cert (mTLS).

## Runtime flow

1. **Register** → `EnrollmentService/Register` (CSR CN = `agent.id`)
2. Persist cert/key/CA under `xdr.cert_dir` (default `{data_dir}/xdr-tls`)
3. **StreamTelemetry** → hosts from `ingest_hosts` (OCSF JSON in `payload`)
4. On send failure → existing `telemetry-queue` disk spool; drain on reconnect
5. **Cert watch** every 6h → `Renew` when within `renew_before_days`

Legacy embedded `server.*` control plane and HTTP `forwarder.telemetry_endpoint` remain available when XDR is disabled.

## Local smoke

```bash
# Create token via gateway (auth disabled) or enrollment admin gRPC, then:
export XDR_ENABLED=true
export XDR_ENROLLMENT_HOST=127.0.0.1:50051
export XDR_ENROLLMENT_TOKEN=...

# Run agent with config that includes xdr: section
# Tenant is bound server-side from the enrollment token (not an agent input).
```

## Package layout

- `internal/xdrclient/` — CSR, enroll, renew, ingest stream, TLS store
- `internal/agent/agent_xdr.go` — startup wiring
- `internal/forwarder.LineSender` — pluggable transport (HTTP or gRPC)
