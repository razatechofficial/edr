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

## Install + enroll (production)

Install and enroll are separate steps. The installer defaults to
`enroll.xdr.averox.com:443` / `ingest.xdr.averox.com:443` over TLS.

Create a one-time token in the console (**EDR agents → Enrollment token**), then:

```bash
# macOS / Linux (token from console; host is baked in)
sudo ./edr-installer install --enrollment-token "$TOKEN"

# Already installed: enroll without reinstall
sudo edrctl enroll --token "$TOKEN"
```

Token is written to a root-only sidecar and cleared after Register (unless `--delay-enroll`).
Tenant is bound server-side from the enrollment token (not an agent input).

Lab only: add `--enrollment-insecure` and `--enrollment-host 127.0.0.1:50051`.

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
