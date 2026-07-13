# XDR Integration (enrollment + ingest)

The agent can talk to **xdr-enrollment** and **xdr-ingest** without using the API gateway.

## Enable

Merge `configs/linux/config.xdr.yml` into your agent config (or set env vars):

| Setting | Env | Purpose |
|---------|-----|---------|
| `xdr.enabled` | `XDR_ENABLED` | Turn on XDR path |
| `xdr.enrollment_host` | `XDR_ENROLLMENT_HOST` | `host:port` of enrollment bootstrap (`:50051`) |
| `xdr.enrollment_token` | `XDR_ENROLLMENT_TOKEN` | One-time token from gateway/admin |
| `xdr.tenant_id` | `XDR_TENANT_ID` | Required until RegisterResponse returns tenant_id |
| `xdr.insecure_skip_tls` | — | `true` for local/dev (plain gRPC) |
| `xdr.spool_max_age_days` | — | Default **7** (drop oldest spool segments) |
| `xdr.spool_max_bytes` | — | Default **1 GiB** |
| `xdr.renew_before_days` | — | Default **7** (cert watch) |

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
export XDR_TENANT_ID=550e8400-e29b-41d4-a716-446655440001

# Run agent with config that includes xdr: section
```

## Package layout

- `internal/xdrclient/` — CSR, enroll, renew, ingest stream, TLS store
- `internal/agent/agent_xdr.go` — startup wiring
- `internal/forwarder.LineSender` — pluggable transport (HTTP or gRPC)
