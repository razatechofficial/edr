// Package xdrclient enrolls the agent with xdr-enrollment and streams OCSF
// telemetry to xdr-ingest over gRPC (TelemetryService/StreamTelemetry).
package xdrclient

import (
	"crypto/ecdsa"
)

// KeyAndCSR holds a newly generated EC P-256 key and CSR PEM.
// The private key is generated on-device and sealed into secure storage;
// only the public CSR is sent to enrollment.
type KeyAndCSR struct {
	PrivateKey *ecdsa.PrivateKey
	KeyPEM     []byte
	CSRPEM     string
}
