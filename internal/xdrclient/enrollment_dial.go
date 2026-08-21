package xdrclient

import (
	"crypto/tls"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Production public endpoints (TLS at Ingress). Do not put data-plane IPs here.
const (
	DefaultEnrollmentHost = "enroll.xdr.averox.com:443"
	DefaultIngestHost     = "ingest.xdr.averox.com:443"
)

// DefaultIngestHosts is the public ingest mTLS address returned to new installs
// when enrollment has not yet provided a host list.
func DefaultIngestHosts() []string {
	return []string{DefaultIngestHost}
}

// EnrollmentDialOptions is TLS with system roots for enroll.xdr.averox.com.
// Loopback and InsecureSkipTLS stay plaintext for local e2e.
func EnrollmentDialOptions(host string, insecureSkip bool) []grpc.DialOption {
	if insecureSkip || isLoopbackEnrollmentHost(host) {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
	}
}

func isLoopbackEnrollmentHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	name := h
	if hn, _, err := net.SplitHostPort(h); err == nil {
		name = hn
	}
	name = strings.Trim(name, "[]")
	if strings.EqualFold(name, "localhost") {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}
