package xdrclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

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
	opts := []grpc.DialOption{grpc.WithContextDialer(enrollmentContextDialer())}
	if insecureSkip || isLoopbackEnrollmentHost(host) {
		return append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	return append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
}

func enrollmentContextDialer() func(context.Context, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}
}

// ProbeEnrollmentHost checks TCP reachability before Register so a hung TLS
// handshake is not the only signal (and so enroll.last has a clear error).
func ProbeEnrollmentHost(host string, timeout time.Duration) error {
	addr := strings.TrimSpace(host)
	if addr == "" {
		return fmt.Errorf("enrollment host is empty")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
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
