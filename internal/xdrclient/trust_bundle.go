package xdrclient

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc"

	enrollmentv1 "github.com/razatechofficial/xdr/api/proto/enrollment/v1"
)

// EnsureTrustCA loads ca-chain.pem (and ingest-ca.pem) from disk, or fetches the
// public trust bundle from enrollment when the sidecar was wiped with /tmp.
func EnsureTrustCA(ctx context.Context, store Store, enrollmentHost string, insecureSkip bool) error {
	if store.CAFilePresent() {
		return nil
	}
	host := strings.TrimSpace(enrollmentHost)
	if host == "" {
		return fmt.Errorf("ca-chain.pem missing and enrollment_host empty; cannot fetch trust bundle")
	}
	chain, err := FetchTrustBundle(ctx, host, insecureSkip)
	if err != nil {
		return err
	}
	return store.WriteCAChain(chain)
}

// FetchTrustBundle dials enrollment GetTrustBundle (no token).
func FetchTrustBundle(ctx context.Context, enrollmentHost string, insecureSkip bool) ([]string, error) {
	conn, err := grpc.NewClient(enrollmentHost, EnrollmentDialOptions(enrollmentHost, insecureSkip)...)
	if err != nil {
		return nil, fmt.Errorf("dial enrollment for trust bundle: %w", err)
	}
	defer conn.Close()
	resp, err := enrollmentv1.NewEnrollmentServiceClient(conn).GetTrustBundle(ctx, &enrollmentv1.GetTrustBundleRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetTrustBundle: %w", err)
	}
	if len(resp.GetCaChainPem()) == 0 {
		return nil, fmt.Errorf("GetTrustBundle returned empty CA chain")
	}
	return resp.GetCaChainPem(), nil
}

// CAFilePresent reports whether ca-chain.pem or ingest-ca.pem exists.
func (s Store) CAFilePresent() bool {
	for _, name := range []string{caFileName, "ingest-ca.pem"} {
		p := filepath.Join(s.Dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			return true
		}
	}
	return false
}

// WriteCAChain persists public CA PEMs for ingest server verification.
func (s Store) WriteCAChain(pems []string) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	var b strings.Builder
	for _, p := range pems {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b.WriteString(p)
		if !strings.HasSuffix(p, "\n") {
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		return fmt.Errorf("empty CA chain")
	}
	data := []byte(b.String())
	if err := os.WriteFile(s.caPath(), data, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, "ingest-ca.pem"), data, 0o600)
}
