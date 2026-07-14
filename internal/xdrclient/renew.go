package xdrclient

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/razatechofficial/edr/internal/config"
	enrollmentv1 "github.com/razatechofficial/xdr/api/proto/enrollment/v1"
)

// NeedsRenew reports whether the cert should be renewed (within renewBefore days).
func NeedsRenew(notAfter time.Time, renewBeforeDays int) bool {
	if notAfter.IsZero() {
		return false
	}
	if renewBeforeDays <= 0 {
		renewBeforeDays = 7
	}
	return time.Now().UTC().After(notAfter.Add(-time.Duration(renewBeforeDays) * 24 * time.Hour))
}

// RenewOptions configures EnrollmentService/Renew.
type RenewOptions struct {
	Config   config.XDRConfig
	State    State
	Store    Store
	AgentVer string
	Logger   *slog.Logger
}

// RenewCertificate generates a new key/CSR and calls Renew. In production the
// renew listener expects mTLS with the current agent cert.
func RenewCertificate(ctx context.Context, opt RenewOptions) (State, error) {
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}
	host := strings.TrimSpace(opt.Config.EnrollmentHost)
	if host == "" {
		return opt.State, fmt.Errorf("enrollment_host required for renew")
	}

	// Renew re-binds device identity; enrollment token is not available (already consumed).
	dev := CollectDeviceIdentity(opt.State.AgentID, opt.State.MachineID, opt.AgentVer, "")
	keyCSR, err := GenerateKeyAndCSRWithIdentity(dev)
	if err != nil {
		return opt.State, err
	}

	dialOpts, err := renewDialOptions(opt)
	if err != nil {
		return opt.State, err
	}
	conn, err := grpc.NewClient(host, dialOpts...)
	if err != nil {
		return opt.State, fmt.Errorf("dial enrollment renew: %w", err)
	}
	defer conn.Close()

	client := enrollmentv1.NewEnrollmentServiceClient(conn)
	agentVer := opt.AgentVer
	if agentVer == "" {
		agentVer = "dev"
	}
	resp, err := client.Renew(ctx, &enrollmentv1.RenewRequest{
		AgentId:      opt.State.AgentID,
		CsrPem:       keyCSR.CSRPEM,
		AgentVersion: agentVer,
		OsVersion:    runtime.GOARCH,
	})
	if err != nil {
		return opt.State, fmt.Errorf("enrollment renew: %w", err)
	}
	if !resp.GetAccepted() || resp.GetCertificatePem() == "" {
		return opt.State, fmt.Errorf("renew rejected: %s", resp.GetMessage())
	}

	notAfter, err := CertNotAfter(resp.GetCertificatePem())
	if err != nil {
		notAfter = time.Now().UTC().Add(365 * 24 * time.Hour)
	}
	st := opt.State
	st.CertificatePEM = resp.GetCertificatePem()
	st.CAChainPEM = resp.GetCaChainPem()
	st.HeartbeatSec = resp.GetHeartbeatSec()
	st.CertNotAfter = notAfter
	st.RenewedAt = time.Now().UTC()
	if err := opt.Store.SaveWithCSR(st, keyCSR.KeyPEM, keyCSR.CSRPEM); err != nil {
		return opt.State, err
	}
	log.Info("xdr certificate renewed", "cert_not_after", st.CertNotAfter)
	return st, nil
}

func renewDialOptions(opt RenewOptions) ([]grpc.DialOption, error) {
	if opt.Config.InsecureSkipTLS || !opt.Store.HasCredentials() {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	tlsCfg, err := LoadClientTLSFromStore(opt.Store)
	if err != nil {
		// Fall back to insecure for local/dev bootstrap renew listener.
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))}, nil
}

// WatchAndRenew runs a periodic cert expiry check and renews when needed.
func WatchAndRenew(ctx context.Context, opt RenewOptions, onRenewed func(State)) {
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	try := func() {
		st := opt.State
		if loaded, err := opt.Store.Load(); err == nil {
			st = loaded
			opt.State = st
		}
		if !NeedsRenew(st.CertNotAfter, opt.Config.RenewBeforeDays) {
			return
		}
		newSt, err := RenewCertificate(ctx, opt)
		if err != nil {
			log.Warn("xdr cert renew failed", "error", err)
			return
		}
		opt.State = newSt
		if onRenewed != nil {
			onRenewed(newSt)
		}
	}

	try()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			try()
		}
	}
}
