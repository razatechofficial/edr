package xdrclient

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/razatechofficial/edr/internal/config"
	enrollmentv1 "github.com/razatechofficial/xdr/api/proto/enrollment/v1"
)

// EnrollOptions configures bootstrap Register.
type EnrollOptions struct {
	Config     config.XDRConfig
	AgentID    string
	AgentVer   string
	DataDir    string
	Logger     *slog.Logger
}

// EnrollResult is returned after Register (or when already enrolled).
type EnrollResult struct {
	State State
	Store Store
	Fresh bool // true if Register was called this run
}

func resolveCertDir(cfg config.XDRConfig, dataDir string) string {
	if d := strings.TrimSpace(cfg.CertDir); d != "" {
		return d
	}
	return strings.TrimRight(dataDir, "/") + "/xdr-tls"
}

// EnsureEnrolled loads existing credentials or calls EnrollmentService/Register.
func EnsureEnrolled(ctx context.Context, opt EnrollOptions) (*EnrollResult, error) {
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}
	store := Store{Dir: resolveCertDir(opt.Config, opt.DataDir)}
	if store.HasCredentials() {
		st, err := store.Load()
		if err == nil && st.AgentID != "" && len(st.IngestHosts) > 0 {
			if tid := strings.TrimSpace(opt.Config.TenantID); tid != "" && st.TenantID == "" {
				st.TenantID = tid
			}
			if len(opt.Config.IngestHosts) > 0 {
				st.IngestHosts = append([]string(nil), opt.Config.IngestHosts...)
			}
			log.Info("xdr enrollment credentials loaded", "cert_dir", store.Dir, "ingest_hosts", st.IngestHosts)
			return &EnrollResult{State: st, Store: store, Fresh: false}, nil
		}
	}

	host := strings.TrimSpace(opt.Config.EnrollmentHost)
	token := strings.TrimSpace(opt.Config.EnrollmentToken)
	if host == "" || token == "" {
		return nil, fmt.Errorf("xdr enrollment requires enrollment_host and enrollment_token")
	}
	if opt.AgentID == "" {
		return nil, fmt.Errorf("agent_id required")
	}

	keyCSR, err := GenerateKeyAndCSR(opt.AgentID)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial enrollment %s: %w", host, err)
	}
	defer conn.Close()

	client := enrollmentv1.NewEnrollmentServiceClient(conn)
	machineID := ResolveMachineID(opt.Config.MachineID)
	hostname := Hostname()
	osFamily := runtime.GOOS
	osVersion := runtime.GOARCH
	agentVer := opt.AgentVer
	if agentVer == "" {
		agentVer = "dev"
	}

	resp, err := client.Register(ctx, &enrollmentv1.RegisterRequest{
		EnrollmentToken: token,
		AgentId:         opt.AgentID,
		Hostname:        hostname,
		OsFamily:        osFamily,
		OsVersion:       osVersion,
		AgentVersion:    agentVer,
		MachineId:       machineID,
		CsrPem:          keyCSR.CSRPEM,
		Labels:          map[string]string{"source": "edr-agent"},
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment register: %w", err)
	}
	if !resp.GetAccepted() || resp.GetCertificatePem() == "" {
		return nil, fmt.Errorf("enrollment rejected: %s", resp.GetMessage())
	}

	notAfter, err := CertNotAfter(resp.GetCertificatePem())
	if err != nil {
		notAfter = time.Now().UTC().Add(365 * 24 * time.Hour)
	}
	hosts := resp.GetIngestHosts()
	if len(opt.Config.IngestHosts) > 0 {
		hosts = append([]string(nil), opt.Config.IngestHosts...)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("enrollment returned no ingest_hosts")
	}

	st := State{
		AgentID:        opt.AgentID,
		TenantID:       strings.TrimSpace(opt.Config.TenantID),
		MachineID:      machineID,
		CertificatePEM: resp.GetCertificatePem(),
		CAChainPEM:     resp.GetCaChainPem(),
		IngestHosts:    hosts,
		HeartbeatSec:   resp.GetHeartbeatSec(),
		CertNotAfter:   notAfter,
		EnrolledAt:     time.Now().UTC(),
	}
	if err := store.Save(st, keyCSR.KeyPEM); err != nil {
		return nil, err
	}
	log.Info("xdr enrollment complete",
		"agent_id", st.AgentID,
		"ingest_hosts", st.IngestHosts,
		"heartbeat_sec", st.HeartbeatSec,
		"cert_not_after", st.CertNotAfter,
	)
	return &EnrollResult{State: st, Store: store, Fresh: true}, nil
}
