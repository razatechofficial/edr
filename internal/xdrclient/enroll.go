package xdrclient

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/razatechofficial/edr/internal/config"
	enrollmentv1 "github.com/razatechofficial/xdr/api/proto/enrollment/v1"
)

func truncFP(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "…"
}

// EnrollOptions configures bootstrap Register.
type EnrollOptions struct {
	Config     config.XDRConfig
	AgentID    string
	AgentVer   string
	DataDir    string
	Logger     *slog.Logger
	// ConfigPath is the agent.yaml path; used to wipe enrollment_token after Register.
	ConfigPath string
	// TokenFileUsed is the bootstrap token sidecar path to delete after Register.
	TokenFileUsed string
	// SkipBootstrapClear leaves token file/yaml intact (tests / special ops).
	SkipBootstrapClear bool
	// Force re-runs Register even when OS keystore already has credentials.
	Force bool
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
	store := Store{
		Dir:     resolveCertDir(opt.Config, opt.DataDir),
		DataDir: opt.DataDir,
		Backend: opt.Config.SecureStorage,
	}
	if !opt.Force && store.HasCredentials() {
		st, err := store.Load()
		if err == nil && st.AgentID != "" && len(st.IngestHosts) > 0 {
			if len(opt.Config.IngestHosts) > 0 {
				st.IngestHosts = append([]string(nil), opt.Config.IngestHosts...)
			}
			log.Info("xdr enrollment credentials loaded",
				"cert_dir", store.Dir,
				"secure_storage", st.SecureStorage,
				"ingest_hosts", st.IngestHosts,
			)
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

	agentVer := opt.AgentVer
	if agentVer == "" {
		agentVer = "dev"
	}
	dev := CollectDeviceIdentity(opt.AgentID, opt.Config.MachineID, agentVer, token)

	// On-device keygen + CSR with full device identity (private key never leaves device).
	keyCSR, err := GenerateKeyAndCSRWithIdentity(dev)
	if err != nil {
		return nil, err
	}
	log.Info("xdr device identity keypair generated for secure storage",
		"agent_id", dev.AgentID,
		"machine_id", dev.MachineID,
		"hostname", dev.Hostname,
		"manufacturer", dev.Manufacturer,
		"model", dev.ProductModel,
		"hw_serial", dev.HardwareSerial,
		"primary_ip", dev.PrimaryIP,
		"timezone", dev.Timezone,
		"enroll_ts", dev.EnrollTimestamp,
		"enrollment_token_fp", truncFP(dev.EnrollmentTokenFP),
	)

	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial enrollment %s: %w", host, err)
	}
	defer conn.Close()

	client := enrollmentv1.NewEnrollmentServiceClient(conn)
	resp, err := client.Register(ctx, &enrollmentv1.RegisterRequest{
		EnrollmentToken: token,
		AgentId:         opt.AgentID,
		Hostname:        dev.Hostname,
		OsFamily:        dev.OSFamily,
		OsVersion:       dev.OSVersion,
		AgentVersion:    agentVer,
		MachineId:       dev.MachineID,
		CsrPem:          keyCSR.CSRPEM,
		Labels:          dev.Labels(),
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
		MachineID:      dev.MachineID,
		CertificatePEM: resp.GetCertificatePem(),
		CAChainPEM:     resp.GetCaChainPem(),
		IngestHosts:    hosts,
		HeartbeatSec:   resp.GetHeartbeatSec(),
		CertNotAfter:   notAfter,
		EnrolledAt:     time.Now().UTC(),
	}
	if err := store.SaveWithCSR(st, keyCSR.KeyPEM, keyCSR.CSRPEM); err != nil {
		return nil, err
	}
	st.SecureStorage = store.BackendName()
	if !opt.SkipBootstrapClear {
		tokenFile := strings.TrimSpace(opt.TokenFileUsed)
		if tokenFile == "" {
			tokenFile = strings.TrimSpace(opt.Config.EnrollmentTokenFile)
		}
		if err := ClearBootstrapMaterial(opt.ConfigPath, tokenFile); err != nil {
			log.Warn("xdr enrollment succeeded but bootstrap token cleanup failed", "error", err)
		} else if tokenFile != "" || strings.TrimSpace(opt.ConfigPath) != "" {
			log.Info("xdr bootstrap token cleared after enrollment")
		}
	}
	log.Info("xdr enrollment complete; key+cert in OS secure storage",
		"agent_id", st.AgentID,
		"secure_storage", st.SecureStorage,
		"cert_dir", store.Dir,
		"ingest_hosts", st.IngestHosts,
		"heartbeat_sec", st.HeartbeatSec,
		"cert_not_after", st.CertNotAfter,
	)
	return &EnrollResult{State: st, Store: store, Fresh: true}, nil
}
