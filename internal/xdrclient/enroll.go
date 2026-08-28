package xdrclient

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"

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
	Config   config.XDRConfig
	AgentID  string
	AgentVer string
	DataDir  string
	Logger   *slog.Logger
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

func ResolveCertDir(cfg config.XDRConfig, dataDir string) string {
	if d := strings.TrimSpace(cfg.CertDir); d != "" {
		return d
	}
	return filepath.Join(dataDir, "xdr-tls")
}

func resolveCertDir(cfg config.XDRConfig, dataDir string) string {
	return ResolveCertDir(cfg, dataDir)
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
	WriteEnrollProgress(opt.DataDir, "token")
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
			if err := EnsureTrustCA(ctx, store, opt.Config.EnrollmentHost, opt.Config.InsecureSkipTLS); err != nil {
				log.Warn("xdr trust CA missing; ingest mTLS may fail", "error", err)
			}
			if err := store.RebindDaemonReadable(st); err != nil {
				log.Warn("xdr could not rebind identity for the sensor service", "error", err)
			}
			enableIngestYAML(opt, st, log)
			WriteEnrollProgress(opt.DataDir, "done")
			return &EnrollResult{State: st, Store: store, Fresh: false}, nil
		}
		// Industry: device identity is the key+cert. enrollment.json is a sidecar.
		// If the sidecar was wiped (/tmp), rebuild it from the cert — do not demand a token.
		recovered, recErr := recoverStateFromCredentials(store, opt.Config, opt.AgentID)
		if recErr == nil {
			if err := store.SaveMetadata(recovered); err != nil {
				log.Warn("xdr recovered enrollment metadata but failed to persist enrollment.json",
					"cert_dir", store.Dir, "error", err)
			} else {
				log.Info("xdr enrollment recovered from device certificate (no token needed)",
					"agent_id", recovered.AgentID,
					"cert_dir", store.Dir,
					"ingest_hosts", recovered.IngestHosts,
				)
			}
			if err := EnsureTrustCA(ctx, store, opt.Config.EnrollmentHost, opt.Config.InsecureSkipTLS); err != nil {
				log.Warn("xdr trust CA missing after recover; ingest mTLS will fail until CA is restored",
					"cert_dir", store.Dir, "error", err)
			} else {
				log.Info("xdr trust CA ready for ingest", "ca_path", store.CAPath())
			}
			enableIngestYAML(opt, recovered, log)
			WriteEnrollProgress(opt.DataDir, "done")
			return &EnrollResult{State: recovered, Store: store, Fresh: false}, nil
		}
		if err != nil {
			log.Warn("secure store has key/cert but enrollment state is unreadable; cannot resume without ingest_hosts",
				"cert_dir", store.Dir, "load_error", err, "recover_error", recErr)
		} else {
			log.Warn("secure store has key/cert but enrollment.json is incomplete; cannot resume",
				"cert_dir", store.Dir, "recover_error", recErr)
		}
	}

	host := strings.TrimSpace(opt.Config.EnrollmentHost)
	token := strings.TrimSpace(opt.Config.EnrollmentToken)
	if host == "" || token == "" {
		return nil, fmt.Errorf("no usable local enrollment (need device cert + ingest_hosts, or %s/enrollment.json); set enrollment_host and a one-time enrollment_token to Register, then restart without the token", store.Dir)
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
	WriteEnrollProgress(opt.DataDir, "key")
	keyCSR, err := GenerateKeyAndCSRWithIdentity(dev)
	if err != nil {
		return nil, err
	}
	WriteEnrollProgress(opt.DataDir, "csr")
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

	conn, err := grpc.NewClient(host, EnrollmentDialOptions(host, opt.Config.InsecureSkipTLS)...)
	if err != nil {
		return nil, fmt.Errorf("dial enrollment %s: %w", host, err)
	}
	defer conn.Close()

	client := enrollmentv1.NewEnrollmentServiceClient(conn)
	WriteEnrollProgress(opt.DataDir, "sign")
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
	WriteEnrollProgress(opt.DataDir, "cert")

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
	WriteEnrollProgress(opt.DataDir, "store")
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
	WriteEnrollProgress(opt.DataDir, "ingest")
	log.Info("xdr enrollment complete; key+cert in OS secure storage",
		"agent_id", st.AgentID,
		"secure_storage", st.SecureStorage,
		"cert_dir", store.Dir,
		"ingest_hosts", st.IngestHosts,
		"heartbeat_sec", st.HeartbeatSec,
		"cert_not_after", st.CertNotAfter,
	)
	enableIngestYAML(opt, st, log)
	WriteEnrollProgress(opt.DataDir, "done")
	return &EnrollResult{State: st, Store: store, Fresh: true}, nil
}

func enableIngestYAML(opt EnrollOptions, st State, log *slog.Logger) {
	p := strings.TrimSpace(opt.ConfigPath)
	if p == "" {
		return
	}
	if err := EnableIngestFromEnrollment(p, st); err != nil {
		log.Warn("xdr could not enable ingest in agent.yaml", "error", err)
	}
}

// recoverStateFromCredentials rebuilds State from keystore cert + config when
// enrollment.json is missing/incomplete. Does not call Register (no token).
func recoverStateFromCredentials(store Store, cfg config.XDRConfig, fallbackAgentID string) (State, error) {
	certPEM, err := store.LoadCertificatePEM()
	if err != nil || len(certPEM) == 0 {
		return State{}, fmt.Errorf("load certificate: %w", err)
	}
	agentID, err := AgentIDFromCert(string(certPEM))
	if err != nil || agentID == "" {
		agentID = strings.TrimSpace(fallbackAgentID)
	}
	if agentID == "" {
		return State{}, fmt.Errorf("cannot derive agent_id from certificate CN")
	}
	hosts := append([]string(nil), cfg.IngestHosts...)
	if len(hosts) == 0 {
		hosts = defaultIngestHosts(cfg.EnrollmentHost)
	}
	if len(hosts) == 0 {
		return State{}, fmt.Errorf("ingest_hosts required to resume (set xdr.ingest_hosts in config)")
	}
	notAfter, _ := CertNotAfter(string(certPEM))
	machineID := MachineIDFromCert(string(certPEM))
	if machineID == "" {
		machineID = ResolveMachineID(cfg.MachineID)
	}
	hb := int32(30)
	st := State{
		AgentID:        agentID,
		MachineID:      machineID,
		CertificatePEM: string(certPEM),
		CAChainPEM:     store.LoadCAChainPEM(),
		IngestHosts:    hosts,
		HeartbeatSec:   hb,
		CertNotAfter:   notAfter,
		EnrolledAt:     time.Now().UTC(),
		SecureStorage:  store.BackendName(),
	}
	return st, nil
}

// defaultIngestHosts maps local enrollment host to the common ingest port when
// ingest_hosts was never persisted (e2e /tmp wipe of enrollment.json).
func defaultIngestHosts(enrollmentHost string) []string {
	if isLoopbackEnrollmentHost(enrollmentHost) {
		return []string{"127.0.0.1:9020"}
	}
	return DefaultIngestHosts()
}
