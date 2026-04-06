package response

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ForensicsManifest describes the contents and chain of custody for a
// forensics collection package.
type ForensicsManifest struct {
	PackageID   string            `json:"package_id"`
	AlertID     string            `json:"alert_id"`
	Hostname    string            `json:"hostname"`
	Platform    string            `json:"platform"`
	CollectedAt time.Time         `json:"collected_at"`
	CollectedBy string            `json:"collected_by"`
	Artifacts   []ArtifactRecord  `json:"artifacts"`
	SHA256      string            `json:"sha256"`
	Encrypted   bool              `json:"encrypted"`
}

// ArtifactRecord describes a single artifact collected during forensics.
type ArtifactRecord struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size"`
	Collected bool  `json:"collected"`
	Error    string `json:"error,omitempty"`
}

// ForensicsHandler implements ActionHandler for comprehensive evidence
// collection. It coordinates gathering of process data, memory, network
// state, file artifacts, and system configuration into a signed, encrypted
// DFIR container.
type ForensicsHandler struct {
	logger    *zap.Logger
	outputDir string
	encKey    []byte
}

// NewForensicsHandler creates a handler that writes DFIR packages to outputDir.
func NewForensicsHandler(logger *zap.Logger, outputDir string, encryptionKey []byte) *ForensicsHandler {
	if outputDir == "" {
		outputDir = "/var/lib/edr/forensics/packages"
	}
	return &ForensicsHandler{
		logger:    logger,
		outputDir: outputDir,
		encKey:    encryptionKey,
	}
}

// Execute collects all forensic artifacts for the given alert context.
// Params: "pid" (int, optional), "alert_id" (string), "operator" (string).
func (h *ForensicsHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	alertID := stringParam(params, "alert_id")
	if alertID == "" {
		alertID = "unknown"
	}
	pid, _ := intParam(params, "pid")

	if err := os.MkdirAll(h.outputDir, 0o750); err != nil {
		return failResult(ActionCollectForensics, err.Error()),
			fmt.Errorf("forensics handler: create output dir: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	packageID := fmt.Sprintf("dfir_%s_%s", alertID, ts)
	workDir := filepath.Join(h.outputDir, packageID)
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return failResult(ActionCollectForensics, err.Error()),
			fmt.Errorf("forensics handler: create work dir: %w", err)
	}

	var artifacts []ArtifactRecord

	// Collect process information.
	if pid > 0 {
		artifacts = append(artifacts, h.collectProcessInfo(ctx, pid, workDir)...)
	}

	// Collect network state.
	artifacts = append(artifacts, h.collectNetworkState(ctx, workDir)...)

	// Collect system information.
	artifacts = append(artifacts, h.collectSystemInfo(ctx, workDir)...)

	// Collect recent logs.
	artifacts = append(artifacts, h.collectLogs(ctx, workDir)...)

	// Package into tarball.
	tarPath := filepath.Join(h.outputDir, packageID+".tar.gz")
	if err := createTarGz(tarPath, workDir); err != nil {
		return failResult(ActionCollectForensics, fmt.Sprintf("create tarball: %s", err)),
			fmt.Errorf("forensics handler: tar: %w", err)
	}

	// Compute hash of the package.
	pkgHash, _ := sha256File(tarPath)

	// Encrypt if key available.
	finalPath := tarPath
	encrypted := false
	if len(h.encKey) == 32 {
		encPath := tarPath + ".enc"
		if err := encryptFile(tarPath, encPath, h.encKey); err != nil {
			h.logger.Error("forensics encryption failed", zap.Error(err))
		} else {
			_ = os.Remove(tarPath)
			finalPath = encPath
			encrypted = true
		}
	}

	hostname, _ := os.Hostname()
	manifest := ForensicsManifest{
		PackageID:   packageID,
		AlertID:     alertID,
		Hostname:    hostname,
		Platform:    runtime.GOOS,
		CollectedAt: time.Now().UTC(),
		CollectedBy: stringParam(params, "operator"),
		Artifacts:   artifacts,
		SHA256:      pkgHash,
		Encrypted:   encrypted,
	}

	manifestPath := filepath.Join(h.outputDir, packageID+".manifest.json")
	if data, err := json.MarshalIndent(manifest, "", "  "); err == nil {
		_ = os.WriteFile(manifestPath, data, 0o640)
	}

	// Clean up work directory.
	_ = os.RemoveAll(workDir)

	collected := 0
	for _, a := range artifacts {
		if a.Collected {
			collected++
		}
	}

	return okResult(ActionCollectForensics,
		fmt.Sprintf("forensics package %s: %d/%d artifacts collected, saved to %s",
			packageID, collected, len(artifacts), finalPath)), nil
}

// Rollback is a no-op; forensic evidence must not be destroyed.
func (h *ForensicsHandler) Rollback(_ context.Context, _ map[string]interface{}) error {
	return nil
}

// ---------------------------------------------------------------------------
// Artifact collectors
// ---------------------------------------------------------------------------

func (h *ForensicsHandler) collectProcessInfo(ctx context.Context, pid int, workDir string) []ArtifactRecord {
	var records []ArtifactRecord
	pidStr := strconv.Itoa(pid)
	procDir := filepath.Join(workDir, "process")
	_ = os.MkdirAll(procDir, 0o750)

	switch runtime.GOOS {
	case "linux":
		procFiles := []string{"status", "cmdline", "environ", "maps", "fd", "cgroup", "mountinfo"}
		for _, name := range procFiles {
			src := fmt.Sprintf("/proc/%s/%s", pidStr, name)
			dst := filepath.Join(procDir, name)
			rec := collectFile(src, dst)
			rec.Type = "process_" + name
			records = append(records, rec)
		}
		// Open file descriptors.
		if out, err := cmdOutput(ctx, "ls", "-la", fmt.Sprintf("/proc/%s/fd", pidStr)); err == nil {
			dst := filepath.Join(procDir, "fd_list.txt")
			_ = os.WriteFile(dst, out, 0o640)
			records = append(records, ArtifactRecord{Type: "process_fd_list", Path: dst, Size: int64(len(out)), Collected: true})
		}
	case "darwin":
		// Use lsof for open files.
		if out, err := cmdOutput(ctx, "lsof", "-p", pidStr); err == nil {
			dst := filepath.Join(procDir, "lsof.txt")
			_ = os.WriteFile(dst, out, 0o640)
			records = append(records, ArtifactRecord{Type: "process_lsof", Path: dst, Size: int64(len(out)), Collected: true})
		}
		// Process info via ps.
		if out, err := cmdOutput(ctx, "ps", "-p", pidStr, "-o", "pid,ppid,user,stat,command"); err == nil {
			dst := filepath.Join(procDir, "ps.txt")
			_ = os.WriteFile(dst, out, 0o640)
			records = append(records, ArtifactRecord{Type: "process_ps", Path: dst, Size: int64(len(out)), Collected: true})
		}
	}
	return records
}

func (h *ForensicsHandler) collectNetworkState(ctx context.Context, workDir string) []ArtifactRecord {
	var records []ArtifactRecord
	netDir := filepath.Join(workDir, "network")
	_ = os.MkdirAll(netDir, 0o750)

	// Active connections.
	var netstatArgs []string
	switch runtime.GOOS {
	case "linux":
		netstatArgs = []string{"-tulnp"}
	case "darwin":
		netstatArgs = []string{"-an", "-p", "tcp"}
	}
	if len(netstatArgs) > 0 {
		if out, err := cmdOutput(ctx, "netstat", netstatArgs...); err == nil {
			dst := filepath.Join(netDir, "connections.txt")
			_ = os.WriteFile(dst, out, 0o640)
			records = append(records, ArtifactRecord{Type: "network_connections", Path: dst, Size: int64(len(out)), Collected: true})
		}
	}

	// ss on Linux for socket detail.
	if runtime.GOOS == "linux" {
		if out, err := cmdOutput(ctx, "ss", "-tunlp"); err == nil {
			dst := filepath.Join(netDir, "ss.txt")
			_ = os.WriteFile(dst, out, 0o640)
			records = append(records, ArtifactRecord{Type: "network_ss", Path: dst, Size: int64(len(out)), Collected: true})
		}
	}

	// ARP cache.
	if out, err := cmdOutput(ctx, "arp", "-a"); err == nil {
		dst := filepath.Join(netDir, "arp.txt")
		_ = os.WriteFile(dst, out, 0o640)
		records = append(records, ArtifactRecord{Type: "network_arp", Path: dst, Size: int64(len(out)), Collected: true})
	}

	// DNS resolver config.
	if runtime.GOOS != "windows" {
		rec := collectFile("/etc/resolv.conf", filepath.Join(netDir, "resolv.conf"))
		rec.Type = "network_dns"
		records = append(records, rec)
	}

	return records
}

func (h *ForensicsHandler) collectSystemInfo(ctx context.Context, workDir string) []ArtifactRecord {
	var records []ArtifactRecord
	sysDir := filepath.Join(workDir, "system")
	_ = os.MkdirAll(sysDir, 0o750)

	// Hostname and uname.
	if out, err := cmdOutput(ctx, "uname", "-a"); err == nil {
		dst := filepath.Join(sysDir, "uname.txt")
		_ = os.WriteFile(dst, out, 0o640)
		records = append(records, ArtifactRecord{Type: "system_uname", Path: dst, Size: int64(len(out)), Collected: true})
	}

	// Environment.
	if out, err := cmdOutput(ctx, "env"); err == nil {
		dst := filepath.Join(sysDir, "env.txt")
		_ = os.WriteFile(dst, out, 0o640)
		records = append(records, ArtifactRecord{Type: "system_env", Path: dst, Size: int64(len(out)), Collected: true})
	}

	// Loaded kernel modules (Linux).
	if runtime.GOOS == "linux" {
		rec := collectFile("/proc/modules", filepath.Join(sysDir, "modules.txt"))
		rec.Type = "system_modules"
		records = append(records, rec)
	}

	// Running processes.
	if out, err := cmdOutput(ctx, "ps", "auxf"); err == nil {
		dst := filepath.Join(sysDir, "ps_full.txt")
		_ = os.WriteFile(dst, out, 0o640)
		records = append(records, ArtifactRecord{Type: "system_processes", Path: dst, Size: int64(len(out)), Collected: true})
	}

	return records
}

func (h *ForensicsHandler) collectLogs(ctx context.Context, workDir string) []ArtifactRecord {
	var records []ArtifactRecord
	logDir := filepath.Join(workDir, "logs")
	_ = os.MkdirAll(logDir, 0o750)

	switch runtime.GOOS {
	case "linux":
		// Last 1000 lines of syslog/auth.
		for _, logFile := range []string{"/var/log/syslog", "/var/log/auth.log", "/var/log/messages", "/var/log/secure"} {
			base := filepath.Base(logFile)
			dst := filepath.Join(logDir, base)
			rec := collectFileTail(logFile, dst, 1000)
			rec.Type = "log_" + strings.TrimSuffix(base, ".log")
			records = append(records, rec)
		}
		// Journalctl recent entries.
		if out, err := cmdOutput(ctx, "journalctl", "--no-pager", "-n", "1000", "--output=short-precise"); err == nil {
			dst := filepath.Join(logDir, "journal.txt")
			_ = os.WriteFile(dst, out, 0o640)
			records = append(records, ArtifactRecord{Type: "log_journal", Path: dst, Size: int64(len(out)), Collected: true})
		}
	case "darwin":
		if out, err := cmdOutput(ctx, "log", "show", "--predicate", "eventMessage contains 'error'", "--last", "1h"); err == nil {
			dst := filepath.Join(logDir, "system.log")
			_ = os.WriteFile(dst, out, 0o640)
			records = append(records, ArtifactRecord{Type: "log_system", Path: dst, Size: int64(len(out)), Collected: true})
		}
	}

	return records
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func collectFile(src, dst string) ArtifactRecord {
	data, err := os.ReadFile(src)
	if err != nil {
		return ArtifactRecord{Path: src, Collected: false, Error: err.Error()}
	}
	if err := os.WriteFile(dst, data, 0o640); err != nil {
		return ArtifactRecord{Path: src, Collected: false, Error: err.Error()}
	}
	h := sha256.Sum256(data)
	return ArtifactRecord{
		Path:      dst,
		SHA256:    hex.EncodeToString(h[:]),
		Size:      int64(len(data)),
		Collected: true,
	}
}

func collectFileTail(src, dst string, lines int) ArtifactRecord {
	out, err := cmdOutput(context.Background(), "tail", "-n", strconv.Itoa(lines), src)
	if err != nil {
		return ArtifactRecord{Path: src, Collected: false, Error: err.Error()}
	}
	if err := os.WriteFile(dst, out, 0o640); err != nil {
		return ArtifactRecord{Path: src, Collected: false, Error: err.Error()}
	}
	h := sha256.Sum256(out)
	return ArtifactRecord{
		Path:      dst,
		SHA256:    hex.EncodeToString(h[:]),
		Size:      int64(len(out)),
		Collected: true,
	}
}

func cmdOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

func createTarGz(dst, srcDir string) error {
	outFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create tar.gz: %w", err)
	}
	defer outFile.Close()

	gz := gzip.NewWriter(outFile)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel

		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}
