package response

import (
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

// MemoryDumpMeta records metadata about a memory dump for forensic chain of
// custody and later analysis.
type MemoryDumpMeta struct {
	PID            int       `json:"pid"`
	ProcessName    string    `json:"process_name,omitempty"`
	DumpPath       string    `json:"dump_path"`
	MapsPath       string    `json:"maps_path,omitempty"`
	Platform       string    `json:"platform"`
	CapturedAt     time.Time `json:"captured_at"`
	CompressedSize int64     `json:"compressed_size"`
	Encrypted      bool      `json:"encrypted"`
	Modules        []string  `json:"modules,omitempty"`
	AlertID        string    `json:"alert_id,omitempty"`
}

// MemoryHandler implements ActionHandler for process memory forensics capture.
type MemoryHandler struct {
	logger    *zap.Logger
	outputDir string
	encKey    []byte // optional 32-byte AES-256 key
}

// NewMemoryHandler creates a handler that writes compressed, optionally
// encrypted memory dumps to outputDir.
func NewMemoryHandler(logger *zap.Logger, outputDir string, encryptionKey []byte) *MemoryHandler {
	if outputDir == "" {
		outputDir = "/var/lib/edr/forensics/memory"
	}
	return &MemoryHandler{
		logger:    logger,
		outputDir: outputDir,
		encKey:    encryptionKey,
	}
}

// Execute captures process memory. Required params: "pid" (int).
// Optional: "process_name", "alert_id".
func (h *MemoryHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	pid, err := intParam(params, "pid")
	if err != nil || pid <= 0 {
		return failResult(OpMemoryDump, "valid pid required"),
			fmt.Errorf("memory handler: invalid pid: %w", err)
	}

	if err := os.MkdirAll(h.outputDir, 0o750); err != nil {
		return failResult(OpMemoryDump, err.Error()),
			fmt.Errorf("memory handler: create output dir: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	baseName := fmt.Sprintf("memdump_%d_%s", pid, ts)
	dumpPath := filepath.Join(h.outputDir, baseName+".gz")
	metaPath := filepath.Join(h.outputDir, baseName+".meta.json")

	var modules []string
	switch runtime.GOOS {
	case "linux":
		modules, err = h.dumpLinux(ctx, pid, dumpPath)
	case "darwin":
		modules, err = h.dumpDarwin(ctx, pid, dumpPath)
	default:
		err = fmt.Errorf("memory dump not supported on %s", runtime.GOOS)
	}
	if err != nil {
		return failResult(OpMemoryDump, err.Error()), err
	}

	if len(h.encKey) == 32 {
		encPath := dumpPath + ".enc"
		if encErr := encryptFile(dumpPath, encPath, h.encKey); encErr != nil {
			h.logger.Error("memory dump encryption failed", zap.Error(encErr))
		} else {
			_ = os.Remove(dumpPath)
			dumpPath = encPath
		}
	}

	info, _ := os.Stat(dumpPath)
	var sz int64
	if info != nil {
		sz = info.Size()
	}

	meta := MemoryDumpMeta{
		PID:            pid,
		ProcessName:    stringParam(params, "process_name"),
		DumpPath:       dumpPath,
		Platform:       runtime.GOOS,
		CapturedAt:     time.Now().UTC(),
		CompressedSize: sz,
		Encrypted:      len(h.encKey) == 32,
		Modules:        modules,
		AlertID:        stringParam(params, "alert_id"),
	}
	if metaData, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = os.WriteFile(metaPath, metaData, 0o640)
	}

	return okResult(OpMemoryDump,
		fmt.Sprintf("memory dump for pid %d saved to %s (%d bytes)", pid, dumpPath, sz)), nil
}

// Rollback is a no-op; memory dumps are forensic evidence and are not reversed.
func (h *MemoryHandler) Rollback(_ context.Context, _ map[string]interface{}) error {
	return nil
}

// dumpLinux reads /proc/<pid>/mem guided by /proc/<pid>/maps, producing a
// gzip-compressed dump. Returns the list of loaded module paths.
func (h *MemoryHandler) dumpLinux(ctx context.Context, pid int, outPath string) ([]string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("memory handler: read maps: %w", err)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("memory handler: open mem: %w", err)
	}
	defer memFile.Close()

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("memory handler: create output: %w", err)
	}
	defer outFile.Close()

	gz := gzip.NewWriter(outFile)
	defer gz.Close()

	modules := make(map[string]struct{})
	for _, line := range strings.Split(string(mapsData), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if len(fields) >= 6 && fields[5] != "" {
			modules[fields[5]] = struct{}{}
		}

		// Only dump readable regions.
		if len(fields[1]) < 1 || fields[1][0] != 'r' {
			continue
		}

		addrs := strings.SplitN(fields[0], "-", 2)
		if len(addrs) != 2 {
			continue
		}
		start, err1 := strconv.ParseInt(addrs[0], 16, 64)
		end, err2 := strconv.ParseInt(addrs[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}

		// Cap individual region reads to avoid huge allocations.
		const maxRegion = 64 * 1024 * 1024
		size := end - start
		if size > maxRegion {
			size = maxRegion
		}

		buf := make([]byte, size)
		n, _ := memFile.ReadAt(buf, start)
		if n > 0 {
			_, _ = gz.Write(buf[:n])
		}
	}

	modList := make([]string, 0, len(modules))
	for m := range modules {
		modList = append(modList, m)
	}
	return modList, nil
}

// dumpDarwin uses the vmmap command to list regions and lldb to read memory.
// Full vm_read requires a signed entitlement; we fall back to vmmap metadata
// plus a core dump via lldb if available.
func (h *MemoryHandler) dumpDarwin(ctx context.Context, pid int, outPath string) ([]string, error) {
	pidStr := strconv.Itoa(pid)

	// Capture vmmap output for module listing.
	vmmapOut, err := exec.CommandContext(ctx, "vmmap", pidStr).CombinedOutput()
	if err != nil {
		h.logger.Warn("vmmap failed, continuing with limited module info",
			zap.Int("pid", pid), zap.Error(err))
	}

	modules := parseVmmapModules(string(vmmapOut))

	// Attempt core dump via lldb; requires debug entitlement.
	coreFile := outPath + ".core"
	lldbScript := fmt.Sprintf("process attach --pid %d\nprocess save-core %s\nquit\n", pid, coreFile)
	cmd := exec.CommandContext(ctx, "lldb", "--batch", "--one-line-before-file", lldbScript)
	cmd.Stdin = strings.NewReader(lldbScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		h.logger.Warn("lldb core dump failed (requires entitlement)",
			zap.Int("pid", pid), zap.Error(err), zap.String("output", string(out)))
		// Write vmmap metadata as fallback.
		if writeErr := writeCompressed(outPath, vmmapOut); writeErr != nil {
			return modules, fmt.Errorf("memory handler: write vmmap fallback: %w", writeErr)
		}
		return modules, nil
	}

	// Compress the core dump.
	defer os.Remove(coreFile)
	if err := compressFileInPlace(coreFile, outPath); err != nil {
		return modules, fmt.Errorf("memory handler: compress core: %w", err)
	}
	return modules, nil
}

func parseVmmapModules(output string) []string {
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		// vmmap lines with paths typically start with "__TEXT" or similar.
		if idx := strings.Index(line, "/"); idx >= 0 {
			path := strings.TrimSpace(line[idx:])
			if _, ok := seen[path]; !ok {
				seen[path] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	return out
}

func writeCompressed(dst string, data []byte) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	if _, err := gz.Write(data); err != nil {
		gz.Close()
		return err
	}
	return gz.Close()
}

func compressFileInPlace(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		return err
	}
	return gz.Close()
}

// encryptFile reads src, encrypts with AES-256-GCM, writes to dst.
func encryptFile(src, dst string, key []byte) error {
	plaintext, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("encrypt file: read: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("encrypt file: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("encrypt file: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("encrypt file: nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(dst, ciphertext, 0o600)
}
