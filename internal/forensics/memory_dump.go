// Package forensics provides digital forensics capabilities for the EDR agent
// including process memory acquisition, disk imaging, timeline reconstruction,
// artifact collection, and chain-of-custody management.
package forensics

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// MemoryRegion describes a single virtual memory region within a process.
type MemoryRegion struct {
	Start      uint64 `json:"start"`
	End        uint64 `json:"end"`
	Size       uint64 `json:"size"`
	Protection string `json:"protection"`
	Pathname   string `json:"pathname,omitempty"`
	Dumped     bool   `json:"dumped"`
}

// MemoryDumpResult contains metadata about a completed memory acquisition.
type MemoryDumpResult struct {
	PID        int            `json:"pid"`
	Timestamp  time.Time      `json:"timestamp"`
	Hostname   string         `json:"hostname"`
	Regions    []MemoryRegion `json:"regions"`
	OutputPath string         `json:"output_path"`
	SHA256     string         `json:"sha256"`
	Encrypted  bool           `json:"encrypted"`
}

// MemoryDumper acquires process memory for forensic analysis.
// Output is a compressed, optionally encrypted archive containing
// the memory dump, region maps, and process information.
type MemoryDumper struct {
	logger        *zap.Logger
	outputDir     string
	encryptionKey []byte // 32-byte AES-256 key; nil disables encryption
}

// NewMemoryDumper creates a dumper that writes forensic images to outputDir.
func NewMemoryDumper(outputDir string, logger *zap.Logger) *MemoryDumper {
	return &MemoryDumper{
		logger:    logger,
		outputDir: outputDir,
	}
}

// SetEncryptionKey sets a 32-byte AES-256 key used to encrypt forensic
// output. Pass nil to disable encryption.
func (md *MemoryDumper) SetEncryptionKey(key []byte) {
	md.encryptionKey = key
}

// DumpProcess acquires the virtual memory of the process identified by pid.
// It produces a compressed (and optionally encrypted) tar archive containing
// the raw memory regions, a region map, and process metadata.
func (md *MemoryDumper) DumpProcess(ctx context.Context, pid int) (*MemoryDumpResult, error) {
	if err := os.MkdirAll(md.outputDir, 0700); err != nil {
		return nil, fmt.Errorf("memory_dump: create output dir: %w", err)
	}

	tmpDir, err := os.MkdirTemp(md.outputDir, fmt.Sprintf("memdump_%d_", pid))
	if err != nil {
		return nil, fmt.Errorf("memory_dump: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	md.logger.Info("starting memory dump", zap.Int("pid", pid))

	regions, err := dumpProcessMemory(ctx, pid, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("memory_dump: pid %d: %w", pid, err)
	}

	// Write region metadata into the dump directory.
	if data, err := json.MarshalIndent(regions, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(tmpDir, "regions.json"), data, 0600)
	}

	hostname, _ := os.Hostname()
	procMeta := map[string]interface{}{
		"pid": pid, "timestamp": time.Now().UTC(), "hostname": hostname,
	}
	if data, err := json.MarshalIndent(procMeta, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(tmpDir, "process_info.json"), data, 0600)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	archivePath := filepath.Join(md.outputDir, fmt.Sprintf("memdump_%d_%s.tar.gz", pid, ts))
	if err := createCompressedArchive(archivePath, tmpDir); err != nil {
		return nil, fmt.Errorf("memory_dump: archive: %w", err)
	}

	finalPath := archivePath
	encrypted := false
	if len(md.encryptionKey) == 32 {
		encPath := archivePath + ".enc"
		if err := encryptFileStreaming(archivePath, encPath, md.encryptionKey); err != nil {
			md.logger.Error("encryption failed, keeping unencrypted", zap.Error(err))
		} else {
			_ = os.Remove(archivePath)
			finalPath = encPath
			encrypted = true
		}
	}

	hash, _ := sha256File(finalPath)

	dumped := 0
	for _, r := range regions {
		if r.Dumped {
			dumped++
		}
	}
	md.logger.Info("memory dump complete",
		zap.Int("pid", pid),
		zap.Int("regions_total", len(regions)),
		zap.Int("regions_dumped", dumped),
		zap.String("output", finalPath),
	)

	return &MemoryDumpResult{
		PID:        pid,
		Timestamp:  time.Now().UTC(),
		Hostname:   hostname,
		Regions:    regions,
		OutputPath: finalPath,
		SHA256:     hash,
		Encrypted:  encrypted,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers shared by the forensics package
// ---------------------------------------------------------------------------

func createCompressedArchive(dst, srcDir string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(srcDir, path)
		header.Name = rel
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
}

// encryptFileStreaming performs AES-256-CTR encryption with HMAC-SHA256
// authentication (encrypt-then-MAC) in a streaming fashion suitable for
// large forensic images.
//
// Output format: [16-byte IV] [ciphertext] [32-byte HMAC]
func encryptFileStreaming(src, dst string, key []byte) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("generate IV: %w", err)
	}
	if _, err := out.Write(iv); err != nil {
		return err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(iv)

	stream := cipher.NewCTR(block, iv)
	mw := io.MultiWriter(out, mac)
	sw := &cipher.StreamWriter{S: stream, W: mw}
	if _, err := io.Copy(sw, in); err != nil {
		return err
	}

	_, err = out.Write(mac.Sum(nil))
	return err
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
