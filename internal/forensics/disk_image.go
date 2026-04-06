package forensics

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ProgressFunc is called during disk imaging to report bytes written against
// an estimated total (-1 when the total is unknown).
type ProgressFunc func(bytesWritten, totalBytes int64)

// DiskImager captures targeted file sets or full volumes for forensic analysis.
type DiskImager struct {
	logger    *zap.Logger
	outputDir string
	progress  ProgressFunc
}

// NewDiskImager creates an imager that writes output to outputDir.
func NewDiskImager(outputDir string, logger *zap.Logger) *DiskImager {
	return &DiskImager{
		logger:    logger,
		outputDir: outputDir,
	}
}

// SetProgress registers a callback invoked as data is written.
func (di *DiskImager) SetProgress(fn ProgressFunc) { di.progress = fn }

// CaptureTargeted creates a compressed tar archive of the given files and
// directories, preserving metadata and computing per-file SHA-256 hashes.
// Returns the path of the output archive.
func (di *DiskImager) CaptureTargeted(ctx context.Context, paths []string) (string, error) {
	if err := os.MkdirAll(di.outputDir, 0700); err != nil {
		return "", fmt.Errorf("disk_image: create output dir: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	archivePath := filepath.Join(di.outputDir, fmt.Sprintf("targeted_%s.tar.gz", ts))

	f, err := os.Create(archivePath)
	if err != nil {
		return "", fmt.Errorf("disk_image: create archive: %w", err)
	}
	defer f.Close()

	var written int64
	pw := &progressWriter{w: f, fn: di.progress, total: -1}
	gw := gzip.NewWriter(pw)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		info, err := os.Stat(p)
		if err != nil {
			di.logger.Warn("disk_image: skip path", zap.String("path", p), zap.Error(err))
			continue
		}
		if info.IsDir() {
			if err := addDirToTar(ctx, tw, p); err != nil {
				di.logger.Warn("disk_image: dir error", zap.String("path", p), zap.Error(err))
			}
		} else {
			if err := addFileToTar(tw, p, info); err != nil {
				di.logger.Warn("disk_image: file error", zap.String("path", p), zap.Error(err))
			}
		}
	}

	_ = written
	di.logger.Info("targeted capture complete", zap.String("output", archivePath))
	return archivePath, nil
}

// CaptureVolume creates a gzip-compressed raw image of the specified block
// device or volume path. Requires administrator/root privileges.
func (di *DiskImager) CaptureVolume(ctx context.Context, volume string) (string, error) {
	if err := os.MkdirAll(di.outputDir, 0700); err != nil {
		return "", fmt.Errorf("disk_image: create output dir: %w", err)
	}

	safe := strings.ReplaceAll(strings.Trim(volume, "/"), "/", "_")
	ts := time.Now().UTC().Format("20060102T150405Z")
	outputPath := filepath.Join(di.outputDir, fmt.Sprintf("volume_%s_%s.raw.gz", safe, ts))

	f, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("disk_image: create output: %w", err)
	}
	defer f.Close()

	pw := &progressWriter{w: f, fn: di.progress, total: -1}
	gw := gzip.NewWriter(pw)
	defer gw.Close()

	di.logger.Info("volume capture starting",
		zap.String("volume", volume), zap.String("output", outputPath))

	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.CommandContext(ctx, "dd", "if="+volume, "bs=4M")
		cmd.Stdout = gw
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("disk_image: dd %s: %w", volume, err)
		}
	default:
		src, err := os.Open(volume)
		if err != nil {
			return "", fmt.Errorf("disk_image: open %s: %w", volume, err)
		}
		defer src.Close()
		if _, err := io.Copy(gw, src); err != nil {
			return "", fmt.Errorf("disk_image: copy %s: %w", volume, err)
		}
	}

	hash, _ := sha256File(outputPath)
	di.logger.Info("volume capture complete",
		zap.String("output", outputPath), zap.String("sha256", hash))
	return outputPath, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type progressWriter struct {
	w       io.Writer
	written int64
	total   int64
	fn      ProgressFunc
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.w.Write(p)
	pw.written += int64(n)
	if pw.fn != nil {
		pw.fn(pw.written, pw.total)
	}
	return n, err
}

func addDirToTar(ctx context.Context, tw *tar.Writer, root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || ctx.Err() != nil {
			return err
		}
		return addFileToTar(tw, path, info)
	})
}

func addFileToTar(tw *tar.Writer, path string, info os.FileInfo) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = path

	// Include a SHA-256 PAX header for forensic integrity.
	if !info.IsDir() && info.Mode().IsRegular() {
		if h, err := sha256File(path); err == nil {
			header.PAXRecords = map[string]string{"EDR.sha256": h}
		}
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(tw, io.TeeReader(f, h))
	return err
}
