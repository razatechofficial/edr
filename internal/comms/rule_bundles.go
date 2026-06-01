package comms

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ApplyRuleBundleTarGz extracts a tar.gz rule bundle under destRoot.
// Paths inside the archive must stay within destRoot.
func ApplyRuleBundleTarGz(name string, data []byte, destRoot string) error {
	if len(data) == 0 {
		return fmt.Errorf("rule_bundle %q: empty payload", name)
	}
	destRoot = filepath.Clean(destRoot)
	if destRoot == "" || destRoot == "." {
		return fmt.Errorf("rule_bundle %q: invalid dest root", name)
	}
	if err := os.MkdirAll(destRoot, 0o750); err != nil {
		return fmt.Errorf("rule_bundle %q: mkdir: %w", name, err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("rule_bundle %q: gzip: %w", name, err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("rule_bundle %q: tar: %w", name, err)
		}
		if hdr == nil {
			continue
		}
		rel := filepath.Clean(hdr.Name)
		if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("rule_bundle %q: invalid member path %q", name, hdr.Name)
		}
		target := filepath.Join(destRoot, rel)
		if !pathWithinRoot(destRoot, target) {
			return fmt.Errorf("rule_bundle %q: path escapes dest root: %q", name, hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return fmt.Errorf("rule_bundle %q: mkdir %q: %w", name, rel, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("rule_bundle %q: mkdir parent %q: %w", name, rel, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("rule_bundle %q: create %q: %w", name, rel, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return fmt.Errorf("rule_bundle %q: write %q: %w", name, rel, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("rule_bundle %q: close %q: %w", name, rel, err)
			}
		default:
			continue
		}
	}
	return nil
}

func pathWithinRoot(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if target == root {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(target, root+sep)
}
