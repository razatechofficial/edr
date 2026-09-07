package config

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed stock_windows.yml
var stockWindows []byte

// EnsureFile writes a stock agent config when path is missing or empty.
// In-place MSI upgrades used to purge config.yml (old product REMOVE=ALL)
// and NeverOverwrite then left ProgramData without a file.
func EnsureFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("config path required")
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	body, err := stockConfigBytes(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

func stockConfigBytes(dest string) ([]byte, error) {
	dir := filepath.Dir(dest)
	for _, name := range []string{"config.default.yml", "config.enterprise.yml", "config.hardened.yml"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && len(bytes.TrimSpace(b)) > 0 {
			return b, nil
		}
	}
	if runtime.GOOS == "windows" {
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		b, err := os.ReadFile(filepath.Join(pf, "EDR Agent", "config.default.yml"))
		if err == nil && len(bytes.TrimSpace(b)) > 0 {
			return b, nil
		}
		if len(bytes.TrimSpace(stockWindows)) > 0 {
			return append([]byte(nil), stockWindows...), nil
		}
	}
	return nil, fmt.Errorf("no stock config template for %s", dest)
}
