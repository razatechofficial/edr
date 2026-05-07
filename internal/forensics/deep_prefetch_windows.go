//go:build windows

package forensics

import (
	"os"
	"path/filepath"
	"strings"
)

func collectPrefetchWindows(cfg *ForensicsDeepConfig, bundle *DeepArtifactsBundle) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	prefetchDir := filepath.Join(root, "Prefetch")
	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		bundle.PrefetchError = err.Error()
		return
	}
	dstDir := filepath.Join(cfg.WorkDir, "prefetch")
	n := 0
	for _, e := range entries {
		if n >= cfg.MaxPrefetchFiles {
			break
		}
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.EqualFold(filepath.Ext(name), ".pf") {
			continue
		}
		src := filepath.Join(prefetchDir, name)
		ent, err := copyFileBounded(src, dstDir, name, maxPrefetchFileBytes)
		if err != nil && ent.Note == "" {
			ent.Note = err.Error()
		}
		bundle.Prefetch = append(bundle.Prefetch, ent)
		n++
	}
}
