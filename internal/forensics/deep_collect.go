package forensics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

const (
	defaultPrefetchMaxFiles     = 256
	defaultSelectedPageMemBytes = 32 << 20 // 32 MiB
	maxPrefetchFileBytes        = 4 << 20 // 4 MiB per .pf
)

// collectDeepArtifacts populates bundle fields based on GOOS and cfg flags.
func (ac *ArtifactCollector) collectDeepArtifacts(ctx context.Context, sa *SystemArtifacts, cfg ForensicsDeepConfig) {
	_ = ctx
	if sa == nil {
		return
	}
	if !cfg.WindowsPrefetchEnabled && !cfg.WindowsAmcacheEnabled && !cfg.SelectedPageMemoryEnabled && !cfg.MacosTCCEnabled {
		return
	}
	if cfg.WorkDir == "" {
		d, err := os.MkdirTemp("", "edr-deep-*")
		if err != nil {
			return
		}
		cfg.WorkDir = d
	}
	if cfg.MaxPrefetchFiles <= 0 {
		cfg.MaxPrefetchFiles = defaultPrefetchMaxFiles
	}
	if cfg.SelectedPageMemoryMaxBytes <= 0 {
		cfg.SelectedPageMemoryMaxBytes = defaultSelectedPageMemBytes
	}
	bundle := &DeepArtifactsBundle{}
	if runtime.GOOS == "windows" {
		if cfg.WindowsPrefetchEnabled {
			collectPrefetchWindows(&cfg, bundle)
		}
		if cfg.WindowsAmcacheEnabled {
			collectAmcacheWindows(&cfg, bundle)
		}
		if cfg.SelectedPageMemoryEnabled {
			collectSelectedPageMemoryWindows(&cfg, bundle)
		}
	}
	if runtime.GOOS == "darwin" && cfg.MacosTCCEnabled {
		collectTCCDarwin(&cfg, bundle)
	}
	if hasDeepContent(bundle) {
		sa.Deep = bundle
	}
}

func hasDeepContent(b *DeepArtifactsBundle) bool {
	if b == nil {
		return false
	}
	return len(b.Prefetch) > 0 || b.Amcache != nil || len(b.SelectedPageMemory) > 0 ||
		len(b.TCC) > 0 || b.PrefetchError != "" || b.AmcacheError != "" ||
		b.PageMemoryError != "" || b.TCCError != "" || b.TCCDegraded != ""
}

// CollectDeepToWorkdir copies deep artifacts into workDir for DFIR tarballs.
func CollectDeepToWorkdir(workDir string, cfg ForensicsDeepConfig) []DeepCollectedFile {
	cfg.WorkDir = filepath.Join(workDir, "deep_artifacts")
	var out []DeepCollectedFile
	if cfg.MaxPrefetchFiles <= 0 {
		cfg.MaxPrefetchFiles = defaultPrefetchMaxFiles
	}
	if cfg.SelectedPageMemoryMaxBytes <= 0 {
		cfg.SelectedPageMemoryMaxBytes = defaultSelectedPageMemBytes
	}
	bundle := &DeepArtifactsBundle{}
	if runtime.GOOS == "windows" {
		if cfg.WindowsPrefetchEnabled {
			collectPrefetchWindows(&cfg, bundle)
		}
		if cfg.WindowsAmcacheEnabled {
			collectAmcacheWindows(&cfg, bundle)
		}
		if cfg.SelectedPageMemoryEnabled {
			collectSelectedPageMemoryWindows(&cfg, bundle)
		}
	}
	if runtime.GOOS == "darwin" && cfg.MacosTCCEnabled {
		collectTCCDarwin(&cfg, bundle)
	}

	if cfg.WindowsPrefetchEnabled && runtime.GOOS == "windows" {
		for i := range bundle.Prefetch {
			e := &bundle.Prefetch[i]
			out = append(out, deepEntryToCollected("windows_prefetch", e))
		}
		if bundle.PrefetchError != "" {
			out = append(out, DeepCollectedFile{Type: "windows_prefetch", Err: bundle.PrefetchError})
		}
	}
	if cfg.WindowsAmcacheEnabled && runtime.GOOS == "windows" {
		if bundle.Amcache != nil {
			out = append(out, deepEntryToCollected("windows_amcache", bundle.Amcache))
		}
		if bundle.AmcacheError != "" {
			out = append(out, DeepCollectedFile{Type: "windows_amcache", Err: bundle.AmcacheError})
		}
	}
	if cfg.SelectedPageMemoryEnabled && runtime.GOOS == "windows" {
		if len(bundle.SelectedPageMemory) > 0 {
			_ = ensureDir(cfg.WorkDir)
			p := filepath.Join(cfg.WorkDir, "page_memory_samples.json")
			raw, _ := json.MarshalIndent(bundle.SelectedPageMemory, "", "  ")
			if err := os.WriteFile(p, raw, 0o640); err == nil {
				h := sha256OfBytes(raw)
				out = append(out, DeepCollectedFile{
					Type:    "windows_page_memory",
					DstPath: p,
					Size:    int64(len(raw)),
					SHA256:  h,
				})
			} else {
				out = append(out, DeepCollectedFile{Type: "windows_page_memory", Err: err.Error()})
			}
		}
		if bundle.PageMemoryError != "" {
			out = append(out, DeepCollectedFile{Type: "windows_page_memory", Err: bundle.PageMemoryError})
		}
	}
	if cfg.MacosTCCEnabled && runtime.GOOS == "darwin" {
		for i := range bundle.TCC {
			out = append(out, deepEntryToCollected("macos_tcc", &bundle.TCC[i]))
		}
		if bundle.TCCError != "" {
			out = append(out, DeepCollectedFile{Type: "macos_tcc", Err: bundle.TCCError})
		}
		if bundle.TCCDegraded != "" {
			out = append(out, DeepCollectedFile{Type: "macos_tcc_note", Err: bundle.TCCDegraded})
		}
	}
	return out
}

func deepEntryToCollected(kind string, e *CopiedFileEntry) DeepCollectedFile {
	if e == nil {
		return DeepCollectedFile{Type: kind}
	}
	rec := DeepCollectedFile{
		Type:    kind,
		SrcPath: e.Source,
		DstPath: e.Dest,
		Size:    e.Size,
		SHA256:  e.SHA256,
	}
	if !e.Copied {
		rec.Err = e.Note
		if rec.Err == "" {
			rec.Err = "not copied"
		}
	}
	return rec
}

func sha256OfBytes(b []byte) string {
	// local import would cycle - use crypto/sha256 in deep_collect_hash.go or inline
	return deepSHA256Hex(b)
}
