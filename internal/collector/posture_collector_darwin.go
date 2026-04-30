//go:build darwin

package collector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/razatechofficial/edr/internal/config"
)

type PostureCollector struct {
	cfg           config.Config
	mu            sync.Mutex
	lastNote      string
	worldWritable atomic.Uint64
	dirsScanned   atomic.Uint64
	tick          atomic.Uint64
}

func NewPostureCollector(cfg config.Config) Collector {
	if !cfg.Monitoring.PostureEnabled {
		return nil
	}
	return &PostureCollector{cfg: cfg}
}

func (p *PostureCollector) Name() string { return "posture" }

func (p *PostureCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	p.tick.Add(1)
	var ww uint64
	var scanned uint64
	for _, root := range []string{"/tmp", "/private/tmp"} {
		if ctx.Err() != nil {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return filepath.SkipDir
			}
			if d.IsDir() {
				if path != root && (strings.HasPrefix(filepath.Base(path), ".") || len(path) > len(root)+200) {
					return filepath.SkipDir
				}
				return nil
			}
			scanned++
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if m := info.Mode(); m&0o002 != 0 && m.IsRegular() {
				ww++
			}
			if scanned > 5000 {
				return filepath.SkipAll
			}
			return nil
		})
	}
	p.worldWritable.Store(ww)
	p.dirsScanned.Store(scanned)
	p.mu.Lock()
	p.lastNote = ""
	p.mu.Unlock()
	return nil, nil
}

func (p *PostureCollector) ExportMonitoringHealth() map[string]any {
	st := "healthy"
	src := MonitoringSource{
		Name:   "posture",
		OS:     runtime.GOOS,
		Source: "probe",
		Status: st,
		EPSOut: p.tick.Load(),
	}.ToMap()
	src["world_writable_files_sampled"] = float64(p.worldWritable.Load())
	src["files_scanned_cap_5k"] = float64(p.dirsScanned.Load())
	return src
}
