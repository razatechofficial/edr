//go:build !linux && !darwin && !windows

package collector

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RareAuthCollector is a dedicated structured auth collector for rare GOOS.
type RareAuthCollector struct {
	endpointID string
	hostname   string
	logPath    string
	lastOffset int64
	mu         sync.Mutex
	events     []Telemetry
	scans      atomic.Uint64
	emitted    atomic.Uint64
}

func NewRareAuthCollector(endpointID, logPath string) *RareAuthCollector {
	host, _ := os.Hostname()
	return &RareAuthCollector{endpointID: endpointID, hostname: host, logPath: logPath}
}

func (r *RareAuthCollector) Name() string { return "auth" }

func (r *RareAuthCollector) Collect(_ context.Context) ([]Telemetry, error) {
	r.scans.Add(1)
	if r.logPath == "" {
		return nil, nil
	}
	f, err := os.Open(r.logPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	if _, err := f.Seek(r.lastOffset, 0); err != nil {
		return nil, nil
	}
	sc := bufio.NewScanner(f)
	now := time.Now().UTC()
	var out []Telemetry
	for sc.Scan() {
		line := sc.Text()
		if ae, ok := parseAuthLine(line, r.endpointID, r.hostname, now); ok {
			out = append(out, Telemetry{Auth: &ae})
		}
	}
	pos, _ := f.Seek(0, 1)
	r.lastOffset = pos
	r.emitted.Add(uint64(len(out)))
	return out, nil
}

func (r *RareAuthCollector) ExportMonitoringHealth() map[string]any {
	return MonitoringSource{
		Name:   "auth",
		OS:     runtime.GOOS,
		Source: "rare_structured_auth",
		Status: "healthy",
		EPSIn:  r.scans.Load(),
		EPSOut: r.emitted.Load(),
		Notes:  strings.TrimSpace(r.logPath),
	}.ToMap()
}

