//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows/registry"
)

// SysmonStatus describes the live state of System Monitor on the host.
//
// Empty Version means the binary is missing or unreadable; an empty Driver
// means the kernel-mode component is not installed; ChannelPresent reflects
// the existence of the Microsoft-Windows-Sysmon/Operational event log.
type SysmonStatus struct {
	Installed       bool   // SysmonDrv service exists
	ServiceState    string // running|stopped|missing
	Driver          string // SysmonDrv
	BinaryPath      string // resolved Sysmon[64].exe path
	Version         string // parsed from `sysmon -? | findstr v`
	ChannelPresent  bool   // Microsoft-Windows-Sysmon/Operational
	ConfigChecksum  string // optional output from `sysmon -c`
	LastError       string
	LastProbedAt    time.Time
}

// SysmonDetector probes the host for Sysmon presence and (optionally)
// installs the bundled binary + minimal config when the operator opted in.
//
// All registry / event-log / subprocess work is done off the hot path, only
// at agent startup or when SnapshotStatus() is called by the doctor command.
type SysmonDetector struct {
	autoInstall bool
	bundleDir   string // pkg/sysmon/ (resolved at runtime)

	last atomic.Pointer[SysmonStatus]
}

// NewSysmonDetector constructs a detector. bundleDir should point at the
// directory containing the bundled Sysmon binary and minimal config; pass an
// empty string when auto-install is disabled.
func NewSysmonDetector(autoInstall bool, bundleDir string) *SysmonDetector {
	return &SysmonDetector{autoInstall: autoInstall, bundleDir: bundleDir}
}

// Probe queries the registry, event log, and (optionally) the Sysmon binary
// to populate a SysmonStatus snapshot. Always returns a non-nil status, even
// when Sysmon is missing or partially configured.
func (d *SysmonDetector) Probe(ctx context.Context) *SysmonStatus {
	st := &SysmonStatus{LastProbedAt: time.Now().UTC()}
	d.probeService(st)
	d.probeChannel(st)
	if st.Installed {
		d.probeBinary(ctx, st)
	}
	d.last.Store(st)
	return st
}

// LastStatus returns the most recent Probe() result, or nil if Probe has
// never been called.
func (d *SysmonDetector) LastStatus() *SysmonStatus { return d.last.Load() }

// ExportMonitoringHealth exposes Sysmon detection status to the doctor.
func (d *SysmonDetector) ExportMonitoringHealth() map[string]any {
	st := d.last.Load()
	src := MonitoringSource{
		Name:   "sysmon",
		OS:     "windows",
		Source: "registry+evt",
		Status: "absent",
	}
	if st != nil {
		switch {
		case st.LastError != "":
			src.Status = "degraded"
			src.LastError = st.LastError
		case st.Installed && st.ChannelPresent:
			src.Status = "healthy"
		case st.Installed || st.ChannelPresent:
			src.Status = "degraded"
		}
		src.Notes = strings.TrimSpace(fmt.Sprintf(
			"installed=%v service=%s version=%s channel=%v",
			st.Installed, st.ServiceState, st.Version, st.ChannelPresent,
		))
	}
	return src.ToMap()
}

// probeService inspects HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv.
func (d *SysmonDetector) probeService(st *SysmonStatus) {
	for _, name := range []string{"SysmonDrv", "Sysmon", "Sysmon64"} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
		if err != nil {
			if !errors.Is(err, registry.ErrNotExist) {
				st.LastError = fmt.Sprintf("registry %s: %v", name, err)
			}
			continue
		}
		defer key.Close()
		st.Installed = true
		st.Driver = name
		if start, _, err := key.GetIntegerValue("Start"); err == nil {
			switch start {
			case 0, 1, 2:
				st.ServiceState = "running"
			default:
				st.ServiceState = "stopped"
			}
		}
		if path, _, err := key.GetStringValue("ImagePath"); err == nil {
			st.BinaryPath = strings.TrimPrefix(strings.TrimSpace(path), `\??\`)
		}
		return
	}
	st.ServiceState = "missing"
}

// probeChannel checks for the Microsoft-Windows-Sysmon/Operational log.
func (d *SysmonDetector) probeChannel(st *SysmonStatus) {
	const path = `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	st.ChannelPresent = true
}

// probeBinary runs `sysmon -? -nologo` once to capture the version line.
func (d *SysmonDetector) probeBinary(ctx context.Context, st *SysmonStatus) {
	bin := st.BinaryPath
	if bin == "" {
		return
	}
	if !filepath.IsAbs(bin) {
		st.LastError = "sysmon image path is not absolute"
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "-?", "-nologo").CombinedOutput()
	if err != nil {
		st.LastError = fmt.Sprintf("sysmon -?: %v", err)
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "System Monitor") || strings.HasPrefix(line, "Sysmon ") {
			st.Version = line
			break
		}
	}
}
