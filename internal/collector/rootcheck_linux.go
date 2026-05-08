//go:build linux

package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/unix"
)

type RootcheckCollector struct {
	cfg        config.Config
	endpointID string
	hostname   string
	lastRun    atomic.Int64
	findings   atomic.Uint64
	hiddenPid  atomic.Uint64
	hiddenPort atomic.Uint64
	mu         sync.Mutex
	suidBase   map[string]struct{}
}

func NewRootcheckCollector(endpointID string, cfg config.Config) *RootcheckCollector {
	h, _ := os.Hostname()
	return &RootcheckCollector{
		cfg:        cfg,
		endpointID: endpointID,
		hostname:   h,
		suidBase:   map[string]struct{}{},
	}
}

func (r *RootcheckCollector) Name() string { return "rootcheck" }

func (r *RootcheckCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	iv := r.cfg.Monitoring.LinuxRootcheckIntervalSec
	if iv <= 0 {
		iv = 300
	}
	last := r.lastRun.Load()
	if last > 0 && time.Since(time.Unix(last, 0)) < time.Duration(iv)*time.Second {
		return nil, nil
	}
	r.lastRun.Store(time.Now().Unix())
	out := make([]Telemetry, 0, 16)
	out = append(out, r.checkHiddenPID(ctx)...)
	out = append(out, r.checkSUIDDrift(ctx)...)
	if r.cfg.Monitoring.LinuxRootcheckPortScan && r.cfg.Monitoring.LinuxRootcheckEnabled {
		out = append(out, r.checkHiddenPorts(ctx)...)
	}
	r.findings.Add(uint64(len(out)))
	return out, nil
}

func (r *RootcheckCollector) checkHiddenPID(ctx context.Context) []Telemetry {
	procSet := map[int]struct{}{}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(e.Name())
			if err == nil && pid > 0 {
				procSet[pid] = struct{}{}
			}
		}
	}
	out := []Telemetry{}
	for pid := 1; pid <= 4096; pid++ {
		if ctx.Err() != nil {
			break
		}
		if _, ok := procSet[pid]; ok {
			continue
		}
		n := 0
		if err := unix.Kill(pid, 0); err == nil {
			n++
		}
		if _, err := unix.Getsid(pid); err == nil {
			n++
		}
		if _, err := unix.Getpgid(pid); err == nil {
			n++
		}
		if n < 2 {
			continue
		}
		r.hiddenPid.Add(1)
		out = append(out, Telemetry{Process: &schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventProcess,
				EndpointID:    r.endpointID,
				Timestamp:     time.Now().UTC(),
				Hostname:      r.hostname,
				OS:            runtime.GOOS,
			},
			PID:         pid,
			ProcessName: "posture.hidden_pid",
			CommandLine: "rootcheck_hidden_pid syscall_hits=" + strconv.Itoa(n),
			Tags:        []string{"rootkit-iocs", "posture"},
			Severity:    "high",
		}})
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func (r *RootcheckCollector) checkSUIDDrift(ctx context.Context) []Telemetry {
	prefixes := r.cfg.Monitoring.LinuxRootcheckSUIDPrefixes
	if len(prefixes) == 0 {
		prefixes = []string{"/usr", "/bin", "/sbin", "/opt"}
	}
	nowSet := map[string]struct{}{}
	for _, root := range prefixes {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return filepath.SkipDir
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			m := info.Mode()
			if m&os.ModeSetuid != 0 || m&os.ModeSetgid != 0 {
				nowSet[path] = struct{}{}
			}
			return nil
		})
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Telemetry{}
	for p := range nowSet {
		if _, ok := r.suidBase[p]; !ok {
			out = append(out, r.suidEvent("posture.suid_added", p))
		}
	}
	for p := range r.suidBase {
		if _, ok := nowSet[p]; !ok && strings.TrimSpace(p) != "" {
			out = append(out, r.suidEvent("posture.suid_removed", p))
		}
	}
	r.suidBase = nowSet
	return out
}

func (r *RootcheckCollector) suidEvent(name, path string) Telemetry {
	return Telemetry{Process: &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    r.endpointID,
			Timestamp:     time.Now().UTC(),
			Hostname:      r.hostname,
			OS:            runtime.GOOS,
		},
		ProcessName: name,
		ProcessPath: path,
		CommandLine: "rootcheck_suid_drift",
	}}
}

func (r *RootcheckCollector) ExportMonitoringHealth() map[string]any {
	return map[string]any{
		"name":                    "rootcheck",
		"os":                      "linux",
		"source":                  "probe",
		"status":                  "healthy",
		"rootcheck_last_run_unix": r.lastRun.Load(),
		"rootcheck_findings_total": r.findings.Load(),
		"rootcheck_hidden_pids_total":   r.hiddenPid.Load(),
		"rootcheck_hidden_ports_total":  r.hiddenPort.Load(),
	}
}

func (r *RootcheckCollector) checkHiddenPorts(ctx context.Context) []Telemetry {
	tcpPorts, err := procNetLocalPortsTCP()
	if err != nil || ctx.Err() != nil {
		return nil
	}
	udpPorts, err := procNetLocalPortsUDP()
	if err != nil {
		udpPorts = map[int]struct{}{}
	}
	out := []Telemetry{}
	ports := r.cfg.Monitoring.LinuxRootcheckPortList
	if len(ports) == 0 {
		return nil
	}
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		if p <= 0 || p > 65535 {
			continue
		}
		proto := ""
		busy := ipv4ListenPortBusy(unix.IPPROTO_TCP, p)
		visibleSet := tcpPorts
		if !busy {
			busy = ipv4ListenPortBusy(unix.IPPROTO_UDP, p)
			visibleSet = udpPorts
			proto = "udp"
		} else {
			proto = "tcp"
		}
		if !busy {
			continue
		}
		if visibleSet != nil {
			if _, ok := visibleSet[p]; ok {
				continue // visible via /proc/net
			}
		}
		r.hiddenPort.Add(1)
		out = append(out, Telemetry{Process: &schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventProcess,
				EndpointID:    r.endpointID,
				Timestamp:     time.Now().UTC(),
				Hostname:      r.hostname,
				OS:            runtime.GOOS,
			},
			PID:         0,
			ProcessName: "posture.hidden_port",
			CommandLine: "rootcheck_hidden_port proto=" + proto + " port=" + strconv.Itoa(p),
			Tags:        []string{"rootkit-iocs", "posture"},
			Severity:    "high",
		}})
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func ipv4ListenPortBusy(proto int, port int) bool {
	var sockType int
	switch proto {
	case unix.IPPROTO_TCP:
		sockType = unix.SOCK_STREAM | unix.SOCK_CLOEXEC
	case unix.IPPROTO_UDP:
		sockType = unix.SOCK_DGRAM | unix.SOCK_CLOEXEC
	default:
		return false
	}
	fd, err := unix.Socket(unix.AF_INET, sockType, proto)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	addr := unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte{0, 0, 0, 0},
	}
	if err := unix.Bind(fd, &addr); err != nil {
		return errors.Is(err, unix.EADDRINUSE)
	}
	return false
}

