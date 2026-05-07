//go:build windows

package collector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows"
)

const maxPathW = 260

type winFindStreamData struct {
	StreamSize int64
	Name       [maxPathW + 36]uint16
}

// ADSEnumeratorSource scans a few high-value roots for non-default NTFS streams.
type ADSEnumeratorSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64
	lastErr     atomic.Value
}

func NewADSEnumeratorSource(endpointID, hostname string, cfg config.Config) *ADSEnumeratorSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &ADSEnumeratorSource{endpointID: endpointID, hostname: hostname, cfg: cfg}
}

func (s *ADSEnumeratorSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "ads_enumerator",
		OS:            runtime.GOOS,
		Source:        "win32",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.WindowsADSEnumerator
	if v, _ := s.lastErr.Load().(string); v != "" {
		src["last_error"] = v
	}
	src["ads_enum_last_unix"] = s.lastUnix.Load()
	return src
}

func (s *ADSEnumeratorSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.WindowsADSEnumerator {
		return nil
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	s.scan(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.scan(ctx, sink)
		}
	}
}

func (s *ADSEnumeratorSource) scan(ctx context.Context, sink *StreamingSink) {
	s.lastErr.Store("")
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())

	roots := []string{
		os.Getenv("ProgramData"),
		os.Getenv("Public"),
	}
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		_ = filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(path, string(os.PathSeparator)) > 6 {
					return filepath.SkipDir
				}
				return nil
			}
			if !s.pathAllowed(path) {
				return nil
			}
			streams, err := listAlternateStreams(path)
			if err != nil || len(streams) == 0 {
				return nil
			}
			for _, st := range streams {
				if strings.EqualFold(st, "::$DATA") {
					continue
				}
				s.eventsTotal.Add(1)
				fe := schema.FileEvent{
					BaseEvent: schema.BaseEvent{
						SchemaVersion: schema.SchemaVersionV1,
						EventType:     schema.EventFile,
						EndpointID:    s.endpointID,
						Timestamp:     now,
						Hostname:      s.hostname,
						OS:            runtime.GOOS,
					},
					Path:      path + st,
					Operation: "posture.ntfs_ads_found",
					Tags:      []string{"posture", "ntfs-ads"},
				}
				if sink != nil {
					_ = sink.Send(ctx, Telemetry{File: &fe})
				}
			}
			return nil
		})
	}
}

func (s *ADSEnumeratorSource) pathAllowed(path string) bool {
	globs := s.cfg.Monitoring.WindowsADSPathGlobs
	if len(globs) == 0 {
		return true
	}
	lp := strings.ToLower(path)
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if ok, _ := filepath.Match(strings.ToLower(g), lp); ok {
			return true
		}
	}
	return false
}

func listAlternateStreams(path string) ([]string, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ff := kernel32.NewProc("FindFirstStreamW")
	fn := kernel32.NewProc("FindNextStreamW")
	fc := kernel32.NewProc("FindClose")
	kernel32.Load()

	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var data winFindStreamData
	h, _, e := ff.Call(uintptr(unsafe.Pointer(p16)), 0, uintptr(unsafe.Pointer(&data)), 0)
	if h == 0 || h == ^uintptr(0) {
		if errno, ok := e.(windows.Errno); ok && errno == windows.ERROR_HANDLE_EOF {
			return nil, nil
		}
		return nil, e
	}
	defer fc.Call(h)

	var out []string
	appendName := func() {
		n := windows.UTF16ToString(data.Name[:])
		if n != "" {
			out = append(out, n)
		}
	}
	appendName()
	for {
		rc, _, _ := fn.Call(h, uintptr(unsafe.Pointer(&data)))
		if rc == 0 {
			break
		}
		appendName()
	}
	return out, nil
}
