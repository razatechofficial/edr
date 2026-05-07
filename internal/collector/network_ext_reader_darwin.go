//go:build darwin

package collector

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/kernel/networkext"
)

type DarwinNEReader struct {
	path      string
	endpoint  string
	hostname  string
	connected atomic.Bool
	frames    atomic.Uint64
}

func NewDarwinNEReader(endpointID, hostname, path string) *DarwinNEReader {
	if path == "" {
		path = "/var/run/edr/ne.sock"
	}
	return &DarwinNEReader{path: path, endpoint: endpointID, hostname: hostname}
}

func (r *DarwinNEReader) Run(ctx context.Context, sink *StreamingSink) error {
	if _, err := os.Stat(r.path); err != nil {
		r.connected.Store(false)
		return err
	}
	s := &networkext.SocketReader{Path: r.path}
	r.connected.Store(true)
	return s.ReadFrames(ctx, func(m map[string]any) {
		r.frames.Add(1)
		ne := &schema.NetworkEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventNetwork,
				EndpointID:    r.endpoint,
				Timestamp:     time.Now().UTC(),
				Hostname:      r.hostname,
				OS:            "darwin",
			},
		}
		if v, ok := m["sni"].(string); ok {
			ne.SNI = v
		}
		if sink != nil {
			_ = sink.Send(ctx, Telemetry{Network: ne})
		}
	})
}

func (r *DarwinNEReader) Health() map[string]any {
	return map[string]any{
		"network_extension_ipc_connected": r.connected.Load(),
		"network_extension_ipc_frames":    r.frames.Load(),
		"network_extension_ipc_path":      r.path,
	}
}

