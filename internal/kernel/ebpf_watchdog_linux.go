//go:build linux

package kernel

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cilium/ebpf"
)

func (d *EBPFDriver) collectOwnProgramIDs() {
	if d.coll == nil {
		return
	}
	d.ownProgIDs = d.ownProgIDs[:0]
	for _, p := range d.coll.Programs {
		if p == nil {
			continue
		}
		if info, err := p.Info(); err == nil {
			if id, ok := info.ID(); ok {
				d.ownProgIDs = append(d.ownProgIDs, uint32(id))
			}
		}
	}
}

func ebpfProgramExists(progID uint32) bool {
	_, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	return err == nil
}

func (d *EBPFDriver) watchdogLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, id := range d.ownProgIDs {
				if ebpfProgramExists(id) {
					continue
				}
				d.emitTamperEvent(id)
				_ = d.reloadPrograms()
			}
		}
	}
}

func (d *EBPFDriver) emitTamperEvent(progID uint32) {
	env := map[string]interface{}{
		"type": "process",
		"timestamp": time.Now().UTC(),
		"agent_id": d.agentID,
		"event_kind": "tamper",
		"operation": "ebpf_program_missing",
		"program_id": progID,
	}
	b, _ := json.Marshal(env)
	_ = d.buf.Write(b)
}

func (d *EBPFDriver) reloadPrograms() error {
	// Best-effort hot reload: sync policy to maps and keep links alive.
	return d.syncPolicyToMaps()
}
