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

// ebpfProgramExistsForWatchdog is swappable in unit tests.
var ebpfProgramExistsForWatchdog = func(progID uint32) bool {
	_, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	return err == nil
}

// ebpfWatchdogInterval is the watchdog poll interval (overridable in tests).
var ebpfWatchdogInterval = 30 * time.Second

func (d *EBPFDriver) watchdogLoop(ctx context.Context) {
	t := time.NewTicker(ebpfWatchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var missing []uint32
			for _, id := range d.ownProgIDs {
				if ebpfProgramExistsForWatchdog(id) {
					continue
				}
				missing = append(missing, id)
			}
			if len(missing) == 0 {
				continue
			}
			for _, id := range missing {
				d.emitTamperEvent(id)
			}
			_ = d.reattachWithBoundedRetry(3)
		}
	}
}

func (d *EBPFDriver) emitTamperEvent(progID uint32) {
	d.tamperEvents.Add(1)
	d.tamperByProgMu.Lock()
	if d.tamperByProg == nil {
		d.tamperByProg = make(map[uint32]uint64)
	}
	d.tamperByProg[progID]++
	d.tamperByProgMu.Unlock()
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
