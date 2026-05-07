//go:build linux

package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
			if err := d.reattachMissingLinks(missing); err != nil {
				_ = d.reattachWithBoundedRetry(3)
			}
		}
	}
}

func (d *EBPFDriver) reattachMissingLinks(missing []uint32) error {
	if d == nil || len(missing) == 0 || d.coll == nil {
		return nil
	}
	var hadErr bool
	for _, id := range missing {
		spec, ok := d.specByProg[id]
		if !ok {
			hadErr = true
			continue
		}
		prog := d.coll.Programs[spec.progName]
		if prog == nil {
			hadErr = true
			continue
		}
		if old, ok := d.linkByProg[id]; ok && old != nil {
			_ = old.Close()
		}
		nl, err := link.Tracepoint(spec.group, spec.tp, prog, nil)
		if err != nil {
			hadErr = true
			continue
		}
		d.linkByProg[id] = nl
		d.links = append(d.links, nl)
		d.tryPinTraceLink(spec.progName, nl)
	}
	if hadErr {
		return errLinkReattachPartial
	}
	return nil
}

var errLinkReattachPartial = errors.New("partial link reattach failure")

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
