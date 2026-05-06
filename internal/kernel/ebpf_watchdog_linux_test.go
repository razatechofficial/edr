//go:build linux

package kernel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdogLoop_BatchesMissingPrograms_SingleReattach(t *testing.T) {
	t.Parallel()
	oldInt := ebpfWatchdogInterval
	oldExists := ebpfProgramExistsForWatchdog
	var reattachCalls int32
	testEbpfReattachOverride = func(_ *EBPFDriver, _ int) error {
		atomic.AddInt32(&reattachCalls, 1)
		return nil
	}
	defer func() {
		ebpfWatchdogInterval = oldInt
		ebpfProgramExistsForWatchdog = oldExists
		testEbpfReattachOverride = nil
	}()
	ebpfWatchdogInterval = 15 * time.Millisecond
	ebpfProgramExistsForWatchdog = func(uint32) bool { return false }

	d := &EBPFDriver{
		buf:        NewRingBuffer(4096),
		ownProgIDs: []uint32{10, 20, 30},
	}
	d.running.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 38*time.Millisecond)
	defer cancel()
	go d.watchdogLoop(ctx)
	<-ctx.Done()
	rc := atomic.LoadInt32(&reattachCalls)
	if rc < 1 {
		t.Fatalf("expected at least one reattach batch, got %d", rc)
	}
	// One tick should batch all missing IDs; allow a second tick before timeout.
	if rc > 4 {
		t.Fatalf("unexpected extra reattach calls (want batched per tick), got %d", rc)
	}
}

func TestReattachWithBoundedRetry_RetriesUntilBudget(t *testing.T) {
	t.Parallel()
	var calls int32
	testEbpfReattachOverride = func(_ *EBPFDriver, _ int) error {
		atomic.AddInt32(&calls, 1)
		return errors.New("forced failure")
	}
	defer func() { testEbpfReattachOverride = nil }()

	d := &EBPFDriver{}
	d.running.Store(true)
	d.rootCtx = context.Background()
	d.eventCtx, d.eventCancel = context.WithCancel(context.Background())

	err := d.reattachWithBoundedRetry(3)
	if err == nil {
		t.Fatal("expected error")
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("want 3 attempts, got %d", calls)
	}
	if d.programReattachFailures.Load() != 3 {
		t.Fatalf("failure counter: %d", d.programReattachFailures.Load())
	}
}
