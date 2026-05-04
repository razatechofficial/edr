//go:build !linux && !windows && !darwin

package collector

import (
	"context"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/config"
)

func TestNewKernelCollectorOtherIsNonNilWithCapabilityProbe(t *testing.T) {
	kc := NewKernelCollector("ep", config.Config{}, nil)
	if kc == nil {
		t.Fatal("NewKernelCollector returned nil")
	}
	m := kc.ExportMonitoringHealth()
	if m == nil {
		t.Fatal("nil health")
	}
	if m["name"] != "kernel" {
		t.Fatalf("name=%v", m["name"])
	}
	if m["source"] != "rare_userland_kernel_stream" {
		t.Fatalf("source=%v", m["source"])
	}
	if m["status"] != "healthy" {
		t.Fatalf("status=%v", m["status"])
	}
	if m["reason"] != "rare_userland_equivalent" {
		t.Fatalf("reason=%v", m["reason"])
	}
	coverage, ok := m["coverage"].([]string)
	if !ok {
		t.Fatalf("coverage type=%T value=%v", m["coverage"], m["coverage"])
	}
	if len(coverage) != 3 || coverage[0] != "process" || coverage[1] != "network" || coverage[2] != "auth" {
		t.Fatalf("coverage=%v", coverage)
	}
}

func TestRareKernelCollector_EmitsProcessNetworkAuth(t *testing.T) {
	kc := NewKernelCollector("ep", config.Config{}, nil)
	if kc == nil {
		t.Fatal("nil collector")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := kc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(2200 * time.Millisecond)
	kc.Stop()

	events, err := kc.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("events=%d", len(events))
	}
	var hasProcess, hasNetwork, hasAuth bool
	for _, e := range events {
		if e.Process != nil {
			hasProcess = true
		}
		if e.Network != nil {
			hasNetwork = true
		}
		if e.Auth != nil {
			hasAuth = true
		}
	}
	if !hasProcess || !hasNetwork || !hasAuth {
		t.Fatalf("hasProcess=%v hasNetwork=%v hasAuth=%v", hasProcess, hasNetwork, hasAuth)
	}
}
