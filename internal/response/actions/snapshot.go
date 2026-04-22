package actions

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Environment is the host hypervisor / cloud class.
type Environment int

const (
	EnvBareMetal Environment = iota
	EnvVMware
	EnvAWS
	EnvAzure
	EnvGCP
	EnvHyperV
)

// SnapshotAction is a pluggable volume snapshot; cloud calls are stubs without credentials.
type SnapshotAction struct {
	Reason string
	Logger *zap.Logger
}

// Execute takes a best-effort snapshot in supported environments.
func (a *SnapshotAction) Execute(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("snapshot panic: %v", r)
		}
	}()
	_ = a
	switch detectEnvironment() {
	case EnvAWS:
		return a.createAWSSnapshot(ctx)
	case EnvAzure:
		return a.createAzureSnapshot(ctx)
	case EnvGCP:
		return a.createGCPSnapshot(ctx)
	case EnvVMware, EnvHyperV:
		// No generic API without host integration
		return nil
	case EnvBareMetal:
		if a.Logger != nil {
			a.Logger.Warn("take_snapshot: bare metal or unknown environment has no built-in volume snapshot; enable cloud/VMware APIs to snapshot disks",
				zap.String("reason", a.Reason),
			)
		}
		return nil
	}
	return nil
}

// detectEnvironment probes DMI and link-local metadata.
func detectEnvironment() Environment {
	if s, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		v := strings.ToLower(string(s))
		switch {
		case strings.Contains(v, "vmware"):
			return EnvVMware
		case strings.Contains(v, "amazon"):
			return EnvAWS
		case strings.Contains(v, "microsoft") && fileExists("/sys/hypervisor/type"):
			return EnvHyperV
		}
	}
	client := &http.Client{Timeout: 100 * time.Millisecond}
	if _, err := client.Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		return EnvAWS
	}
	if _, err := client.Get("http://169.254.169.254/metadata/instance?api-version=2017-08-01"); err == nil {
		return EnvAzure
	}
	if _, err := client.Get("http://metadata.google.internal/"); err == nil {
		return EnvGCP
	}
	return EnvBareMetal
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (a *SnapshotAction) createAWSSnapshot(_ context.Context) error {
	// No AWS SDK: stub
	return nil
}
func (a *SnapshotAction) createAzureSnapshot(_ context.Context) error { return nil }
func (a *SnapshotAction) createGCPSnapshot(_ context.Context) error   { return nil }

// LocalIP returns a non-loopback IP for allow lists.
func LocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
			if v4 := ipn.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return "127.0.0.1"
}
