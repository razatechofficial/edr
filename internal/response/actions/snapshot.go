package actions

import (
	"context"
	"errors"
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
		return fmt.Errorf("%w: no snapshot API for a %v guest without host integration", errSnapshotUnavailable, detectEnvironment())
	case EnvBareMetal:
		if a.Logger != nil {
			a.Logger.Warn("take_snapshot: bare metal or unknown environment has no built-in volume snapshot; enable cloud/VMware APIs to snapshot disks",
				zap.String("reason", a.Reason),
			)
		}
		return errSnapshotUnavailable
	}
	return errSnapshotUnavailable
}

// errSnapshotUnavailable is returned where no snapshot can actually be taken.
//
// These paths used to return nil, which reports success for a snapshot that was
// never created. A responder reading the result would believe a disk image
// existed and could be returned to — the same class of failure as collecting
// forensic evidence and discarding it, and more damaging here, because the
// belief persists until someone needs the snapshot and finds nothing.
var errSnapshotUnavailable = errors.New("take_snapshot: no snapshot mechanism available in this environment")

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

// The cloud providers are not implemented. Each needs its vendor SDK, an
// instance role carrying the snapshot permission, and the volume and instance
// context to act on — none of which the agent has today.
//
// They return an error rather than nil so that an unimplemented snapshot is
// reported as not taken. Returning nil made every cloud snapshot look like it
// had succeeded.
func (a *SnapshotAction) createAWSSnapshot(_ context.Context) error {
	return fmt.Errorf("%w: AWS EBS snapshots need the AWS SDK and ec2:CreateSnapshot", errSnapshotUnavailable)
}

func (a *SnapshotAction) createAzureSnapshot(_ context.Context) error {
	return fmt.Errorf("%w: Azure disk snapshots are not implemented", errSnapshotUnavailable)
}

func (a *SnapshotAction) createGCPSnapshot(_ context.Context) error {
	return fmt.Errorf("%w: GCP disk snapshots are not implemented", errSnapshotUnavailable)
}

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
