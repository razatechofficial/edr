package collector

import (
	"context"
)

// NetworkStubCollector is a placeholder for future kernel/socket-level network telemetry.
type NetworkStubCollector struct{ endpointID string }

func NewNetworkStubCollector(endpointID string) *NetworkStubCollector {
	return &NetworkStubCollector{endpointID: endpointID}
}

func (n *NetworkStubCollector) Name() string { return "network" }

func (n *NetworkStubCollector) Collect(context.Context) ([]Telemetry, error) {
	return nil, nil
}

// AuthStubCollector is a placeholder for future auth / session telemetry.
type AuthStubCollector struct{ endpointID string }

func NewAuthStubCollector(endpointID string) *AuthStubCollector {
	return &AuthStubCollector{endpointID: endpointID}
}

func (a *AuthStubCollector) Name() string { return "auth" }

func (a *AuthStubCollector) Collect(context.Context) ([]Telemetry, error) {
	return nil, nil
}

// FileStubCollector is a placeholder for future file / FIM telemetry.
type FileStubCollector struct{ endpointID string }

func NewFileStubCollector(endpointID string) *FileStubCollector {
	return &FileStubCollector{endpointID: endpointID}
}

func (f *FileStubCollector) Name() string { return "file" }

func (f *FileStubCollector) Collect(context.Context) ([]Telemetry, error) {
	return nil, nil
}

// DefaultCollectors returns process plus stub collectors for network, auth, and file domains.
func DefaultCollectors(endpointID string) ([]Collector, error) {
	pc, err := NewProcessCollector(endpointID)
	if err != nil {
		return nil, err
	}
	return []Collector{
		pc,
		NewNetworkStubCollector(endpointID),
		NewAuthStubCollector(endpointID),
		NewFileStubCollector(endpointID),
	}, nil
}
