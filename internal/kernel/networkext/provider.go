//go:build darwin

package networkext

type Provider interface {
	Start() error
	Stop()
	Probe() bool
	Health() map[string]any
}

