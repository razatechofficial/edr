//go:build !darwin

package collector

import "context"

// RunSCDynamicStoreRouteProbe is a no-op on non-Darwin builds.
func RunSCDynamicStoreRouteProbe(ctx context.Context, emit func(map[string]any)) {
	_ = ctx
	_ = emit
}
