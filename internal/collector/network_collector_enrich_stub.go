//go:build !linux

package collector

import "context"

func applyLinuxProcNetPIDEnrichIfConfigured(_ context.Context, _ *NetworkCollector, _ []connEntry) {}
