//go:build darwin && (!cgo || nosec)

package collector

import (
	"context"
	"os/exec"
	"strings"
)

// RunSCDynamicStoreRouteProbe uses scutil as a coarse network-configuration heartbeat (SCDynamicStore full bridge needs cgo).
func RunSCDynamicStoreRouteProbe(ctx context.Context, emit func(map[string]any)) {
	if emit == nil {
		return
	}
	c := exec.CommandContext(ctx, "scutil", "--nc", "list")
	out, err := c.CombinedOutput()
	if err != nil {
		emit(map[string]any{"scdynamicstore_probe": "error", "detail": err.Error()})
		return
	}
	emit(map[string]any{"scdynamicstore_probe": "scutil_nc_list", "lines": len(strings.Split(string(out), "\n"))})
}
