//go:build !linux

package collector

import (
	"context"
	"log/slog"
)

// WatchPasswd is a no-op outside Linux (no /etc/passwd semantics).
func (*UsernameCache) WatchPasswd(_ context.Context, _ *slog.Logger) {}
