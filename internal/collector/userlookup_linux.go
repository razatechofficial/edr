//go:build linux

package collector

import (
	"context"
	"log/slog"

	"github.com/fsnotify/fsnotify"
)

// WatchPasswd invalidates the UID cache when /etc/passwd changes.
func (c *UsernameCache) WatchPasswd(ctx context.Context, log *slog.Logger) {
	if c == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Debug("passwd watcher unavailable", "error", err)
		return
	}
	defer w.Close()
	if err := w.Add("/etc/passwd"); err != nil {
		log.Debug("passwd watch add failed", "error", err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				c.Invalidate()
				log.Debug("username cache invalidated", "reason", "passwd_change", "path", ev.Name)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			if err != nil {
				log.Debug("passwd watcher error", "error", err)
			}
		}
	}
}
