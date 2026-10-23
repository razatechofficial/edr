//go:build !windows

package localapi

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// listenControlSocket binds the control socket and restricts it to
// root:group. The returned mode is 0660 when the group exists and could be
// set, and 0600 otherwise: a socket nobody but root can reach is a working
// agent with a smaller audience, whereas a world-writable one would let any
// local user reach the mutating routes and rely entirely on the peer-credential
// check to refuse them.
func listenControlSocket(path, group string) (net.Listener, fs.FileMode, error) {
	if path == "" {
		return nil, 0, errors.New("localapi: empty control socket path")
	}
	dir := filepath.Dir(path)
	// 0755: a caller must traverse this directory to reach the socket; the
	// socket's own mode is what restricts access.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, 0, fmt.Errorf("localapi: create socket dir %s: %w", dir, err)
	}
	// A socket left behind by a killed agent keeps the new one from binding.
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, 0, fmt.Errorf("localapi: remove stale socket %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, 0, fmt.Errorf("localapi: listen on %s: %w", path, err)
	}

	mode := fs.FileMode(0o600)
	if gid, ok := lookupGID(group); ok {
		if err := os.Chown(path, os.Getuid(), gid); err == nil {
			mode = 0o660
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, 0, fmt.Errorf("localapi: chmod socket %s: %w", path, err)
	}
	return ln, mode, nil
}

// lookupGID resolves a group name to a gid, reporting false when the group
// does not exist on this host.
func lookupGID(group string) (int, bool) {
	if group == "" {
		return 0, false
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}
