//go:build windows

package localapi

import (
	"io/fs"
	"net"
)

// listenControlSocket has no Windows implementation. The control path there
// is a named pipe, and a pipe server that can name its caller needs more than
// the standard library offers, so the agent falls back to the loopback HTTP
// listener and refuses the mutating routes on it.
func listenControlSocket(_, _ string) (net.Listener, fs.FileMode, error) {
	return nil, 0, ErrNoSocketTransport
}
