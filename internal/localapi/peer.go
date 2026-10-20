package localapi

import (
	"errors"
	"fmt"
	"net"
)

// Peer identifies the process on the other end of a local control
// connection, as reported by the kernel rather than by the request.
type Peer struct {
	PID int32
	UID uint32
	GID uint32
}

var (
	// ErrPeerCredsUnsupported means the kernel on this platform will not name
	// the caller for this transport. A mutating route is refused rather than
	// guessed at.
	ErrPeerCredsUnsupported = errors.New("localapi: peer credentials are not available on this transport")
	// ErrNotPrivileged means the caller was identified and is not root.
	ErrNotPrivileged = errors.New("localapi: caller is not privileged")
)

// peerOf returns the credentials of the process on the other end of conn.
// Only a Unix domain socket carries them; a loopback TCP connection does not,
// which is why the HTTP fallback is read-only.
func peerOf(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, ErrPeerCredsUnsupported
	}
	return peerCredentials(uc)
}

// authorizePeer decides whether a mutating route may run for the peer that
// peerOf returned. Anything other than an identified root caller is refused:
// the request body is never consulted, because a caller that can reach the
// socket can put anything in it.
func authorizePeer(p Peer, err error) error {
	if err != nil {
		return err
	}
	if p.UID != 0 {
		return fmt.Errorf("%w (uid %d, pid %d)", ErrNotPrivileged, p.UID, p.PID)
	}
	return nil
}
