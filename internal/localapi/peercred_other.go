//go:build !linux && !darwin

package localapi

import "net"

// peerCredentials is unimplemented outside Linux and macOS. Windows reaches
// the agent over the loopback HTTP fallback, which cannot name its caller at
// all, so the mutating routes are refused there; see the package comment.
func peerCredentials(_ *net.UnixConn) (Peer, error) {
	return Peer{}, ErrPeerCredsUnsupported
}
