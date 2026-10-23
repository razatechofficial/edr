//go:build linux

package localapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredentials reads SO_PEERCRED, which the kernel fills in at connect
// time from the peer's own credentials.
func peerCredentials(uc *net.UnixConn) (Peer, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("localapi: peer credentials: %w", err)
	}
	var (
		cred    *unix.Ucred
		sockErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, fmt.Errorf("localapi: peer credentials: %w", err)
	}
	if sockErr != nil {
		return Peer{}, fmt.Errorf("localapi: SO_PEERCRED: %w", sockErr)
	}
	return Peer{PID: cred.Pid, UID: cred.Uid, GID: cred.Gid}, nil
}
