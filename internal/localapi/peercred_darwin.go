//go:build darwin

package localapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredentials reads LOCAL_PEERCRED, the macOS equivalent of SO_PEERCRED.
// Xucred carries no PID, so the PID comes from LOCAL_PEERPID; it is for the
// audit log only, and a failure to read it does not fail the call.
func peerCredentials(uc *net.UnixConn) (Peer, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("localapi: peer credentials: %w", err)
	}
	var (
		cred    *unix.Xucred
		pid     int
		sockErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if sockErr != nil {
			return
		}
		pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return Peer{}, fmt.Errorf("localapi: peer credentials: %w", err)
	}
	if sockErr != nil {
		return Peer{}, fmt.Errorf("localapi: LOCAL_PEERCRED: %w", sockErr)
	}
	p := Peer{PID: int32(pid), UID: cred.Uid}
	if cred.Ngroups > 0 {
		p.GID = cred.Groups[0]
	}
	return p, nil
}
