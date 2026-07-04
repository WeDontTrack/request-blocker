//go:build linux

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// getPeerCred returns the kernel-verified credentials of the process on the
// other end of a Unix domain socket. These are obtained via SO_PEERCRED and
// cannot be forged by the client, which is the foundation of the daemon's
// access control.
func getPeerCred(c *net.UnixConn) (peerCred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return peerCred{}, fmt.Errorf("syscall conn: %w", err)
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peerCred{}, fmt.Errorf("getsockopt control: %w", err)
	}
	if sockErr != nil {
		return peerCred{}, fmt.Errorf("SO_PEERCRED: %w", sockErr)
	}
	return peerCred{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}
