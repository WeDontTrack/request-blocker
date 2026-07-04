//go:build !linux

package main

import (
	"fmt"
	"net"
)

// getPeerCred is unavailable off Linux. The daemon is Linux-only; this stub
// exists solely so the package compiles during cross-platform development.
func getPeerCred(_ *net.UnixConn) (peerCred, error) {
	return peerCred{}, fmt.Errorf("webblockd is only supported on Linux")
}
