package main

// peerCred is the kernel-verified identity of a connecting client, obtained via
// SO_PEERCRED (see peercred_linux.go). It is the sole source of caller identity;
// nothing in the request body is ever trusted for authorization.
type peerCred struct {
	UID uint32
	GID uint32
	PID int32
}

// IsRoot reports whether the caller is the superuser.
func (c peerCred) IsRoot() bool { return c.UID == 0 }
