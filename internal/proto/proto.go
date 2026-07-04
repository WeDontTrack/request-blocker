// Package proto defines the JSON request/response types exchanged between the
// unprivileged webblock CLI client and the privileged webblockd daemon over a
// Unix domain socket.
//
// The protocol is deliberately tiny: the client opens a connection, writes a
// single newline-terminated JSON Request, and reads a single newline-terminated
// JSON Response. The daemon never trusts identity information carried in the
// request body; the caller's uid/gid are read from the kernel via SO_PEERCRED.
package proto

// SocketPath is the well-known location of the daemon's Unix domain socket.
const SocketPath = "/run/webblock.sock"

// Version is the current protocol version. The client stamps every Request with
// it, and the daemon rejects Requests whose Version it does not support. Bump
// this when the wire format changes incompatibly.
const Version = 1

// Action enumerates the operations a client may request.
type Action string

const (
	// ActionAdd adds domains and/or IPs to a blocklist scope.
	ActionAdd Action = "add"
	// ActionRemove removes domains and/or IPs from a blocklist scope.
	ActionRemove Action = "remove"
	// ActionShow returns the blocklists visible to the caller.
	ActionShow Action = "show"
	// ActionStatus returns daemon health/version information.
	ActionStatus Action = "status"
)

// Request is sent by the client to the daemon.
//
// Identity (uid/gid) is intentionally absent: it is derived by the daemon from
// the connecting socket's peer credentials and cannot be supplied by the client.
type Request struct {
	// Version is the protocol version the client speaks; see Version.
	Version int      `json:"version"`
	Action  Action   `json:"action"`
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`

	// TargetUser is only honored when the caller is root. It selects the scope
	// to operate on:
	//   - ""        : the global scope (root) / the caller's own scope (user)
	//   - "global"  : the global scope (root only)
	//   - "<name>"  : a specific user's scope by name (root only)
	//   - "<uid>"   : a specific user's scope by numeric uid (root only)
	TargetUser string `json:"target_user,omitempty"`
}

// ScopeView is a single blocklist scope returned by ActionShow.
type ScopeView struct {
	// Scope is a human-readable label, e.g. "global" or "user:1000 (alice)".
	Scope string `json:"scope"`
	// ReadOnly indicates the caller may view but not modify this scope.
	ReadOnly bool     `json:"read_only"`
	Domains  []string `json:"domains"`
	IPs      []string `json:"ips"`
}

// Response is returned by the daemon to the client.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Message is a human-readable status for add/remove operations.
	Message string `json:"message,omitempty"`
	// Views is populated for ActionShow only.
	Views []ScopeView `json:"views,omitempty"`
	// Status is populated for ActionStatus only.
	Status *StatusInfo `json:"status,omitempty"`
}

// StatusInfo reports daemon health and configuration to a client.
type StatusInfo struct {
	Backend         string `json:"backend"`
	ProtocolVersion int    `json:"protocol_version"`
}
