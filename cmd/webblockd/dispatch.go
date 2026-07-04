package main

import (
	"context"
	"fmt"

	"webblock/internal/proto"
)

// Dispatcher routes a request to the Handler registered for its action. It also
// enforces the protocol version check. Transport code (the Server) knows nothing
// about individual actions; it only calls Dispatch.
type Dispatcher struct {
	handlers map[proto.Action]Handler
}

// NewDispatcher wires the action handlers. Adding an operation means adding a
// constant in proto and an entry here; nothing in the transport layer changes.
func NewDispatcher(eng *Engine, logf Logger) *Dispatcher {
	az := authorizer{}
	return &Dispatcher{
		handlers: map[proto.Action]Handler{
			proto.ActionAdd:    mutateHandler{eng: eng, authz: az, logf: logf, add: true},
			proto.ActionRemove: mutateHandler{eng: eng, authz: az, logf: logf, add: false},
			proto.ActionShow:   showHandler{eng: eng, logf: logf},
			proto.ActionStatus: statusHandler{eng: eng},
		},
	}
}

// Dispatch validates the protocol version, selects the handler, and runs it.
func (d *Dispatcher) Dispatch(ctx context.Context, caller peerCred, req proto.Request) proto.Response {
	// Version 0 means a legacy client that did not stamp a version; accept it
	// for backward compatibility. Reject anything newer than we understand.
	if req.Version > proto.Version {
		return proto.Response{Error: fmt.Sprintf("unsupported protocol version %d (daemon speaks %d); upgrade the daemon", req.Version, proto.Version)}
	}
	h, ok := d.handlers[req.Action]
	if !ok {
		return proto.Response{Error: fmt.Sprintf("unknown action %q", req.Action)}
	}
	return h.Handle(ctx, caller, req)
}
