package main

import (
	"context"
	"fmt"

	"webblock/internal/proto"
	"webblock/internal/store"
	"webblock/internal/validate"
)

// Handler processes one kind of request under the authority of a caller. Each
// action is a small, independently testable Handler registered in the
// Dispatcher (see docs/STANDARDS.md section 7).
type Handler interface {
	Handle(ctx context.Context, caller peerCred, req proto.Request) proto.Response
}

// genericApplyError is the stable, non-leaky message returned to clients when an
// internal store/firewall operation fails. Details are logged, not returned.
const genericApplyError = "could not apply changes; check the daemon logs (journalctl -u webblockd)"

// mutateHandler implements both add and remove; add reports the operation when
// adding is true.
type mutateHandler struct {
	eng   *Engine
	authz authorizer
	logf  Logger
	add   bool
}

func (h mutateHandler) Handle(ctx context.Context, caller peerCred, req proto.Request) proto.Response {
	scope, err := h.authz.ResolveScope(req.TargetUser, caller)
	if err != nil {
		// Authorization messages are intentionally user-facing.
		return proto.Response{Error: err.Error()}
	}

	domains, ips, err := normalizeAndValidate(req.Domains, req.IPs)
	if err != nil {
		// Validation messages are safe and helpful to return.
		return proto.Response{Error: err.Error()}
	}
	if len(domains) == 0 && len(ips) == 0 {
		return proto.Response{Error: "nothing to do: provide --name and/or --ip"}
	}

	action := proto.ActionRemove
	if h.add {
		action = proto.ActionAdd
	}

	var nDom, nIP int
	if h.add {
		nDom, nIP, err = h.eng.AddEntries(ctx, scope, domains, ips)
	} else {
		nDom, nIP, err = h.eng.RemoveEntries(ctx, scope, domains, ips)
	}
	if err != nil {
		h.logf("uid=%d action=%s scope=%s FAILED: %v", caller.UID, action, scope.Label(), err)
		return proto.Response{Error: genericApplyError}
	}

	h.logf("uid=%d action=%s scope=%s domains=%v ips=%v applied=%d/%d OK",
		caller.UID, action, scope.Label(), domains, ips, nDom, nIP)
	return proto.Response{OK: true, Message: h.message(scope, nDom, nIP, len(domains), len(ips))}
}

// message reports what actually changed, distinguishing requested from applied
// counts so "already present" / "not found" items are visible to the user.
func (h mutateHandler) message(scope store.Scope, changedDom, changedIP, reqDom, reqIP int) string {
	verb := "removed from"
	if h.add {
		verb = "added to"
	}
	msg := fmt.Sprintf("%d domain(s) and %d IP(s) %s %s blocklist", changedDom, changedIP, verb, scope.Label())
	noop := (reqDom - changedDom) + (reqIP - changedIP)
	if noop > 0 {
		if h.add {
			msg += fmt.Sprintf(" (%d already present)", noop)
		} else {
			msg += fmt.Sprintf(" (%d not found)", noop)
		}
	}
	return msg
}

// showHandler returns the blocklists visible to the caller. A normal user sees
// only their own list plus the read-only global list; root sees the global list
// and a per-user breakdown. Other users' lists are never returned to a non-root
// caller.
type showHandler struct {
	eng  *Engine
	logf Logger
}

func (h showHandler) Handle(_ context.Context, caller peerCred, _ proto.Request) proto.Response {
	if caller.IsRoot() {
		return h.showAsRoot()
	}
	return h.showAsUser(int(caller.UID))
}

func (h showHandler) showAsRoot() proto.Response {
	global, err := h.eng.Load(store.GlobalScope)
	if err != nil {
		h.logf("show(root) load global FAILED: %v", err)
		return proto.Response{Error: genericApplyError}
	}
	views := []proto.ScopeView{
		{Scope: "global (all users)", Domains: global.Domains, IPs: global.IPs},
	}

	uids, err := h.eng.ListUserUIDs()
	if err != nil {
		h.logf("show(root) list users FAILED: %v", err)
		return proto.Response{Error: genericApplyError}
	}
	for _, uid := range uids {
		bl, err := h.eng.Load(store.UserScope(uid))
		if err != nil {
			h.logf("show(root) load user %d FAILED: %v", uid, err)
			return proto.Response{Error: genericApplyError}
		}
		views = append(views, proto.ScopeView{Scope: scopeLabelWithName(uid), Domains: bl.Domains, IPs: bl.IPs})
	}
	return proto.Response{OK: true, Views: views}
}

func (h showHandler) showAsUser(uid int) proto.Response {
	own, err := h.eng.Load(store.UserScope(uid))
	if err != nil {
		h.logf("show(uid=%d) load own FAILED: %v", uid, err)
		return proto.Response{Error: genericApplyError}
	}
	global, err := h.eng.Load(store.GlobalScope)
	if err != nil {
		h.logf("show(uid=%d) load global FAILED: %v", uid, err)
		return proto.Response{Error: genericApplyError}
	}
	return proto.Response{
		OK: true,
		Views: []proto.ScopeView{
			{Scope: "your blocklist", Domains: own.Domains, IPs: own.IPs},
			{Scope: "global (set by administrator)", ReadOnly: true, Domains: global.Domains, IPs: global.IPs},
		},
	}
}

// statusHandler reports daemon health and configuration.
type statusHandler struct {
	eng *Engine
}

func (h statusHandler) Handle(_ context.Context, _ peerCred, _ proto.Request) proto.Response {
	return proto.Response{
		OK: true,
		Status: &proto.StatusInfo{
			Backend:         h.eng.BackendName(),
			ProtocolVersion: proto.Version,
		},
	}
}

// normalizeAndValidate cleans and checks all inputs, returning canonical forms.
// It is the authoritative validation in the privileged process (the client also
// validates, but only for early feedback).
func normalizeAndValidate(rawDomains, rawIPs []string) (domains, ips []string, err error) {
	if len(rawDomains)+len(rawIPs) > validate.MaxItemsPerRequest {
		return nil, nil, fmt.Errorf("too many items in one request (max %d)", validate.MaxItemsPerRequest)
	}
	for _, d := range rawDomains {
		n := validate.NormalizeDomain(d)
		if err := validate.ValidateDomain(n); err != nil {
			return nil, nil, err
		}
		domains = append(domains, n)
	}
	for _, ip := range rawIPs {
		canon, _, err := validate.NormalizeIP(ip)
		if err != nil {
			return nil, nil, err
		}
		ips = append(ips, canon)
	}
	return domains, ips, nil
}
