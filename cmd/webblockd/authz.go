package main

import (
	"fmt"
	"os/user"
	"strconv"

	"webblock/internal/store"
)

// authorizer centralizes all access-control decisions. Identity always comes
// from peerCred (kernel SO_PEERCRED); request fields never influence it.
type authorizer struct{}

// ResolveScope determines which blocklist a mutating request targets and
// enforces authorization:
//
//   - A non-root caller may only ever operate on its own scope. Supplying a
//     --user that is not itself is denied.
//   - Root operates on the global scope by default, or on a specific user's
//     scope when target names/numbers that user.
func (authorizer) ResolveScope(target string, caller peerCred) (store.Scope, error) {
	if !caller.IsRoot() {
		if target != "" && target != strconv.Itoa(int(caller.UID)) {
			return store.Scope{}, fmt.Errorf("permission denied: you may only modify your own blocklist")
		}
		return store.UserScope(int(caller.UID)), nil
	}

	if target == "" || target == "global" {
		return store.GlobalScope, nil
	}
	uid, err := lookupUID(target)
	if err != nil {
		return store.Scope{}, err
	}
	return store.UserScope(uid), nil
}

// lookupUID resolves a target that is either a numeric uid or a username.
func lookupUID(target string) (int, error) {
	if uid, err := strconv.Atoi(target); err == nil {
		return uid, nil
	}
	u, err := user.Lookup(target)
	if err != nil {
		return 0, fmt.Errorf("unknown user %q", target)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("user %q has non-numeric uid", target)
	}
	return uid, nil
}

// scopeLabelWithName renders a user scope label, enriched with the username when
// it can be resolved.
func scopeLabelWithName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return fmt.Sprintf("user:%d (%s)", uid, u.Username)
	}
	return fmt.Sprintf("user:%d", uid)
}
