package main

import "testing"

func TestResolveScope(t *testing.T) {
	az := authorizer{}
	root := peerCred{UID: 0}
	alice := peerCred{UID: 1000}

	t.Run("user defaults to own scope", func(t *testing.T) {
		scope, err := az.ResolveScope("", alice)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scope.Global || scope.UID != 1000 {
			t.Errorf("got %+v, want user:1000", scope)
		}
	})

	t.Run("user may target self by uid", func(t *testing.T) {
		if _, err := az.ResolveScope("1000", alice); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("user may not target another user", func(t *testing.T) {
		if _, err := az.ResolveScope("1001", alice); err == nil {
			t.Errorf("expected permission denied")
		}
	})

	t.Run("root defaults to global", func(t *testing.T) {
		scope, err := az.ResolveScope("", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !scope.Global {
			t.Errorf("got %+v, want global", scope)
		}
	})

	t.Run("root may target a user by uid", func(t *testing.T) {
		scope, err := az.ResolveScope("1000", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scope.Global || scope.UID != 1000 {
			t.Errorf("got %+v, want user:1000", scope)
		}
	})

	t.Run("root global keyword", func(t *testing.T) {
		scope, err := az.ResolveScope("global", root)
		if err != nil || !scope.Global {
			t.Errorf("got %+v err=%v, want global", scope, err)
		}
	})
}
