package resolver

import (
	"context"
	"testing"
	"time"
)

func TestResolveLocalhost(t *testing.T) {
	r := New(2 * time.Second)
	res, err := r.Resolve(context.Background(), "localhost")
	if err != nil {
		t.Skipf("localhost not resolvable in this environment: %v", err)
	}
	if len(res.V4) == 0 && len(res.V6) == 0 {
		t.Errorf("expected at least one address for localhost, got none")
	}
}

func TestResolveManyEmpty(t *testing.T) {
	r := New(time.Second)
	results, failures := r.ResolveMany(context.Background(), nil, 4)
	if len(results) != 0 || len(failures) != 0 {
		t.Errorf("expected empty maps, got results=%v failures=%v", results, failures)
	}
}

func TestResolveManyFailureReported(t *testing.T) {
	r := New(2 * time.Second)
	// A reserved TLD that must never resolve (RFC 2606).
	results, failures := r.ResolveMany(context.Background(), []string{"nonexistent.invalid"}, 2)
	if len(results) != 0 {
		t.Errorf("expected no successful results, got %v", results)
	}
	if _, ok := failures["nonexistent.invalid"]; !ok {
		t.Errorf("expected a failure for nonexistent.invalid, got %v", failures)
	}
}
