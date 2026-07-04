package store

import (
	"reflect"
	"testing"
)

func TestMutateAndLoad(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = st.Mutate(GlobalScope, func(bl *BlockList) error {
		bl.AddDomains([]string{"b.com", "a.com", "a.com"}) // duplicate ignored
		bl.AddIPs([]string{"10.0.0.2", "10.0.0.1"})
		return nil
	})
	if err != nil {
		t.Fatalf("Mutate: %v", err)
	}

	got, err := st.Load(GlobalScope)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got.Domains, []string{"a.com", "b.com"}) {
		t.Errorf("domains not sorted/deduped: %v", got.Domains)
	}
	if !reflect.DeepEqual(got.IPs, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("ips not sorted: %v", got.IPs)
	}
}

func TestRemoveCounts(t *testing.T) {
	bl := BlockList{}
	if n := bl.AddDomains([]string{"a.com", "b.com"}); n != 2 {
		t.Errorf("AddDomains added %d, want 2", n)
	}
	if n := bl.AddDomains([]string{"a.com"}); n != 0 {
		t.Errorf("re-adding existing returned %d, want 0", n)
	}
	if n := bl.RemoveDomains([]string{"a.com", "missing.com"}); n != 1 {
		t.Errorf("RemoveDomains removed %d, want 1", n)
	}
}

func TestLoadMissingScopeIsEmpty(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bl, err := st.Load(UserScope(4242))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if len(bl.Domains) != 0 || len(bl.IPs) != 0 {
		t.Errorf("expected empty blocklist, got %+v", bl)
	}
}

func TestListUserUIDs(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, uid := range []int{1001, 1000} {
		if err := st.Mutate(UserScope(uid), func(bl *BlockList) error {
			bl.AddDomains([]string{"x.com"})
			return nil
		}); err != nil {
			t.Fatalf("Mutate uid %d: %v", uid, err)
		}
	}
	uids, err := st.ListUserUIDs()
	if err != nil {
		t.Fatalf("ListUserUIDs: %v", err)
	}
	if !reflect.DeepEqual(uids, []int{1000, 1001}) {
		t.Errorf("ListUserUIDs = %v, want [1000 1001]", uids)
	}
}
