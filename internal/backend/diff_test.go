package backend

import (
	"sort"
	"strings"
	"testing"
)

func TestDiffStrings(t *testing.T) {
	added, removed := diffStrings([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	sort.Strings(added)
	sort.Strings(removed)
	if strings.Join(added, ",") != "d" {
		t.Errorf("added = %v, want [d]", added)
	}
	if strings.Join(removed, ",") != "a" {
		t.Errorf("removed = %v, want [a]", removed)
	}
}

func TestSameUIDs(t *testing.T) {
	a := map[int]IPSet{1000: {}, 1001: {}}
	b := map[int]IPSet{1000: {}, 1001: {}}
	c := map[int]IPSet{1000: {}}
	if !sameUIDs(a, b) {
		t.Error("expected sameUIDs(a,b) true")
	}
	if sameUIDs(a, c) {
		t.Error("expected sameUIDs(a,c) false")
	}
}

func TestNftBuildDelta(t *testing.T) {
	b := newNftBackend()
	prev := State{
		Global:  IPSet{V4: []string{"1.1.1.1", "2.2.2.2"}},
		PerUser: map[int]IPSet{1000: {V4: []string{"10.0.0.1"}}},
	}
	next := State{
		Global:  IPSet{V4: []string{"2.2.2.2", "3.3.3.3"}}, // remove 1.1.1.1, add 3.3.3.3
		PerUser: map[int]IPSet{1000: {V4: []string{"10.0.0.1", "10.0.0.2"}}},
	}
	delta := b.buildDelta(prev, next)

	want := []string{
		"add element inet webblock blocked_v4_global { 3.3.3.3 }",
		"delete element inet webblock blocked_v4_global { 1.1.1.1 }",
		"add element inet webblock blocked_v4_uid_1000 { 10.0.0.2 }",
	}
	for _, w := range want {
		if !strings.Contains(delta, w) {
			t.Errorf("delta missing %q\nfull:\n%s", w, delta)
		}
	}
	if strings.Contains(delta, "2.2.2.2") {
		t.Errorf("unchanged element 2.2.2.2 should not appear in delta:\n%s", delta)
	}
}

func TestIptablesBuildSetDelta(t *testing.T) {
	b := newIptablesBackend()
	prev := State{Global: IPSet{V4: []string{"1.1.1.1"}}}
	next := State{Global: IPSet{V4: []string{"2.2.2.2"}}}
	delta := b.buildSetDelta(prev, next, nil)

	if !strings.Contains(delta, "add webblk_g_4 2.2.2.2") {
		t.Errorf("delta missing add line:\n%s", delta)
	}
	if !strings.Contains(delta, "del webblk_g_4 1.1.1.1") {
		t.Errorf("delta missing del line:\n%s", delta)
	}
}
