package backend

import (
	"strings"
	"testing"
)

func TestNftBuildScript(t *testing.T) {
	b := newNftBackend()
	state := State{
		Global: IPSet{V4: []string{"93.184.216.34"}, V6: []string{"2001:db8::1"}},
		PerUser: map[int]IPSet{
			1000: {V4: []string{"10.0.0.5"}},
		},
	}
	script := b.buildScript(state)

	mustContain := []string{
		"add table inet webblock",
		"delete table inet webblock",
		"add set inet webblock blocked_v4_global { type ipv4_addr; }",
		"add set inet webblock blocked_v4_uid_1000 { type ipv4_addr; }",
		"add chain inet webblock output { type filter hook output priority 0; policy accept; }",
		"add chain inet webblock uid_1000",
		"add rule inet webblock uid_1000 ip daddr @blocked_v4_uid_1000 drop",
		"add rule inet webblock output ip daddr @blocked_v4_global drop",
		"add rule inet webblock output meta skuid vmap { 1000 : jump uid_1000 }",
		"add element inet webblock blocked_v4_global { 93.184.216.34 }",
		"add element inet webblock blocked_v6_global { 2001:db8::1 }",
		"add element inet webblock blocked_v4_uid_1000 { 10.0.0.5 }",
	}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Errorf("script missing line:\n  %q\nfull script:\n%s", want, script)
		}
	}
}

func TestNftBuildScriptEmptyState(t *testing.T) {
	b := newNftBackend()
	script := b.buildScript(State{})

	// The table and global sets/rules always exist; no element lines and no
	// per-uid rules when there is nothing to block.
	if !strings.Contains(script, "add rule inet webblock output ip daddr @blocked_v4_global drop") {
		t.Errorf("expected global drop rule even when empty")
	}
	if strings.Contains(script, "add element") {
		t.Errorf("did not expect element lines for empty state:\n%s", script)
	}
	if strings.Contains(script, "meta skuid") {
		t.Errorf("did not expect a verdict map for empty state:\n%s", script)
	}
	if strings.Contains(script, "jump uid_") {
		t.Errorf("did not expect per-uid chains for empty state:\n%s", script)
	}
}
