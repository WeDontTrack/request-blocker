//go:build linux

package backend

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestFirewallIntegration exercises the real backend against the live kernel
// firewall. It is destructive (it programs and tears down rules) so it only runs
// when explicitly opted in via WEBBLOCK_INTEGRATION=1 and as root.
func TestFirewallIntegration(t *testing.T) {
	if os.Getenv("WEBBLOCK_INTEGRATION") != "1" {
		t.Skip("set WEBBLOCK_INTEGRATION=1 to run firewall integration tests (modifies the live firewall)")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to modify the firewall")
	}
	be, err := Detect()
	if err != nil {
		t.Skipf("no usable backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Teardown() })

	// Initial (full) apply.
	state := State{Global: IPSet{V4: []string{"203.0.113.9"}}}
	if err := be.Apply(state); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !liveContains(t, be, "203.0.113.9") {
		t.Errorf("expected 203.0.113.9 in live ruleset after apply")
	}

	// Incremental apply (same structure, one more element).
	state.Global.V4 = append(state.Global.V4, "203.0.113.10")
	if err := be.Apply(state); err != nil {
		t.Fatalf("incremental apply: %v", err)
	}
	if !liveContains(t, be, "203.0.113.10") {
		t.Errorf("incremental add not visible in live ruleset")
	}

	if err := be.Teardown(); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if liveContains(t, be, "203.0.113.9") {
		t.Errorf("teardown left rules behind")
	}
}

func liveContains(t *testing.T, be Backend, needle string) bool {
	t.Helper()
	var out []byte
	var err error
	if be.Name() == "nftables" {
		out, err = exec.Command("nft", "list", "ruleset").CombinedOutput()
	} else {
		out, err = exec.Command("ipset", "list").CombinedOutput()
	}
	if err != nil {
		t.Fatalf("inspect live ruleset: %v: %s", err, out)
	}
	return strings.Contains(string(out), needle)
}
