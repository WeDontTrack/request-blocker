package backend

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// nftTable is the single nftables table this tool owns. It is the only place the
// table identifier is written (see docs/STANDARDS.md section 3).
const nftTable = "inet webblock"

// nftBackend enforces blocklists using nftables. It owns nftTable. The first
// apply (and any apply that changes the rule structure, i.e. the set of users)
// rebuilds the whole table in one atomic `nft -f` transaction; subsequent
// element-only changes are applied incrementally via add/delete element, which
// avoids re-parsing the entire ruleset on every small change.
//
// last is the most recently applied desired state, used to compute deltas. It
// is safe without a mutex because the engine serializes all Apply calls.
type nftBackend struct {
	last *State
}

func newNftBackend() *nftBackend { return &nftBackend{} }

func (b *nftBackend) Name() string { return "nftables" }

func (b *nftBackend) Apply(state State) error {
	// Full rebuild on first apply or when the user set changes (structure).
	if b.last == nil || !sameUIDs(b.last.PerUser, state.PerUser) {
		if err := runNft(b.buildScript(state)); err != nil {
			b.last = nil // force a full rebuild next time
			return err
		}
		snapshot := cloneState(state)
		b.last = &snapshot
		return nil
	}

	// Incremental: only set elements may have changed.
	if delta := b.buildDelta(*b.last, state); delta != "" {
		if err := runNft(delta); err != nil {
			// Self-heal: the live ruleset may have drifted; rebuild fully.
			if healErr := runNft(b.buildScript(state)); healErr != nil {
				b.last = nil
				return healErr
			}
		}
	}
	snapshot := cloneState(state)
	b.last = &snapshot
	return nil
}

func (b *nftBackend) Teardown() error {
	b.last = nil
	// Ensure the table exists before deleting so this is idempotent.
	return runNft(fmt.Sprintf("add table %s\ndelete table %s\n", nftTable, nftTable))
}

// buildDelta renders an nft script that brings the element membership of each
// set from prev to next. Structure (sets, chains, rules) is assumed unchanged
// (callers guarantee sameUIDs).
func (b *nftBackend) buildDelta(prev, next State) string {
	var s strings.Builder
	writeElementDelta(&s, "blocked_v4_global", prev.Global.V4, next.Global.V4)
	writeElementDelta(&s, "blocked_v6_global", prev.Global.V6, next.Global.V6)
	for _, uid := range sortedUIDs(next.PerUser) {
		p := prev.PerUser[uid]
		n := next.PerUser[uid]
		writeElementDelta(&s, fmt.Sprintf("blocked_v4_uid_%d", uid), p.V4, n.V4)
		writeElementDelta(&s, fmt.Sprintf("blocked_v6_uid_%d", uid), p.V6, n.V6)
	}
	return s.String()
}

// writeElementDelta appends add/delete element lines for one set.
func writeElementDelta(s *strings.Builder, set string, prev, next []string) {
	added, removed := diffStrings(prev, next)
	if len(added) > 0 {
		fmt.Fprintf(s, "add element %s %s { %s }\n", nftTable, set, strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		fmt.Fprintf(s, "delete element %s %s { %s }\n", nftTable, set, strings.Join(removed, ", "))
	}
}

// buildScript renders the full desired ruleset as an nft script. It is pure
// (no I/O) so it can be unit-tested directly.
//
// Per-user enforcement uses a verdict map keyed on the socket owner uid
// (meta skuid vmap) that jumps to a per-uid chain. This makes the per-packet
// cost O(1) - a single map lookup - regardless of how many users have lists,
// rather than a linear scan of one rule pair per user.
func (b *nftBackend) buildScript(state State) string {
	var s strings.Builder

	// Recreate the table atomically: add (idempotent) then delete then add.
	fmt.Fprintf(&s, "add table %s\n", nftTable)
	fmt.Fprintf(&s, "delete table %s\n", nftTable)
	fmt.Fprintf(&s, "add table %s\n", nftTable)

	// Declare sets.
	fmt.Fprintf(&s, "add set %s blocked_v4_global { type ipv4_addr; }\n", nftTable)
	fmt.Fprintf(&s, "add set %s blocked_v6_global { type ipv6_addr; }\n", nftTable)

	uids := sortedUIDs(state.PerUser)
	for _, uid := range uids {
		fmt.Fprintf(&s, "add set %s blocked_v4_uid_%d { type ipv4_addr; }\n", nftTable, uid)
		fmt.Fprintf(&s, "add set %s blocked_v6_uid_%d { type ipv6_addr; }\n", nftTable, uid)
	}

	// Output chain hooked at priority 0 with a default-accept policy so we only
	// affect destinations we explicitly block.
	fmt.Fprintf(&s, "add chain %s output { type filter hook output priority 0; policy accept; }\n", nftTable)

	// Per-uid regular (unhooked) chains, each dropping that user's destinations.
	// These must exist before the verdict map that jumps to them.
	for _, uid := range uids {
		fmt.Fprintf(&s, "add chain %s uid_%d\n", nftTable, uid)
		fmt.Fprintf(&s, "add rule %s uid_%d ip daddr @blocked_v4_uid_%d drop\n", nftTable, uid, uid)
		fmt.Fprintf(&s, "add rule %s uid_%d ip6 daddr @blocked_v6_uid_%d drop\n", nftTable, uid, uid)
	}

	// Global drops apply to every user.
	fmt.Fprintf(&s, "add rule %s output ip daddr @blocked_v4_global drop\n", nftTable)
	fmt.Fprintf(&s, "add rule %s output ip6 daddr @blocked_v6_global drop\n", nftTable)

	// Single O(1) dispatch to the owner's chain. Owners not in the map simply
	// fall through (no verdict) and are accepted.
	if len(uids) > 0 {
		entries := make([]string, 0, len(uids))
		for _, uid := range uids {
			entries = append(entries, fmt.Sprintf("%d : jump uid_%d", uid, uid))
		}
		fmt.Fprintf(&s, "add rule %s output meta skuid vmap { %s }\n", nftTable, strings.Join(entries, ", "))
	}

	// Populate set elements.
	writeElements(&s, "blocked_v4_global", state.Global.V4)
	writeElements(&s, "blocked_v6_global", state.Global.V6)
	for _, uid := range uids {
		writeElements(&s, fmt.Sprintf("blocked_v4_uid_%d", uid), state.PerUser[uid].V4)
		writeElements(&s, fmt.Sprintf("blocked_v6_uid_%d", uid), state.PerUser[uid].V6)
	}

	return s.String()
}

func writeElements(s *strings.Builder, set string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	fmt.Fprintf(s, "add element %s %s { %s }\n", nftTable, set, strings.Join(addrs, ", "))
}

func runNft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
