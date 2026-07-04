package backend

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// iptablesBackend enforces blocklists using iptables/ip6tables for matching and
// ipset for efficient O(1) address sets.
//
// Structure:
//   - ipset hash:ip sets hold destination addresses, one per scope/family.
//   - A custom chain "WEBBLOCK" is hooked from OUTPUT and rebuilt on each Apply.
//   - Per-user rules use the owner match (-m owner --uid-owner), valid in OUTPUT.
//
// A full apply uses a constant number of subprocesses regardless of how many
// users or addresses are involved: one "ipset restore" for all sets, and one
// "iptables-restore --noflush" per address family for the WEBBLOCK chain (plus
// an idempotent OUTPUT-jump check). Set contents are swapped atomically via the
// ipset create/swap idiom; each chain rebuild is one atomic restore.
//
// When only set elements change (the user set is unchanged), Apply takes an
// incremental path: a single "ipset restore -exist" with add/del lines, leaving
// the iptables chain untouched (rules reference sets by name).
//
// last is the most recently applied desired state, used to compute deltas. It
// is safe without a mutex because the engine serializes all Apply calls.
type iptablesBackend struct {
	last *State
}

func newIptablesBackend() *iptablesBackend { return &iptablesBackend{} }

func (b *iptablesBackend) Name() string { return "iptables+ipset" }

const (
	ipChain   = "WEBBLOCK"
	setPrefix = "webblk_"
)

// family bundles the per-address-family tools and identifiers.
type family struct {
	cmd     string // "iptables" or "ip6tables"
	restore string // "iptables-restore" or "ip6tables-restore"
	ipsetF  string // "inet" or "inet6"
	suffix  string // "4" or "6"
}

var (
	v4 = family{cmd: "iptables", restore: "iptables-restore", ipsetF: "inet", suffix: "4"}
	v6 = family{cmd: "ip6tables", restore: "ip6tables-restore", ipsetF: "inet6", suffix: "6"}
)

func (b *iptablesBackend) Apply(state State) error {
	uids := sortedUIDs(state.PerUser)

	// Full apply on first apply or when the user set changes (chain structure).
	if b.last == nil || !sameUIDs(b.last.PerUser, state.PerUser) {
		if err := b.fullApply(state, uids); err != nil {
			b.last = nil
			return err
		}
		snapshot := cloneState(state)
		b.last = &snapshot
		return nil
	}

	// Incremental: only set elements changed; chain rules are unaffected.
	if delta := b.buildSetDelta(*b.last, state, uids); delta != "" {
		if err := runStdin("ipset", []string{"restore", "-exist"}, delta); err != nil {
			// Self-heal with a full apply if the live sets drifted.
			if healErr := b.fullApply(state, uids); healErr != nil {
				b.last = nil
				return healErr
			}
		}
	}
	snapshot := cloneState(state)
	b.last = &snapshot
	return nil
}

// fullApply rebuilds every set and the WEBBLOCK chain from scratch.
func (b *iptablesBackend) fullApply(state State, uids []int) error {
	// 1. Refresh every ipset in a single atomic restore.
	if err := b.refreshAllSets(state, uids); err != nil {
		return err
	}
	// 2. Rebuild the WEBBLOCK chain for each family in a single restore each.
	for _, f := range []family{v4, v6} {
		if err := b.rebuildChain(f, uids); err != nil {
			return err
		}
	}
	return nil
}

// buildSetDelta renders one "ipset restore" payload of add/del lines bringing
// every set's membership from prev to next.
func (b *iptablesBackend) buildSetDelta(prev, next State, uids []int) string {
	var s strings.Builder
	b.writeSetElemDelta(&s, v4, "g", prev.Global.V4, next.Global.V4)
	b.writeSetElemDelta(&s, v6, "g", prev.Global.V6, next.Global.V6)
	for _, uid := range uids {
		p := prev.PerUser[uid]
		n := next.PerUser[uid]
		b.writeSetElemDelta(&s, v4, uidToken(uid), p.V4, n.V4)
		b.writeSetElemDelta(&s, v6, uidToken(uid), p.V6, n.V6)
	}
	return s.String()
}

// writeSetElemDelta appends add/del lines for one set.
func (b *iptablesBackend) writeSetElemDelta(s *strings.Builder, f family, token string, prev, next []string) {
	name := b.setName(f, token)
	added, removed := diffStrings(prev, next)
	for _, a := range added {
		fmt.Fprintf(s, "add %s %s\n", name, a)
	}
	for _, a := range removed {
		fmt.Fprintf(s, "del %s %s\n", name, a)
	}
}

// refreshAllSets builds one "ipset restore" payload that atomically swaps the
// contents of every set (global + per-uid, both families) into place.
func (b *iptablesBackend) refreshAllSets(state State, uids []int) error {
	var s strings.Builder
	b.writeSetRefresh(&s, v4, "g", state.Global.V4)
	b.writeSetRefresh(&s, v6, "g", state.Global.V6)
	for _, uid := range uids {
		b.writeSetRefresh(&s, v4, uidToken(uid), state.PerUser[uid].V4)
		b.writeSetRefresh(&s, v6, uidToken(uid), state.PerUser[uid].V6)
	}
	return runStdin("ipset", []string{"restore"}, s.String())
}

// writeSetRefresh appends the create/fill/swap/destroy lines for one set.
func (b *iptablesBackend) writeSetRefresh(s *strings.Builder, f family, token string, addrs []string) {
	name := b.setName(f, token)
	tmp := name + "_t"
	fmt.Fprintf(s, "create %s hash:ip family %s -exist\n", name, f.ipsetF)
	fmt.Fprintf(s, "create %s hash:ip family %s -exist\n", tmp, f.ipsetF)
	fmt.Fprintf(s, "flush %s\n", tmp)
	for _, a := range addrs {
		fmt.Fprintf(s, "add %s %s\n", tmp, a)
	}
	fmt.Fprintf(s, "swap %s %s\n", name, tmp)
	fmt.Fprintf(s, "destroy %s\n", tmp)
}

// rebuildChain replaces the WEBBLOCK chain for a family using a single
// iptables-restore (with --noflush so other firewall rules are untouched), then
// ensures OUTPUT jumps to it exactly once.
func (b *iptablesBackend) rebuildChain(f family, uids []int) error {
	var s strings.Builder
	s.WriteString("*filter\n")
	// Declare and flush only our own chain; --noflush leaves everything else.
	fmt.Fprintf(&s, ":%s - [0:0]\n", ipChain)
	fmt.Fprintf(&s, "-F %s\n", ipChain)
	// Global drop.
	fmt.Fprintf(&s, "-A %s -m set --match-set %s dst -j DROP\n", ipChain, b.setName(f, "g"))
	// Per-user drops.
	for _, uid := range uids {
		fmt.Fprintf(&s, "-A %s -m owner --uid-owner %d -m set --match-set %s dst -j DROP\n",
			ipChain, uid, b.setName(f, uidToken(uid)))
	}
	s.WriteString("COMMIT\n")

	if err := runStdin(f.restore, []string{"--noflush"}, s.String()); err != nil {
		return err
	}

	// Ensure OUTPUT jumps to WEBBLOCK exactly once (idempotent, O(1)).
	if run(f.cmd, "-C", "OUTPUT", "-j", ipChain) != nil {
		if err := run(f.cmd, "-I", "OUTPUT", "1", "-j", ipChain); err != nil {
			return err
		}
	}
	return nil
}

func (b *iptablesBackend) setName(f family, token string) string {
	// e.g. webblk_g_4, webblk_u1000_4 (kept under ipset's 31-char limit).
	return fmt.Sprintf("%s%s_%s", setPrefix, token, f.suffix)
}

func uidToken(uid int) string { return fmt.Sprintf("u%d", uid) }

func (b *iptablesBackend) Teardown() error {
	b.last = nil
	for _, f := range []family{v4, v6} {
		// Detach and remove the chain.
		_ = run(f.cmd, "-D", "OUTPUT", "-j", ipChain)
		_ = run(f.cmd, "-F", ipChain)
		_ = run(f.cmd, "-X", ipChain)
	}
	// Destroy all of our ipsets.
	names, err := listIpsets()
	if err != nil {
		return err
	}
	for _, n := range names {
		if strings.HasPrefix(n, setPrefix) {
			_ = run("ipset", "destroy", n)
		}
	}
	return nil
}

func listIpsets() ([]string, error) {
	out, err := exec.Command("ipset", "list", "-n").Output()
	if err != nil {
		return nil, fmt.Errorf("ipset list: %w", err)
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if l := strings.TrimSpace(line); l != "" {
			names = append(names, l)
		}
	}
	return names, nil
}

// run executes a command, returning an error that includes stderr on failure.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// runStdin executes a command feeding payload on stdin (for the *-restore tools).
func runStdin(name string, args []string, payload string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
