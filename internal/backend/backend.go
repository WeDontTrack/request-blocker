// Package backend abstracts the kernel-level egress packet filtering used to
// enforce blocklists. Two implementations are provided:
//
//   - nft (nftables): the primary backend on modern distributions.
//   - iptables (+ ipset): a fallback for systems without nft.
//
// Filtering happens on the OUTPUT path by destination IP so that it also blocks
// raw-IP traffic from tools like curl. Domains are resolved to IPs by the
// resolver before reaching the backend; the backend only ever deals in IPs.
package backend

import (
	"fmt"
	"os/exec"
	"sort"
)

// IPSet holds resolved destination addresses for a single scope, split by
// address family.
type IPSet struct {
	V4 []string
	V6 []string
}

// Empty reports whether the set contains no addresses.
func (s IPSet) Empty() bool { return len(s.V4) == 0 && len(s.V6) == 0 }

// State is the complete desired filtering state. The backend reconciles the
// live firewall to exactly match this on every Apply call (atomically).
type State struct {
	// Global addresses are dropped for every user (root-managed rules).
	Global IPSet
	// PerUser maps a uid to the addresses dropped only for that uid.
	PerUser map[int]IPSet
}

// Backend reconciles desired filtering State into the running firewall.
type Backend interface {
	// Name identifies the backend (e.g. "nftables", "iptables+ipset").
	Name() string
	// Apply makes the live firewall match state exactly. It must be atomic:
	// either the new state is fully applied or the previous state is retained.
	Apply(state State) error
	// Teardown removes all rules and sets owned by this tool.
	Teardown() error
}

// Detect selects a backend at runtime, preferring nftables. It returns an
// error only if no supported backend is available.
func Detect() (Backend, error) {
	if hasWorkingNft() {
		return newNftBackend(), nil
	}
	if hasIptablesAndIpset() {
		return newIptablesBackend(), nil
	}
	return nil, fmt.Errorf("no supported firewall backend found: need either 'nft', or 'iptables' and 'ipset'")
}

func hasWorkingNft() bool {
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	// Confirm nft can actually talk to the kernel (it cannot in some minimal
	// containers without the right modules/permissions).
	return exec.Command("nft", "list", "ruleset").Run() == nil
}

func hasIptablesAndIpset() bool {
	_, e1 := exec.LookPath("iptables")
	_, e2 := exec.LookPath("ipset")
	return e1 == nil && e2 == nil
}

// sortedUIDs returns the uids present in a per-user map in ascending order. It
// is shared by the backends so rule generation is deterministic.
func sortedUIDs(m map[int]IPSet) []int {
	uids := make([]int, 0, len(m))
	for uid := range m {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	return uids
}
