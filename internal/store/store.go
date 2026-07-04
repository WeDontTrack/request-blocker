// Package store persists blocklists to a root-owned directory tree. Privacy
// between users is enforced by the daemon's access control, not solely by file
// permissions, but the directory is created 0700 as defense in depth.
//
// Layout:
//
//	/var/lib/webblock/
//	  global.json          # root-managed, applies to all users
//	  users/
//	    1000.json          # per-uid blocklist
//	    1001.json
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DefaultDir is the on-disk root for persisted configuration.
const DefaultDir = "/var/lib/webblock"

// Scope identifies a blocklist: either the global one or a specific user's.
type Scope struct {
	Global bool
	UID    int
}

// GlobalScope is the system-wide blocklist managed by root.
var GlobalScope = Scope{Global: true}

// UserScope returns the scope for a given uid.
func UserScope(uid int) Scope { return Scope{UID: uid} }

// Label returns a human-readable identifier for the scope.
func (s Scope) Label() string {
	if s.Global {
		return "global"
	}
	return fmt.Sprintf("user:%d", s.UID)
}

// BlockList is the set of domains and IPs blocked within a scope. Entries are
// kept sorted and de-duplicated.
type BlockList struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}

// Clone returns a deep copy of the blocklist.
func (b BlockList) Clone() BlockList {
	return BlockList{
		Domains: append([]string(nil), b.Domains...),
		IPs:     append([]string(nil), b.IPs...),
	}
}

// Store reads and writes blocklists under a base directory. It is safe for
// concurrent use.
type Store struct {
	dir string
	mu  sync.Mutex
}

// New creates a Store rooted at dir, creating the directory tree if needed.
func New(dir string) (*Store, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if err := os.MkdirAll(filepath.Join(dir, "users"), 0o700); err != nil {
		return nil, fmt.Errorf("create store dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(scope Scope) string {
	if scope.Global {
		return filepath.Join(s.dir, "global.json")
	}
	return filepath.Join(s.dir, "users", strconv.Itoa(scope.UID)+".json")
}

// Load returns the blocklist for a scope. A missing file yields an empty list.
func (s *Store) Load(scope Scope) (BlockList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(scope)
}

func (s *Store) loadLocked(scope Scope) (BlockList, error) {
	var bl BlockList
	data, err := os.ReadFile(s.path(scope))
	if err != nil {
		if os.IsNotExist(err) {
			return BlockList{Domains: []string{}, IPs: []string{}}, nil
		}
		return bl, fmt.Errorf("read %s: %w", scope.Label(), err)
	}
	if err := json.Unmarshal(data, &bl); err != nil {
		return bl, fmt.Errorf("parse %s: %w", scope.Label(), err)
	}
	if bl.Domains == nil {
		bl.Domains = []string{}
	}
	if bl.IPs == nil {
		bl.IPs = []string{}
	}
	return bl, nil
}

// save writes a blocklist atomically (write temp + rename).
func (s *Store) saveLocked(scope Scope, bl BlockList) error {
	bl.Domains = sortedUnique(bl.Domains)
	bl.IPs = sortedUnique(bl.IPs)

	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", scope.Label(), err)
	}
	final := s.path(scope)
	tmp, err := os.CreateTemp(filepath.Dir(final), ".tmp-*")
	if err != nil {
		return fmt.Errorf("temp file for %s: %w", scope.Label(), err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", scope.Label(), err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", scope.Label(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", scope.Label(), err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("rename %s: %w", scope.Label(), err)
	}
	return nil
}

// Mutate loads a scope, applies fn to a mutable copy, and saves the result
// atomically. The whole operation holds the store lock.
func (s *Store) Mutate(scope Scope, fn func(*BlockList) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bl, err := s.loadLocked(scope)
	if err != nil {
		return err
	}
	if err := fn(&bl); err != nil {
		return err
	}
	return s.saveLocked(scope, bl)
}

// ListUserUIDs returns the uids that have a stored blocklist file.
func (s *Store) ListUserUIDs() ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, "users"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var uids []int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	return uids, nil
}

// AddDomains/AddIPs/RemoveDomains/RemoveIPs are convenience helpers used by the
// daemon to mutate a blocklist. They operate on a BlockList in memory.

// AddDomains adds domains to the list, returning the count actually added.
func (b *BlockList) AddDomains(domains []string) int {
	return addUnique(&b.Domains, domains)
}

// AddIPs adds IPs to the list, returning the count actually added.
func (b *BlockList) AddIPs(ips []string) int {
	return addUnique(&b.IPs, ips)
}

// RemoveDomains removes domains, returning the count actually removed.
func (b *BlockList) RemoveDomains(domains []string) int {
	return removeAll(&b.Domains, domains)
}

// RemoveIPs removes IPs, returning the count actually removed.
func (b *BlockList) RemoveIPs(ips []string) int {
	return removeAll(&b.IPs, ips)
}

func addUnique(dst *[]string, add []string) int {
	existing := make(map[string]bool, len(*dst))
	for _, v := range *dst {
		existing[v] = true
	}
	n := 0
	for _, v := range add {
		if !existing[v] {
			existing[v] = true
			*dst = append(*dst, v)
			n++
		}
	}
	*dst = sortedUnique(*dst)
	return n
}

func removeAll(dst *[]string, remove []string) int {
	toRemove := make(map[string]bool, len(remove))
	for _, v := range remove {
		toRemove[v] = true
	}
	out := (*dst)[:0]
	n := 0
	for _, v := range *dst {
		if toRemove[v] {
			n++
			continue
		}
		out = append(out, v)
	}
	*dst = sortedUnique(out)
	return n
}

func sortedUnique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
