package main

import (
	"context"
	"net"
	"sync"
	"time"

	"webblock/internal/backend"
	"webblock/internal/resolver"
	"webblock/internal/store"
)

// resolveMode controls which domains a Rebuild re-resolves.
type resolveMode int

const (
	// resolveMissing resolves only domains absent from the cache (used by
	// interactive add/remove, where at most the newly added domains are new).
	resolveMissing resolveMode = iota
	// resolveExpired additionally re-resolves domains whose cached resolution
	// has passed its TTL (used by the periodic refresh).
	resolveExpired
	// resolveAll re-resolves every domain (used on startup reconcile).
	resolveAll
)

// cacheEntry is a resolved domain plus the time its resolution goes stale. The
// expiry is time-based: Go's stdlib resolver does not expose DNS TTLs, so this
// is a configurable freshness window rather than the authoritative record TTL.
type cacheEntry struct {
	res     resolver.Resolved
	expires time.Time
}

// Engine owns the persisted store, the resolved-address cache, and the firewall
// backend. It is the single place that turns the persisted blocklists into live
// firewall state.
//
// Locking discipline (see docs/STANDARDS.md section 10): mu guards the cache and
// serializes the apply step. DNS resolution is performed without holding mu so a
// slow refresh never blocks interactive add/remove operations. The store is
// loaded under mu before applying so concurrent updates are never lost.
type Engine struct {
	store       *store.Store
	res         *resolver.Resolver
	be          backend.Backend
	concurrency int
	ttl         time.Duration

	mu    sync.Mutex             // guards cache and serializes Apply
	cache map[string]cacheEntry  // domain -> last good resolution + expiry
	logf  Logger
}

// NewEngine constructs an Engine. concurrency bounds parallel DNS lookups and
// ttl is how long a resolution is considered fresh before the periodic refresh
// re-resolves it.
func NewEngine(st *store.Store, res *resolver.Resolver, be backend.Backend, concurrency int, ttl time.Duration, logf Logger) *Engine {
	if concurrency < 1 {
		concurrency = 1
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Engine{
		store:       st,
		res:         res,
		be:          be,
		concurrency: concurrency,
		ttl:         ttl,
		cache:       make(map[string]cacheEntry),
		logf:        logf,
	}
}

// BackendName returns the active firewall backend's name.
func (e *Engine) BackendName() string { return e.be.Name() }

// AddEntries adds domains and IPs to a scope and reapplies the firewall. It
// returns the number of domains and IPs that were actually new.
func (e *Engine) AddEntries(ctx context.Context, scope store.Scope, domains, ips []string) (addedDomains, addedIPs int, err error) {
	if err = e.store.Mutate(scope, func(bl *store.BlockList) error {
		addedDomains = bl.AddDomains(domains)
		addedIPs = bl.AddIPs(ips)
		return nil
	}); err != nil {
		return 0, 0, err
	}
	return addedDomains, addedIPs, e.Rebuild(ctx, resolveMissing)
}

// RemoveEntries removes domains and IPs from a scope and reapplies the firewall.
// It returns the number of domains and IPs that were actually removed.
func (e *Engine) RemoveEntries(ctx context.Context, scope store.Scope, domains, ips []string) (removedDomains, removedIPs int, err error) {
	if err = e.store.Mutate(scope, func(bl *store.BlockList) error {
		removedDomains = bl.RemoveDomains(domains)
		removedIPs = bl.RemoveIPs(ips)
		return nil
	}); err != nil {
		return 0, 0, err
	}
	return removedDomains, removedIPs, e.Rebuild(ctx, resolveMissing)
}

// Load returns the stored blocklist for a scope.
func (e *Engine) Load(scope store.Scope) (store.BlockList, error) {
	return e.store.Load(scope)
}

// ListUserUIDs returns uids that have a stored blocklist.
func (e *Engine) ListUserUIDs() ([]int, error) {
	return e.store.ListUserUIDs()
}

// Rebuild recomputes the desired firewall state from the store and applies it.
//
// Fast path: when no domain needs resolving (the common case for IP-only
// changes, removals, and refreshes where nothing has expired) the store is
// loaded once under the lock and applied immediately. Only when resolution is
// actually required do we release the lock to resolve, then re-read the store
// under the lock and apply - so a concurrent change is never lost.
func (e *Engine) Rebuild(ctx context.Context, mode resolveMode) error {
	e.mu.Lock()
	global, userLists, err := e.loadAll()
	if err != nil {
		e.mu.Unlock()
		return err
	}
	toResolve := e.domainsToResolveLocked(wantedDomains(global, userLists), mode)
	if len(toResolve) == 0 {
		// Fast path: single load, no off-lock resolution needed.
		err := e.buildAndApplyLocked(global, userLists)
		e.mu.Unlock()
		return err
	}
	e.mu.Unlock()

	// Resolve without holding the lock so interactive requests are not blocked.
	resolved, failures := e.res.ResolveMany(ctx, toResolve, e.concurrency)

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	for d, r := range resolved {
		e.cache[d] = cacheEntry{res: r, expires: now.Add(e.ttl)}
	}

	// Re-read under the lock so we never apply a state that lost a concurrent
	// update committed to the store between resolution and apply.
	global, userLists, err = e.loadAll()
	if err != nil {
		return err
	}
	wanted := wantedDomains(global, userLists)
	for d, ferr := range failures {
		if !wanted[d] {
			continue
		}
		if _, had := e.cache[d]; had {
			e.logf("resolve %q failed, keeping previous addresses: %v", d, ferr)
		} else {
			e.logf("resolve %q failed, no addresses yet: %v", d, ferr)
		}
	}
	return e.buildAndApplyLocked(global, userLists)
}

// buildAndApplyLocked prunes the cache to the wanted domains, builds the desired
// firewall state, and applies it. The caller must hold e.mu.
func (e *Engine) buildAndApplyLocked(global store.BlockList, userLists map[int]store.BlockList) error {
	wanted := wantedDomains(global, userLists)
	for d := range e.cache {
		if !wanted[d] {
			delete(e.cache, d)
		}
	}

	state := backend.State{
		Global:  e.ipSetForLocked(global),
		PerUser: make(map[int]backend.IPSet, len(userLists)),
	}
	for uid, bl := range userLists {
		set := e.ipSetForLocked(bl)
		if !set.Empty() { // omit users with nothing to block
			state.PerUser[uid] = set
		}
	}
	return e.be.Apply(state)
}

// domainsToResolveLocked returns the wanted domains that need resolving for the
// given mode. The caller must hold e.mu.
func (e *Engine) domainsToResolveLocked(wanted map[string]bool, mode resolveMode) []string {
	now := time.Now()
	var out []string
	for d := range wanted {
		entry, ok := e.cache[d]
		switch {
		case !ok:
			out = append(out, d)
		case mode == resolveAll:
			out = append(out, d)
		case mode == resolveExpired && now.After(entry.expires):
			out = append(out, d)
		}
	}
	return out
}

// loadAll reads the global list and every user list from the store.
func (e *Engine) loadAll() (store.BlockList, map[int]store.BlockList, error) {
	global, err := e.store.Load(store.GlobalScope)
	if err != nil {
		return store.BlockList{}, nil, err
	}
	uids, err := e.store.ListUserUIDs()
	if err != nil {
		return store.BlockList{}, nil, err
	}
	userLists := make(map[int]store.BlockList, len(uids))
	for _, uid := range uids {
		bl, err := e.store.Load(store.UserScope(uid))
		if err != nil {
			return store.BlockList{}, nil, err
		}
		userLists[uid] = bl
	}
	return global, userLists, nil
}

// ipSetForLocked combines a blocklist's explicit IPs with the resolved addresses
// of its domains. The caller must hold e.mu (it reads the cache).
func (e *Engine) ipSetForLocked(bl store.BlockList) backend.IPSet {
	v4 := map[string]bool{}
	v6 := map[string]bool{}

	for _, ip := range bl.IPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			if p4 := parsed.To4(); p4 != nil {
				v4[p4.String()] = true
			} else {
				v6[parsed.String()] = true
			}
		}
	}
	for _, d := range bl.Domains {
		entry, ok := e.cache[d]
		if !ok {
			continue
		}
		for _, a := range entry.res.V4 {
			v4[a] = true
		}
		for _, a := range entry.res.V6 {
			v6[a] = true
		}
	}
	return backend.IPSet{V4: keys(v4), V6: keys(v6)}
}

// RefreshLoop periodically re-resolves expired domains and reapplies the
// firewall until ctx is cancelled.
func (e *Engine) RefreshLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.Rebuild(ctx, resolveExpired); err != nil {
				e.logf("periodic refresh failed: %v", err)
			}
		}
	}
}

// wantedDomains returns the union of all domains across the global and per-user
// blocklists.
func wantedDomains(global store.BlockList, userLists map[int]store.BlockList) map[string]bool {
	wanted := make(map[string]bool)
	for _, d := range global.Domains {
		wanted[d] = true
	}
	for _, bl := range userLists {
		for _, d := range bl.Domains {
			wanted[d] = true
		}
	}
	return wanted
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
