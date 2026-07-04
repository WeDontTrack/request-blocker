// Package resolver turns domain names into the IPv4/IPv6 addresses that the
// firewall backend actually blocks. Because CDN addresses drift over time, the
// daemon re-resolves periodically and re-applies the firewall state.
package resolver

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// Resolved holds the addresses a domain currently maps to.
type Resolved struct {
	V4 []string
	V6 []string
}

// Resolver looks up addresses for domains with a bounded per-lookup timeout.
type Resolver struct {
	r       *net.Resolver
	timeout time.Duration
}

// New returns a Resolver using the system resolver and the given per-lookup
// timeout. A zero timeout defaults to 5 seconds.
func New(timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{r: &net.Resolver{}, timeout: timeout}
}

// Resolve looks up a single domain. A lookup error yields an empty result and
// the error; callers typically keep the previous addresses on failure.
func (r *Resolver) Resolve(ctx context.Context, domain string) (Resolved, error) {
	lctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ips, err := r.r.LookupIP(lctx, "ip", domain)
	if err != nil {
		return Resolved{}, err
	}
	var res Resolved
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			res.V4 = append(res.V4, v4.String())
		} else {
			res.V6 = append(res.V6, ip.String())
		}
	}
	res.V4 = sortedUnique(res.V4)
	res.V6 = sortedUnique(res.V6)
	return res, nil
}

// ResolveMany resolves a list of domains concurrently, bounded by concurrency
// workers. Successful lookups land in results; failures are reported separately
// so the caller can decide whether to retain prior addresses. The work respects
// ctx cancellation. Resolution is intentionally lock-free so callers can run it
// without holding their own state locks (see docs/STANDARDS.md section 10).
func (r *Resolver) ResolveMany(ctx context.Context, domains []string, concurrency int) (results map[string]Resolved, failures map[string]error) {
	results = make(map[string]Resolved, len(domains))
	failures = make(map[string]error)
	if len(domains) == 0 {
		return results, failures
	}
	if concurrency < 1 {
		concurrency = 1
	}

	type outcome struct {
		domain string
		res    Resolved
		err    error
	}
	jobs := make(chan string)
	out := make(chan outcome)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				res, err := r.Resolve(ctx, d)
				out <- outcome{domain: d, res: res, err: err}
			}
		}()
	}
	go func() {
		for _, d := range domains {
			jobs <- d
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	for o := range out {
		if o.err != nil {
			failures[o.domain] = o.err
			continue
		}
		results[o.domain] = o.res
	}
	return results, failures
}

func sortedUnique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
