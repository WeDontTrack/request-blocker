package main

import (
	"sync"
	"time"
)

// rateLimiter is a simple fixed-window per-uid request limiter. It guards the
// privileged daemon against a single user flooding it with requests.
type rateLimiter struct {
	mu     sync.Mutex // protects counts
	limit  int
	window time.Duration
	counts map[uint32]*windowCount
}

type windowCount struct {
	start time.Time
	n     int
}

// newRateLimiter returns a limiter allowing limit requests per window per uid.
func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, counts: make(map[uint32]*windowCount)}
}

// allow records a request from uid and reports whether it is within the limit.
func (r *rateLimiter) allow(uid uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	wc, ok := r.counts[uid]
	if !ok || now.Sub(wc.start) > r.window {
		r.counts[uid] = &windowCount{start: now, n: 1}
		return true
	}
	if wc.n >= r.limit {
		return false
	}
	wc.n++
	return true
}
