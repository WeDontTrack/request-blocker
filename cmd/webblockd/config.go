package main

import (
	"os"
	"time"

	"webblock/internal/proto"
	"webblock/internal/store"
)

// Logger is the logging contract used throughout the daemon. Business logic
// depends on this type rather than the global log package so output can be
// redirected and tested.
type Logger func(format string, args ...any)

// Config holds every tunable for the daemon in one place. There are no magic
// timeouts, limits, or modes scattered through the code: all of them live here
// (see docs/STANDARDS.md section 3).
type Config struct {
	// SocketPath is where the daemon listens for client connections.
	SocketPath string
	// StoreDir is the root directory for persisted blocklists.
	StoreDir string
	// RefreshInterval is how often the refresh loop wakes to re-resolve expired
	// domains and reapply rules.
	RefreshInterval time.Duration
	// DNSCacheTTL is how long a resolved domain is considered fresh; the refresh
	// loop only re-resolves entries older than this, smoothing DNS load.
	DNSCacheTTL time.Duration
	// ResolveTimeout bounds a single DNS lookup.
	ResolveTimeout time.Duration
	// ResolveConcurrency caps the number of concurrent DNS lookups per rebuild.
	ResolveConcurrency int
	// ConnDeadline bounds the lifetime of a single client connection.
	ConnDeadline time.Duration
	// SocketMode is the permission bits for the listening socket. Connecting is
	// intentionally open; authorization is enforced from peer credentials.
	SocketMode os.FileMode
	// RateLimit / RateWindow form a fixed-window per-uid request limiter.
	RateLimit  int
	RateWindow time.Duration
}

// DefaultConfig returns the standard configuration. Flag parsing overrides
// individual fields on top of these defaults.
func DefaultConfig() Config {
	return Config{
		SocketPath:         proto.SocketPath,
		StoreDir:           store.DefaultDir,
		RefreshInterval:    5 * time.Minute,
		DNSCacheTTL:        15 * time.Minute,
		ResolveTimeout:     5 * time.Second,
		ResolveConcurrency: 12,
		ConnDeadline:       30 * time.Second,
		SocketMode:         0o666,
		RateLimit:          20,
		RateWindow:         10 * time.Second,
	}
}
