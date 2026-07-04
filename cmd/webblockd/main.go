// Command webblockd is the privileged daemon that owns the firewall rules and
// the persisted blocklists. It runs as root (typically under systemd), listens
// on a Unix socket, and applies changes requested by the unprivileged webblock
// client after authenticating callers via SO_PEERCRED.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"webblock/internal/backend"
	"webblock/internal/resolver"
	"webblock/internal/store"
)

func main() {
	cfg := DefaultConfig()

	flag.StringVar(&cfg.SocketPath, "socket", cfg.SocketPath, "Unix socket path to listen on")
	flag.StringVar(&cfg.StoreDir, "store", cfg.StoreDir, "directory for persisted blocklists")
	flag.DurationVar(&cfg.RefreshInterval, "refresh", cfg.RefreshInterval, "how often the refresh loop wakes to re-resolve expired domains")
	flag.DurationVar(&cfg.DNSCacheTTL, "dns-ttl", cfg.DNSCacheTTL, "how long a resolved domain stays fresh before re-resolution")
	flag.DurationVar(&cfg.ResolveTimeout, "resolve-timeout", cfg.ResolveTimeout, "per-domain DNS lookup timeout")
	flag.IntVar(&cfg.ResolveConcurrency, "resolve-concurrency", cfg.ResolveConcurrency, "max concurrent DNS lookups per rebuild")
	teardown := flag.Bool("teardown", false, "remove all firewall rules/sets owned by webblock and exit")
	flag.Parse()

	logger := log.New(os.Stderr, "webblockd: ", log.LstdFlags)
	logf := Logger(logger.Printf)

	be, err := backend.Detect()
	if err != nil {
		logger.Fatalf("backend detection failed: %v", err)
	}

	if *teardown {
		if err := be.Teardown(); err != nil {
			logger.Fatalf("teardown failed: %v", err)
		}
		logger.Printf("removed all webblock firewall rules (%s)", be.Name())
		return
	}

	st, err := store.New(cfg.StoreDir)
	if err != nil {
		logger.Fatalf("store init failed: %v", err)
	}

	eng := NewEngine(st, resolver.New(cfg.ResolveTimeout), be, cfg.ResolveConcurrency, cfg.DNSCacheTTL, logf)

	// Reconcile persisted state into the live firewall on startup.
	if err := eng.Rebuild(context.Background(), resolveAll); err != nil {
		logger.Fatalf("initial firewall reconcile failed: %v", err)
	}
	logf("reconciled blocklists into firewall (backend: %s)", be.Name())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go eng.RefreshLoop(ctx, cfg.RefreshInterval)

	// Firewall rules are intentionally left in place on shutdown so blocks
	// persist across restarts; use -teardown to remove them explicitly.
	dispatcher := NewDispatcher(eng, logf)
	srv := NewServer(cfg, dispatcher, logf)

	if err := srv.Run(ctx); err != nil {
		logger.Fatalf("server error: %v", err)
	}
	logger.Printf("shutting down")
}
