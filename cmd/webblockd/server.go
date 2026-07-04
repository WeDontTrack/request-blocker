package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"webblock/internal/proto"
)

// Server is the transport layer: it owns the Unix socket, reads each caller's
// kernel-verified identity, decodes one request, applies rate limiting, and
// hands the request to the Dispatcher. It contains no per-action logic.
type Server struct {
	cfg        Config
	dispatcher *Dispatcher
	limiter    *rateLimiter
	logf       Logger
}

// NewServer constructs a transport Server from configuration.
func NewServer(cfg Config, dispatcher *Dispatcher, logf Logger) *Server {
	return &Server{
		cfg:        cfg,
		dispatcher: dispatcher,
		limiter:    newRateLimiter(cfg.RateLimit, cfg.RateWindow),
		logf:       logf,
	}
}

// Run listens and serves until ctx is cancelled. Cancellation closes the
// listener, which unblocks Accept and returns nil.
func (s *Server) Run(ctx context.Context) error {
	if err := os.Remove(s.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.SocketPath, err)
	}
	defer ln.Close()

	// Connecting is open to all local users; authorization is enforced per
	// request from peer credentials, so the socket itself need not be guarded.
	if err := os.Chmod(s.cfg.SocketPath, s.cfg.SocketMode); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	s.logf("listening on %s", s.cfg.SocketPath)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // expected: listener closed on shutdown
			}
			return err
		}
		go s.serve(ctx, conn.(*net.UnixConn))
	}
}

// serve handles a single connection: authenticate, decode, rate-limit, dispatch.
func (s *Server) serve(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.ConnDeadline))

	cred, err := getPeerCred(conn)
	if err != nil {
		s.logf("peer cred error: %v", err)
		writeResponse(conn, proto.Response{Error: "could not determine caller identity"})
		return
	}

	var req proto.Request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		writeResponse(conn, proto.Response{Error: "malformed request"})
		return
	}

	if !s.limiter.allow(cred.UID) {
		writeResponse(conn, proto.Response{Error: "rate limit exceeded, slow down"})
		return
	}

	writeResponse(conn, s.dispatcher.Dispatch(ctx, cred, req))
}

// writeResponse marshals and writes a newline-terminated JSON response.
func writeResponse(conn net.Conn, resp proto.Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(data, '\n'))
}
