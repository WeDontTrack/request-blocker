//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webblock/internal/backend"
	"webblock/internal/proto"
	"webblock/internal/resolver"
	"webblock/internal/store"
)

// fakeBackend records the last applied state instead of touching the firewall,
// so the daemon's transport/authz/dispatch/engine/store path can be tested
// end-to-end without root or a real packet filter.
type fakeBackend struct {
	mu   sync.Mutex
	last backend.State
}

func (f *fakeBackend) Name() string { return "fake" }

func (f *fakeBackend) Apply(s backend.State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = s
	return nil
}

func (f *fakeBackend) Teardown() error { return nil }

func (f *fakeBackend) snapshot() backend.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

// newTestServer starts a daemon over a temp Unix socket with a fake backend.
func newTestServer(t *testing.T) (*fakeBackend, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fb := &fakeBackend{}
	logf := Logger(func(string, ...any) {})
	eng := NewEngine(st, resolver.New(time.Second), fb, 4, time.Minute, logf)
	if err := eng.Rebuild(context.Background(), resolveAll); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SocketPath = filepath.Join(dir, "webblock.sock")
	srv := NewServer(cfg, NewDispatcher(eng, logf), logf)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Run(ctx) }()
	t.Cleanup(cancel)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fb, cfg.SocketPath
}

func roundTrip(t *testing.T, socket string, req proto.Request) proto.Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	var resp proto.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestE2EAddIPAndShow(t *testing.T) {
	fb, socket := newTestServer(t)

	resp := roundTrip(t, socket, proto.Request{Version: proto.Version, Action: proto.ActionAdd, IPs: []string{"203.0.113.7"}})
	if !resp.OK {
		t.Fatalf("add failed: %s", resp.Error)
	}

	// The fake backend should have received the IP in the caller's scope.
	st := fb.snapshot()
	var got backend.IPSet
	if os.Geteuid() == 0 {
		got = st.Global
	} else {
		got = st.PerUser[os.Geteuid()]
	}
	if !containsStr(got.V4, "203.0.113.7") {
		t.Errorf("backend state missing IP; state=%+v euid=%d", st, os.Geteuid())
	}

	show := roundTrip(t, socket, proto.Request{Version: proto.Version, Action: proto.ActionShow})
	if !show.OK || len(show.Views) == 0 {
		t.Fatalf("show failed: %+v", show)
	}
	found := false
	for _, v := range show.Views {
		if containsStr(v.IPs, "203.0.113.7") {
			found = true
		}
	}
	if !found {
		t.Errorf("show did not include added IP: %+v", show.Views)
	}
}

func TestE2EStatus(t *testing.T) {
	_, socket := newTestServer(t)
	resp := roundTrip(t, socket, proto.Request{Version: proto.Version, Action: proto.ActionStatus})
	if !resp.OK || resp.Status == nil {
		t.Fatalf("status failed: %+v", resp)
	}
	if resp.Status.Backend != "fake" {
		t.Errorf("backend = %q, want fake", resp.Status.Backend)
	}
	if resp.Status.ProtocolVersion != proto.Version {
		t.Errorf("protocol version = %d, want %d", resp.Status.ProtocolVersion, proto.Version)
	}
}

func TestE2EUnsupportedVersionRejected(t *testing.T) {
	_, socket := newTestServer(t)
	resp := roundTrip(t, socket, proto.Request{Version: proto.Version + 1, Action: proto.ActionStatus})
	if resp.OK {
		t.Errorf("expected rejection of a future protocol version, got OK")
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
