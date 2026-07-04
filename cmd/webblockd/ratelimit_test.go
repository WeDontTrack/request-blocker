package main

import (
	"testing"
	"time"
)

func TestRateLimiterWithinAndOverLimit(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)

	if !rl.allow(1000) {
		t.Fatal("first request should be allowed")
	}
	if !rl.allow(1000) {
		t.Fatal("second request should be allowed")
	}
	if rl.allow(1000) {
		t.Fatal("third request should be blocked")
	}

	// A different uid has an independent window.
	if !rl.allow(1001) {
		t.Fatal("other uid should be allowed")
	}
}

func TestRateLimiterWindowResets(t *testing.T) {
	rl := newRateLimiter(1, time.Millisecond)
	if !rl.allow(1) {
		t.Fatal("first allowed")
	}
	if rl.allow(1) {
		t.Fatal("second within window blocked")
	}
	time.Sleep(2 * time.Millisecond)
	if !rl.allow(1) {
		t.Fatal("after window should be allowed again")
	}
}
