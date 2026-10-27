package service

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/reachability"
)

type serviceProber struct{ calls atomic.Int32 }

func (p *serviceProber) Probe(context.Context, netip.Addr) error { p.calls.Add(1); return nil }

func TestReachabilityValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		enabled    bool
		want       int
	}{
		{"valid", `["100.96.0.1"]`, true, 200},
		{"outside mesh", `["127.0.0.1"]`, true, 400},
		{"malformed", `[`, true, 400},
		{"invalid IP", `["phone.mesh"]`, true, 400},
		{"unavailable", `[]`, false, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Control
			if tc.enabled {
				c.Reachability = reachability.New(&serviceProber{})
			}
			w := httptest.NewRecorder()
			c.checkReachability(w, httptest.NewRequest(http.MethodPost, "/reachability", bytes.NewBufferString(tc.body)))
			if w.Code != tc.want {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
		})
	}
}

func TestDaemonReachabilityCacheAcrossRequests(t *testing.T) {
	p := &serviceProber{}
	c := &Control{Reachability: reachability.New(p)}
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	go func() { done <- c.Run(ctx, dir, ready) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("control startup: %v", err)
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for range 3 {
		var got map[string]bool
		if err := Request(context.Background(), dir, http.MethodPost, "/reachability", []string{"100.96.0.1"}, &got); err != nil {
			t.Fatal(err)
		}
		if !got["100.96.0.1"] {
			t.Fatal(got)
		}
	}
	if p.calls.Load() != 1 {
		t.Fatalf("polling caused %d probes", p.calls.Load())
	}
}
