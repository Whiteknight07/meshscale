package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/service"
)

func TestDaemonInventoryPreferredWithoutCredentials(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := config.ServiceDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	cache := service.NewInventoryCache(func(context.Context) ([]service.Device, error) {
		calls++
		return []service.Device{{ID: "registration", Name: "laptop", ThisMachine: true, OffersExit: true, Secure: &secure.PeerStatus{Peer: secure.Peer{PublicKey: "key"}}}}, nil
	})
	if _, err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctrl := &service.Control{Inventory: cache, Proxies: &service.Proxies{}}
	ctrl.Update(func(s *service.Status) {
		s.Connection.Connected = true
		s.Connection.State = "connected"
		s.Secure.ExitState = "blocked"
		s.Secure.ExitNode = "exit"
	})
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("socket did not start")
	}
	for _, refresh := range []bool{false, true} {
		devices, reachable, err := daemonDevices(ctx, refresh)
		if err != nil || !reachable || len(devices) != 1 {
			t.Fatal(devices, reachable, err)
		}
		if !devices[0].Online || devices[0].ExitState != "blocked" || devices[0].OnlineSource != "local" {
			t.Fatal(devices)
		}
	}
	if calls != 2 {
		t.Fatalf("loads=%d", calls)
	}
	// The public entry point must also work with no account credentials.
	if err := runStatus(ctx, []string{"--json"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("cached status triggered a load: %d", calls)
	}
}

func TestDaemonInventoryFallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	devices, reachable, err := daemonDevices(context.Background(), false)
	if err != nil || reachable || devices != nil {
		t.Fatal(devices, reachable, err)
	}
	dir, _ := config.ServiceDir()
	// A reachable daemon's warming/error response must not trigger API fallback.
	cache := service.NewInventoryCache(func(context.Context) ([]service.Device, error) { return nil, nil })
	ctrl := &service.Control{Inventory: cache, Proxies: &service.Proxies{}}
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	<-ready
	if _, reachable, err := daemonDevices(ctx, false); !reachable || err == nil {
		t.Fatal(reachable, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "status.sock")); err != nil {
		t.Fatal(err)
	}
}

// After an update, the daemon keeps running the previous binary until it is
// restarted; the new CLI must still work through the API.
func TestDaemonInventoryFallsBackForOlderDaemon(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := config.ServiceDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", service.Socket(dir))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.NotFoundHandler()}
	go server.Serve(listener)
	defer server.Close()
	devices, reachable, err := daemonDevices(t.Context(), false)
	if err != nil || reachable || devices != nil {
		t.Fatal(devices, reachable, err)
	}
}
