package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/service"
)

func TestPingUsesWarmInventoryWithoutAPICredentials(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	dir, err := config.ServiceDir()
	if err != nil {
		t.Fatal(err)
	}
	cache := service.NewInventoryCache(func(context.Context) ([]service.Device, error) {
		return []service.Device{{ID: "peer", Kind: "node", Name: "peer", IPv4: "100.96.0.2"}}, nil
	})
	if _, err := cache.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctrl := &service.Control{Inventory: cache, Proxies: &service.Proxies{}}
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	defer func() { cancel(); <-done }()
	<-ready
	// An invalid destination exercises the real resolution path without dialing
	// the host network. Credentials must not mask the target validation error.
	err = runPing(ctx, []string{"127.0.0.1"})
	if err == nil || !strings.Contains(err.Error(), "outside the Mesh") {
		t.Fatalf("warm inventory unexpectedly needed the API: %v", err)
	}
}
