package main

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
	"github.com/Whiteknight07/meshscale/internal/service"
)

func TestHostsModeUsesInventoryChangeHooks(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "hosts")
	original := []byte("127.0.0.1 localhost\r\n# unrelated bytes")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	snapshot := devicesync.Snapshot{Account: "test", LocalHosts: true, Devices: []devicesync.Device{{ID: "reg", Name: "peer", IPv4: "100.96.0.2"}}}
	lookups, hooks := 0, 0
	resolves := true
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		if resolves {
			return []netip.Addr{netip.MustParseAddr("100.96.0.2")}, nil
		}
		return nil, fmt.Errorf("resolver owned by another VPN")
	}
	registry := &devicesync.Registry{}
	registry.Register("hosts", func(ctx context.Context, s devicesync.Snapshot) error {
		hooks++
		return syncHostsAt(ctx, s, path, lookup)
	})
	poller := &service.Poller{Registry: registry, Load: func(context.Context) (devicesync.Snapshot, error) { return snapshot, nil }}
	if _, _, err := poller.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	if !bytes.Equal(first, original) || lookups != 1 {
		t.Fatal("auto changed a working resolver")
	}
	if _, changed, err := poller.Poll(t.Context()); err != nil || changed || hooks != 1 || lookups != 1 {
		t.Fatalf("idle inventory did work: %v", err)
	}
	resolves = false
	snapshot.Devices[0].IPv4 = "100.96.0.3"
	if _, _, err := poller.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	installed, _ := os.ReadFile(path)
	if !bytes.Contains(installed, []byte("100.96.0.3\tpeer.mesh")) {
		t.Fatalf("fallback absent: %q", installed)
	}
	snapshot.Devices[0].IPv4 = "100.96.0.4"
	if _, _, err := poller.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(path)
	if bytes.Contains(updated, []byte("100.96.0.3")) || !bytes.Contains(updated, []byte("100.96.0.4")) {
		t.Fatalf("stale inventory: %q", updated)
	}
	if lookups != 2 {
		t.Fatal("auto rechecked its own hosts entries")
	}
	if err := (&config.DNSSettings{Hosts: "off"}).Save(); err != nil {
		t.Fatal(err)
	}
	if err := syncHostsAt(t.Context(), snapshot, path, lookup); err != nil {
		t.Fatal(err)
	}
	cleaned, _ := os.ReadFile(path)
	if !bytes.Equal(cleaned, original) {
		t.Fatalf("off cleanup changed unrelated bytes: %q", cleaned)
	}
	if err := (&config.DNSSettings{Hosts: "on"}).Save(); err != nil {
		t.Fatal(err)
	}
	if err := syncHostsAt(t.Context(), snapshot, path, lookup); err != nil {
		t.Fatal(err)
	}
	if lookups != 2 {
		t.Fatal("explicit on consulted resolver")
	}
	if err := config.SetPaused(true); err != nil {
		t.Fatal(err)
	}
	if err := syncHostsAt(t.Context(), snapshot, path, lookup); err != nil {
		t.Fatal(err)
	}
	cleaned, _ = os.ReadFile(path)
	if !bytes.Equal(cleaned, original) {
		t.Fatal("paused inventory restored hosts entries")
	}
	// Account-only registry users cannot reach the real hosts file.
	if err := syncHosts(t.Context(), devicesync.Snapshot{}); err != nil {
		t.Fatal(err)
	}
}
