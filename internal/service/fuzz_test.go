package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/reachability"
)

type replyProber struct{}

func (replyProber) Probe(context.Context, netip.Addr) error { return nil }

// startControl serves a Control on a private socket for the test's lifetime.
func startControl(tb testing.TB, ctrl *Control) (dir string, client *http.Client) {
	tb.Helper()
	dir, err := os.MkdirTemp("", "ms-control-")
	if err != nil {
		tb.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	tb.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			tb.Error(err)
		}
		os.RemoveAll(dir)
	})
	select {
	case <-ready:
	case err := <-done:
		tb.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", Socket(dir))
	}}
	tb.Cleanup(transport.CloseIdleConnections)
	return dir, &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// FuzzControlSocket sends arbitrary requests to every local control handler.
// None may panic or fail with a server error, and the daemon keeps serving.
func FuzzControlSocket(f *testing.F) {
	proxies := &Proxies{Listen: func(context.Context, int) ([]net.Listener, error) { return nil, errors.New("not connected") }}
	inventory := NewInventoryCache(func(context.Context) ([]Device, error) {
		return []Device{{ID: "a", Kind: "device", Name: "laptop\x1b[2J"}}, nil
	})
	ctrl := &Control{
		Proxies: proxies, Inventory: inventory, Reachability: reachability.New(replyProber{}),
		SetSSH: func(context.Context, bool) error { return nil },
	}
	_, client := startControl(f, ctrl)
	for _, seed := range []struct{ method, path, body string }{
		{"GET", "/status", ""},
		{"POST", "/reachability", `["100.96.0.1","2606:4700:cf1:1000::1"]`},
		{"POST", "/reachability", `["1.1.1.1"]`},
		{"POST", "/reachability", "[" + strings.Repeat(`"100.96.0.1",`, 5000) + `"100.96.0.1"]`},
		{"GET", "/devices", ""},
		{"POST", "/devices", "{}"},
		{"PUT", "/ssh", `{"enabled":true}`},
		{"PUT", "/ssh", `{"enabled":true}{"enabled":false}`},
		{"PUT", "/serve", `{"port":80,"mesh_port":8080}`},
		{"PUT", "/serve", `{"port":0}`},
		{"GET", "/serve", ""},
		{"DELETE", "/serve", ""},
		{"GET", "/../status", ""},
	} {
		f.Add(seed.method, seed.path, []byte(seed.body))
	}
	f.Fuzz(func(t *testing.T, method, path string, body []byte) {
		req, err := http.NewRequest(method, "http://meshscale"+path, bytes.NewReader(body))
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			return // malformed request lines are rejected by the client or server
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 500 && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusBadGateway && !(method == "DELETE" && req.URL.Path == "/serve") {
			t.Fatalf("%s %q: HTTP %d", method, path, resp.StatusCode)
		}
		health, err := client.Get("http://meshscale/status")
		if err != nil {
			t.Fatalf("daemon stopped serving after %s %q: %v", method, path, err)
		}
		health.Body.Close()
	})
}

// An inventory for a large account must reach status and the macOS app; the
// client's response bound has to fit 10,000 devices.
func TestRequestReadsLargeInventory(t *testing.T) {
	devices := make([]Device, 10000)
	for i := range devices {
		devices[i] = Device{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), RegistrationID: fmt.Sprintf("10000000-0000-4000-8000-%012d", i), DeviceID: fmt.Sprintf("20000000-0000-4000-8000-%012d", i),
			Kind: "device", Name: fmt.Sprintf("device-%d", i), DNSName: fmt.Sprintf("device-%d.mesh", i), OwnerEmail: "someone@example.com", User: "someone@example.com",
			IPv4: "100.96.0.1", IPv6: "2606:4700:cf1:1000::1", OS: "macOS", OnlineSource: "cloudflare"}
	}
	inventory := NewInventoryCache(func(context.Context) ([]Device, error) { return devices, nil })
	if _, err := inventory.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	dir, _ := startControl(t, &Control{Inventory: inventory, Proxies: &Proxies{}})
	var got Inventory
	if err := Request(t.Context(), dir, "GET", "/devices", nil, &got); err != nil || len(got.Devices) != len(devices) {
		t.Fatalf("read %d of %d devices: %v", len(got.Devices), len(devices), err)
	}
}
