package sshserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

func TestRegistry(t *testing.T) {
	now := time.Now()
	base := cfapi.Registration{ID: "reg", Device: cfapi.RegistrationDevice{ID: "dev", Name: "physical-name"}, User: cfapi.User{Email: "alice@example.com"}, VirtualIPv4: "100.96.0.3", VirtualIPv6: "2606:4700:cf1:1000::3", RegistrationType: "warp"}
	regs := []cfapi.Registration{base}
	fail, calls := false, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.Method != "GET" {
			t.Error("identity lookup attempted a write")
		}
		if fail {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var result any
		switch req.URL.Path {
		case "/accounts/a/devices/registrations":
			result = regs
		case "/accounts/a/warp_connector":
			result = []cfapi.MeshNode{{ID: "node", Name: "laptop"}}
		case "/accounts/a/warp_connector/node/connections":
			result = []cfapi.MeshConnector{{ID: "reg"}}
		default:
			t.Errorf("unexpected request %s", req.URL)
			http.Error(w, "unexpected", 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer api.Close()
	client := cfapi.New(cfapi.StaticToken("test"), "test")
	client.BaseURL = api.URL
	registry := &Registry{API: client, Account: "a"}
	lookup := func(ip string) (Identity, error) {
		return registry.Lookup(context.Background(), netip.MustParseAddr(ip))
	}
	id, err := lookup("100.96.0.3")
	if err != nil || id.Device != "laptop" || id.Owner != "alice@example.com" || id.DeviceID != "dev" {
		t.Fatalf("identity: %#v, %v", id, err)
	}
	initialCalls := calls
	if _, err := lookup("2606:4700:cf1:1000::3"); err != nil || calls != initialCalls {
		t.Fatalf("cache: calls=%d err=%v", calls, err)
	}
	for _, ip := range []string{"100.96.0.4", "127.0.0.1", "100.64.0.1", "2606:4700:cf1:2000::1", "100.112.0.1"} {
		if _, err := lookup(ip); err == nil {
			t.Errorf("accepted unknown/out-of-range IP %s", ip)
		}
	}
	for _, change := range []func(){
		func() { regs = []cfapi.Registration{base, base} },
		func() { r := base; r.RevokedAt = &now; regs = []cfapi.Registration{r} },
		func() { r := base; r.DeletedAt = &now; regs = []cfapi.Registration{r} },
		func() { r := base; r.RegistrationType = "browser"; regs = []cfapi.Registration{r} },
		func() { r := base; r.Device.ID = ""; regs = []cfapi.Registration{r} },
	} {
		change()
		registry.expires = time.Time{}
		if _, err := lookup("100.96.0.3"); err == nil {
			t.Errorf("accepted invalid registrations: %+v", regs)
		}
	}
	regs = []cfapi.Registration{base}
	registry.expires = time.Time{}
	if _, err := lookup("100.96.0.3"); err != nil {
		t.Fatal(err)
	}
	fail = true
	registry.expires = time.Time{}
	for range 2 {
		if _, err := lookup("100.96.0.3"); err == nil {
			t.Fatal("used stale identity after API failure")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Lookup(ctx, netip.MustParseAddr("100.96.0.3")); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestMeshRanges(t *testing.T) {
	for _, ip := range []string{"100.96.0.1", "100.111.255.255", "2606:4700:cf1:1000::2", "::ffff:100.96.0.3"} {
		if !meshaddr.IsDevice(netip.MustParseAddr(ip)) {
			t.Error(fmt.Sprint("rejected device IP ", ip))
		}
	}
	if meshaddr.IsDevice(netip.MustParseAddr("2606:4700:cf1:1000::2%eth0")) {
		t.Fatal("accepted zoned address")
	}
	if _, err := Listen([]netip.Addr{netip.MustParseAddr("0.0.0.0")}, 22); err == nil {
		t.Fatal("accepted wildcard listen")
	}
	if _, err := Listen([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, 22); err == nil {
		t.Fatal("accepted non-Mesh listen")
	}
}
