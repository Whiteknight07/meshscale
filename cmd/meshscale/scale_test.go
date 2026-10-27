package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/names"
	"github.com/Whiteknight07/meshscale/internal/reachability"
	"github.com/Whiteknight07/meshscale/internal/service"
)

// scaleAccount serves an account the way Cloudflare paginates it: cursors for
// device lists, pages elsewhere, and per_page capped at 100.
type scaleAccount struct {
	registrations []cfapi.Registration
	physical      []cfapi.PhysicalDevice
	rules         []cfapi.GatewayRule
	requests      atomic.Int64
}

func newScaleAccount(devices, rules int) *scaleAccount {
	a := &scaleAccount{}
	seen := time.Now()
	for i := range devices {
		id := fmt.Sprintf("dev-%05d", i)
		// Half the account shares one name, as phones often do.
		name := fmt.Sprintf("laptop %d", i)
		if i%2 == 1 {
			name = "iPhone"
		}
		a.registrations = append(a.registrations, cfapi.Registration{
			ID: fmt.Sprintf("reg-%05d", i), Device: cfapi.RegistrationDevice{ID: id, Name: name},
			User: cfapi.User{Email: fmt.Sprintf("user%d@example.com", i%300)}, LastSeenAt: &seen,
			VirtualIPv4: fmt.Sprintf("100.%d.%d.%d", 96+i>>16, i>>8&255, i&255), VirtualIPv6: fmt.Sprintf("2606:4700:cf1:1000::%x", i+1),
		})
		a.physical = append(a.physical, cfapi.PhysicalDevice{ID: id, Name: name, DeviceType: "mac", LastSeenAt: &seen})
	}
	// Customer DNS rules, owned DNS rules for the first devices, and customer
	// network policies well after meshscale's precedence block.
	for i := range rules {
		r := cfapi.GatewayRule{ID: fmt.Sprintf("rule-%04d", i), Name: fmt.Sprintf("customer %d", i), Enabled: true, Action: "block", Filters: []string{"dns"}, Traffic: `dns.fqdn == "x.example"`, Precedence: int64(10000 + i)}
		switch {
		case i < 100:
			r.Filters, r.Traffic = []string{"l4"}, "net.dst.port == 25"
		case i < 600 && i-100 < devices:
			reg := a.registrations[i-100]
			r.Name, r.Description = names.RulePrefix+"stale.mesh", "Managed by meshscale DNS v1; participant=device/"+reg.ID
			r.Action, r.Traffic, r.RuleSettings.OverrideIPs = "override", `dns.fqdn == "stale.mesh"`, []string{reg.VirtualIPv4}
		}
		a.rules = append(a.rules, r)
	}
	return a
}

func (a *scaleAccount) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests.Add(1)
	if r.Method != http.MethodGet {
		http.Error(w, "read-only fixture", http.StatusMethodNotAllowed)
		return
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 100
	}
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/devices/registrations"):
		writeCursorPage(w, r, a.registrations, perPage)
	case strings.HasSuffix(path, "/devices/physical-devices"):
		writeCursorPage(w, r, a.physical, perPage)
	case strings.HasSuffix(path, "/gateway/rules"):
		writeResult(w, a.rules, nil)
	default:
		// Mesh nodes, routes, Gateway lists, SSH targets: an empty first page.
		writeResult(w, []struct{}{}, map[string]any{"page": 1, "per_page": perPage, "total_count": 0})
	}
}

func writeCursorPage[T any](w http.ResponseWriter, r *http.Request, items []T, perPage int) {
	start, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
	end := min(start+perPage, len(items))
	cursor := ""
	if end < len(items) {
		cursor = strconv.Itoa(end)
	}
	writeResult(w, append([]T{}, items[min(start, end):end]...), map[string]any{"per_page": perPage, "count": end - start, "cursor": cursor})
}

func writeResult(w http.ResponseWriter, result any, info map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result, "result_info": info})
}

type scaleResult struct {
	elapsed  time.Duration
	allocMiB float64
	requests int64
}

func measure(t *testing.T, a *scaleAccount, run func() error) scaleResult {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	requests := a.requests.Load()
	start := time.Now()
	if err := run(); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	return scaleResult{elapsed, float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20), a.requests.Load() - requests}
}

// TestScale records time, allocation and API requests for account sizes
// against an in-process API. Run with -v to see the numbers.
func TestScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale fixture")
	}
	for _, size := range []int{0, 1, 10000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", home)
			t.Setenv("HOME", home)
			t.Setenv("MESHSCALE_DNS_SUFFIX", "")
			account := newScaleAccount(size, 1000)
			client := commandAPI(t, account.ServeHTTP)
			ctx := context.Background()
			pages := int64(2 * ((size + 99) / 100))
			if size == 0 {
				pages = 2
			}
			var devices []meshDevice
			status := measure(t, account, func() error {
				var err error
				devices, err = loadMeshDevices(ctx, client, "account", nil, time.Now(), nil)
				if err == nil {
					err = assignDNSNames(devices)
				}
				if err == nil {
					err = writeStatus(io.Discard, devices, false, time.Now())
				}
				return err
			})
			if len(devices) != size {
				t.Fatalf("status listed %d of %d devices", len(devices), size)
			}
			// Two device lists, one page per 100 entries, plus Mesh nodes.
			if status.requests != pages+1 {
				t.Fatalf("status used %d API requests, want %d", status.requests, pages+1)
			}
			dns := measure(t, account, func() error { return syncDNS(ctx, io.Discard, client, "account", true) })
			policy := filepath.Join(home, "rules.json")
			var rules []string
			for i := range min(size, 398) { // 100 customer policies + 398 + default deny <= 500
				rules = append(rules, fmt.Sprintf(`{"from":["user%d@example.com"],"to":["laptop %d:22,443"]}`, i%300, 2*i))
			}
			if err := os.WriteFile(policy, []byte(`{"rules":[`+strings.Join(rules, ",")+`]}`), 0600); err != nil {
				t.Fatal(err)
			}
			rulesSync := measure(t, account, func() error { return SyncRules(ctx, io.Discard, client, "account", policy, true) })
			inventory := measure(t, account, func() error { return scaleInventory(t, devices) })
			for _, m := range []struct {
				name string
				r    scaleResult
			}{{"status", status}, {"dns sync", dns}, {"rules sync", rulesSync}, {"daemon inventory", inventory}} {
				name, r := m.name, m.r
				t.Logf("%5d devices, 1000 rules: %-16s %8.1fms %8.1f MiB allocated %4d API requests", size, name, float64(r.elapsed.Microseconds())/1000, r.allocMiB, r.requests)
				if r.elapsed > 20*time.Second {
					t.Errorf("%s took %v", name, r.elapsed)
				}
			}
		})
	}
}

// scaleInventory serves the inventory over the private socket the way the
// daemon does, and reads it back through the status client.
func scaleInventory(t *testing.T, devices []meshDevice) error {
	cache := service.NewInventoryCache(func(context.Context) ([]meshDevice, error) { return devices, nil })
	if _, err := cache.Refresh(t.Context()); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "ms-scale-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	ctrl := &service.Control{Inventory: cache, Proxies: &service.Proxies{}}
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	defer func() { cancel(); <-done }()
	<-ready
	var inventory service.Inventory
	if err := service.Request(ctx, dir, "GET", "/devices", nil, &inventory); err != nil {
		return err
	}
	if len(inventory.Devices) != len(devices) {
		return fmt.Errorf("inventory returned %d of %d devices", len(inventory.Devices), len(devices))
	}
	return nil
}

// An owned-looking rule name comes from the account; listing it for deletion
// must not write terminal escapes, line breaks or bidi overrides.
func TestDNSSyncEscapesAccountRuleNames(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	t.Setenv("MESHSCALE_DNS_SUFFIX", "")
	account := newScaleAccount(0, 0)
	account.rules = []cfapi.GatewayRule{{
		ID: "r1", Name: names.RulePrefix + "\x1b[2Jgone\r\ndelete\tbank.mesh\u202egpj.exe", Enabled: true, Action: "override",
		Description: "Managed by meshscale DNS v1; participant=device/missing", Filters: []string{"dns"},
	}}
	var out strings.Builder
	if err := syncDNS(context.Background(), &out, commandAPI(t, account.ServeHTTP), "account", true); err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(out.String(), "\n")
	if !strings.HasPrefix(line, "delete\t") || strings.ContainsAny(line, "\x1b\r\u202e") || strings.Count(line, "\t") != 2 {
		t.Fatalf("unsafe dry-run line %q", line)
	}
}

type countingProber struct{ calls atomic.Int64 }

func (p *countingProber) Probe(context.Context, netip.Addr) error { p.calls.Add(1); return nil }

// A large account's stale devices must still use the daemon's shared probe
// cache rather than exceed its request bound and probe from the CLI.
func TestStatusReachabilityUsesDaemonForLargeAccounts(t *testing.T) {
	home, err := os.MkdirTemp("", "ms-reach-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	t.Setenv("XDG_CONFIG_HOME", home)
	dir, err := config.ServiceDir()
	if err != nil {
		t.Fatal(err)
	}
	prober := &countingProber{}
	ctrl := &service.Control{Reachability: reachability.New(prober), Proxies: &service.Proxies{}}
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	defer func() { cancel(); <-done }()
	<-ready
	var ips []netip.Addr
	for i := range 10000 {
		ips = append(ips, netip.AddrFrom4([4]byte{100, 96, byte(i >> 8), byte(i)}))
	}
	results := statusReachability(t.Context(), ips)
	if prober.calls.Load() == 0 || len(results) == 0 {
		t.Fatalf("daemon probed %d addresses; CLI fell back to local probes", prober.calls.Load())
	}
}
