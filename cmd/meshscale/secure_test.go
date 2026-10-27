package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/service"
	"golang.zx2c4.com/wireguard/conn"
)

type secureTestBackend struct{ backend.Backend }

func (secureTestBackend) Registration(context.Context) (backend.Registration, error) {
	return backend.Registration{ID: "reg"}, nil
}

// Real userspace engine and private TCP listener leases, with only the account
// API mocked. No WARP calls, host interfaces, routes, or real account writes.
func TestSecureWorkerLifecycle(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := secureDir()
	if err != nil {
		t.Fatal(err)
	}
	settings := secure.Config{Enabled: true, Userspace: true}
	if err := settings.Save(dir); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var list *cfapi.GatewayList
	offline := false
	api := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var result any
		switch r.URL.Path {
		case "/accounts/acc/gateway/lists", "/accounts/acc/gateway/lists/key-list":
			if offline {
				http.Error(w, "directory unavailable", http.StatusForbidden)
				return
			}
			if r.Method == http.MethodGet {
				result = []cfapi.GatewayList{}
				if list != nil {
					result = []cfapi.GatewayList{*list}
				}
			} else {
				var value cfapi.GatewayList
				if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				value.ID = "key-list"
				list = &value
				result = value
			}
		case "/accounts/acc/devices/registrations":
			result = []cfapi.Registration{{ID: "reg", Device: cfapi.RegistrationDevice{ID: "dev", Name: "test"}, VirtualIPv4: "100.96.0.3"}}
		case "/accounts/acc/warp_connector":
			result = []cfapi.MeshNode{}
		default:
			t.Errorf("unexpected API %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	})
	ctrl := &service.Control{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- startSecureWorker(ctx, ctrl, api, "acc", secureTestBackend{}, time.Second, func(netip.Addr) conn.Bind {
			return &secure.PacketBind{Listen: func(uint16) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") }}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("secure worker failed to stop")
		}
	})
	wait := func(check func(secure.Status) bool) secure.Status {
		t.Helper()
		timer := time.NewTimer(8 * time.Second)
		defer timer.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			s := ctrl.Status().Secure
			if check(s) {
				return s
			}
			select {
			case <-timer.C:
				t.Fatalf("secure state did not converge: %+v", s)
			case <-tick.C:
			}
		}
	}
	running := wait(func(s secure.Status) bool { return s.Running })
	ip := netip.MustParseAddr(running.IP)
	listener, err := (&native.Client{Dir: dir}).ListenTCP(ctx, netip.AddrPortFrom(ip, 2222))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if c != nil {
			c.Close()
		}
		accepted <- err
	}()
	mu.Lock()
	offline = true
	mu.Unlock()
	wait(func(s secure.Status) bool { return s.Enabled && !s.Running && strings.Contains(s.Error, "403") })
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("closed secure listener accepted a connection")
		}
	case <-time.After(time.Second):
		t.Fatal("refresh failure left a secure listener active")
	}
	mu.Lock()
	offline = false
	mu.Unlock()
	restarted := wait(func(s secure.Status) bool { return s.Running })
	if restarted.IP != running.IP {
		t.Fatal("restart changed secure identity")
	}
	settings.Enabled = false
	if err := settings.Save(dir); err != nil {
		t.Fatal(err)
	}
	wait(func(s secure.Status) bool { return !s.Enabled && !s.Running && s.Error == "" })
	records, _, err := secure.Records(ctx, api, "acc")
	if err != nil || len(records) != 0 {
		t.Fatalf("disabled key still advertised: %v %v", records, err)
	}
}

func TestSecureTargetResolution(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := config.ServiceDir()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctrl := &service.Control{}
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("service control did not start")
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ip := netip.MustParseAddr("fd6d:6573:6873::1234")
	peer := secure.PeerStatus{Peer: secure.Peer{IP: ip, DNSName: "server.secure"}, Enabled: true}
	for _, tc := range []struct {
		name, target                      string
		running, duplicate, handled, fail bool
	}{
		{"name", "server.secure", true, false, true, false},
		{"address", ip.String(), true, false, true, false},
		{"plain remains plain", "server.mesh", true, false, false, false},
		{"unknown cannot downgrade", "unknown.secure", true, false, true, true},
		{"stopped cannot downgrade", "server.secure", false, false, true, true},
		{"ambiguous", "server.secure", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl.Update(func(s *service.Status) {
				s.Secure = secure.Status{Enabled: true, Running: tc.running, Peers: []secure.PeerStatus{peer}}
				if tc.duplicate {
					s.Secure.Peers = append(s.Secure.Peers, peer)
				}
			})
			got, handled, err := resolveSecureTarget(ctx, tc.target)
			if handled != tc.handled || (err != nil) != tc.fail || handled && err == nil && got != ip {
				t.Fatalf("target=%s ip=%s handled=%v error=%v", tc.target, got, handled, err)
			}
		})
	}
}

func TestExitConfigurationErrorsPreserveSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"cannot disable under selection", []string{"--secure=false"}, "deselect"},
		{"cannot replace host routing with private stack", []string{"--userspace=true"}, "exit nodes require"},
		{"cannot use explicit Go engine", []string{"--secure-engine=go"}, "exit nodes require"},
		{"cannot advertise and select", []string{"--advertise-exit-node=true"}, "advertise and select"},
		// Conflicts must be rejected before the selection is resolved online.
		{"cannot advertise while selecting", []string{"--exit-node=other", "--advertise-exit-node=true"}, "advertise and select"},
		{"cannot select without secure mode", []string{"--exit-node=other", "--secure=false"}, "requires secure mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			dir, err := secureDir()
			if err != nil {
				t.Fatal(err)
			}
			saved := secure.Config{Enabled: true, ExitID: "selected", ExitKey: "pinned", ExitName: "exit", ExitMeshIP: "100.96.0.7", IPv4: "10.200.1.2"}
			if err := saved.Save(dir); err != nil {
				t.Fatal(err)
			}
			if err := runSet(t.Context(), tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			after, err := secure.LoadConfig(dir)
			if err != nil {
				t.Fatal(err)
			}
			if after != saved {
				t.Fatalf("invalid change modified selection: %+v", after)
			}
		})
	}
}
