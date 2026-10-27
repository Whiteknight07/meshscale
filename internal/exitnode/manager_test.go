package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

func TestSelectedExitBinding(t *testing.T) {
	self := secure.Peer{Owner: "owner@example.com"}
	peer := secure.Peer{Owner: self.Owner, RegistrationID: "reg", PublicKey: "key", OffersExit: true, MeshIP: netip.MustParseAddr("100.96.0.7")}
	config := secure.Config{ExitID: "reg", ExitKey: "key", ExitMeshIP: peer.MeshIP.String()}
	for _, tc := range []struct {
		name     string
		change   func(*secure.Peer, *secure.Config)
		selected bool
	}{
		{"matching identity", func(*secure.Peer, *secure.Config) {}, true},
		{"deselected", func(_ *secure.Peer, c *secure.Config) { c.ExitID = "" }, false},
		{"withdrawn", func(p *secure.Peer, _ *secure.Config) { p.OffersExit = false }, false},
		{"replacement registration", func(p *secure.Peer, _ *secure.Config) { p.RegistrationID = "new" }, false},
		{"rotated key", func(p *secure.Peer, _ *secure.Config) { p.PublicKey = "new" }, false},
		{"changed owner", func(p *secure.Peer, _ *secure.Config) { p.Owner = "other" }, false},
		{"changed endpoint", func(p *secure.Peer, _ *secure.Config) { p.MeshIP = netip.MustParseAddr("100.96.0.8") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, c := peer, config
			tc.change(&p, &c)
			got := selectedExit([]secure.Peer{p}, self, c)
			if (got == "key") != tc.selected {
				t.Fatal(got)
			}
		})
	}
}

func TestConfigurePeerRoutesPreservesDiscovery(t *testing.T) {
	self := secure.Peer{PublicKey: "self", ExitVersion: 2, IP: netip.MustParseAddr("fd6d:6573:6873::1"), IPv4: netip.MustParseAddr("10.200.1.1")}
	peer := secure.Peer{PublicKey: "peer", ExitVersion: 2, IP: netip.MustParseAddr("fd6d:6573:6873::2"), IPv4: netip.MustParseAddr("10.200.1.2")}
	for _, selected := range []string{"", "peer"} {
		t.Run("selected="+selected, func(t *testing.T) {
			peers := []secure.Peer{self, peer}
			before := append([]secure.Peer(nil), peers...)
			var calls []netip.Addr
			m := Manager{PeerRoute: func(ip netip.Addr) error {
				calls = append(calls, ip)
				return nil
			}}
			configured, err := m.configurePeerRoutes(t.Context(), peers, self, selected)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(peers, before) {
				t.Fatal("modified discovery peers")
			}
			if !reflect.DeepEqual(calls, []netip.Addr{peer.IPv4}) {
				t.Fatal(calls)
			}
			defaults := len(configured[1].AllowedIPs) == 4
			if defaults != (selected != "") {
				t.Fatal(configured)
			}
		})
	}
}

type activationRoutes struct {
	RouteManager
	calls int
}

func (r *activationRoutes) Activate(context.Context, Plan, bool) error { r.calls++; return nil }
func TestUnavailableSelectionRetainsGuard(t *testing.T) {
	for _, selected := range []string{"", "key"} {
		t.Run("selected="+selected, func(t *testing.T) {
			routes := &activationRoutes{}
			m := Manager{Routes: routes, plan: &Plan{Table: 51840, Priority: 5000}}
			before := *m.plan
			if err := m.activateSelection(t.Context(), nil, secure.Peer{}, selected); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*m.plan, before) || routes.calls != map[bool]int{false: 0, true: 1}[selected != ""] {
				t.Fatal("changed desired protection")
			}
		})
	}
	sentinel := errors.New("route failed")
	m := Manager{PeerRoute: func(netip.Addr) error { return sentinel }}
	if _, err := m.configurePeerRoutes(t.Context(), []secure.Peer{{IPv4: netip.MustParseAddr("10.200.1.1"), PublicKey: "peer"}}, secure.Peer{}, ""); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func TestResolverReplacementCanBootstrapWithoutDNS(t *testing.T) {
	for _, changed := range []bool{true, false} {
		t.Run(map[bool]string{true: "resolver replaced", false: "resolver temporarily unavailable"}[changed], func(t *testing.T) {
			dns := []netip.Addr{netip.MustParseAddr("127.0.2.2")}
			p := Plan{DNS: dns}
			if changed {
				p.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
			}
			m := Manager{plan: &Plan{DNS: dns, Control: []Exception{{Family: "-4", Route: Route{Dst: "104.17.110.184", Dev: "eth0", Gateway: "172.17.0.1"}}}}}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			controls, err := m.selectionControls(ctx, Snapshot{}, p)
			if err != nil || len(controls) != 1 {
				t.Fatal(controls, err)
			}
			controls[0].Route.Dst = "changed"
			if m.plan.Control[0].Route.Dst != "104.17.110.184" {
				t.Fatal("mutated persisted control exceptions")
			}
		})
	}
}

type snapshotFunc func(context.Context) (Snapshot, error)

func (f snapshotFunc) Inspect(ctx context.Context) (Snapshot, error) { return f(ctx) }

type protectionNFT struct {
	Nftables
	installed            bool
	applyErr, inspectErr error
	applies, probes      int
}

func (n *protectionNFT) Apply(context.Context, string, string) error { n.applies++; return n.applyErr }
func (n *protectionNFT) Installed(context.Context, string) (bool, error) {
	n.probes++
	return n.installed, n.inspectErr
}

type protectionRoutes struct {
	RouteManager
	exceptionsErr, blockErr error
	exceptions, blocks      int
}

func (r *protectionRoutes) Exceptions(context.Context, Plan) error {
	r.exceptions++
	return r.exceptionsErr
}
func (r *protectionRoutes) Block(context.Context, Plan) error { r.blocks++; return r.blockErr }

func protectionFixture() (Plan, Snapshot) {
	p := Plan{Table: 51840, Priority: 5000, Exceptions: []Exception{{Family: "-4", Route: Route{Dst: "100.96.0.0/12", Dev: "CloudflareWARP"}}}}
	var s Snapshot
	for _, f := range []struct {
		family  *Family
		blocked string
	}{{&s.V4, "100.64.0.0/10"}, {&s.V6, "fd7a:115c:a1e0::/48"}} {
		f.family.Rules = []Rule{{Priority: 5002, Protocol: "242", Table: "51840"}, {Priority: 5003, Protocol: "242", Table: "51841"}, {Priority: 5004, Protocol: "242", Action: "unreachable"}}
		f.family.Routes = []Route{{Dst: "default", Table: "51841", Type: "unreachable", Metric: 42760}, {Dst: f.blocked, Table: "51840", Type: "unreachable", Metric: 42760}}
	}
	s.V4.Routes = append(s.V4.Routes, Route{Dst: "100.96.0.0/12", Dev: "CloudflareWARP", Table: "51840", Type: "unicast"})
	return p, s
}

func TestProtectionRetriesEveryFailedStep(t *testing.T) {
	for _, stage := range []string{"recovery", "nft", "exceptions", "block"} {
		t.Run(stage, func(t *testing.T) {
			want := errors.New(stage + " failed")
			nft, routes := &protectionNFT{}, &protectionRoutes{}
			p, _ := protectionFixture()
			m := Manager{Dir: filepath.Join(t.TempDir(), "state"), NFT: nft, Routes: routes, plan: &Plan{}, prepared: true}
			recoveries := 0
			m.recovery = func(context.Context, Runner, string, string) error {
				recoveries++
				if m.plan != nil || m.prepared {
					t.Fatal("cached success before protection completed")
				}
				if stage == "recovery" && recoveries == 1 {
					return want
				}
				return nil
			}
			switch stage {
			case "nft":
				nft.applyErr = want
			case "exceptions":
				routes.exceptionsErr = want
			case "block":
				routes.blockErr = want
			}
			if err := m.protectSelection(t.Context(), p); !errors.Is(err, want) {
				t.Fatal(err)
			}
			if m.plan != nil || m.prepared {
				t.Fatal("retained failed plan")
			}
			nft.applyErr, routes.exceptionsErr, routes.blockErr = nil, nil, nil
			if err := m.protectSelection(t.Context(), p); err != nil {
				t.Fatal(err)
			}
			if recoveries != 2 || !m.prepared || !reflect.DeepEqual(m.plan, &p) {
				t.Fatal("failed protection was not retried")
			}
		})
	}
}

func TestProtectionRechecksKernelStateWithoutCommands(t *testing.T) {
	for _, missing := range []string{"none", "IPv4 rules", "IPv6 rules", "terminal route", "exception route", "guard", "snapshot error", "nft error"} {
		t.Run(missing, func(t *testing.T) {
			p, s := protectionFixture()
			nft, routes := &protectionNFT{installed: true}, &protectionRoutes{}
			want := errors.New("inspect failed")
			switch missing {
			case "IPv4 rules":
				s.V4.Rules = nil
			case "IPv6 rules":
				s.V6.Rules = nil
			case "terminal route":
				s.V6.Routes = s.V6.Routes[1:]
			case "exception route":
				s.V4.Routes = s.V4.Routes[:2]
			case "guard":
				nft.installed = false
			case "nft error":
				nft.inspectErr = want
			}
			reads, recoveries := 0, 0
			m := Manager{Dir: filepath.Join(t.TempDir(), "state"), NFT: nft, Routes: routes, plan: &p, prepared: true,
				Run: runnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
					t.Fatal("idle probe spawned a command")
					return nil, nil
				}),
				Reader: snapshotFunc(func(context.Context) (Snapshot, error) {
					reads++
					if missing == "snapshot error" {
						return Snapshot{}, want
					}
					return s, nil
				}),
				recovery: func(context.Context, Runner, string, string) error { recoveries++; return nil },
			}
			err := m.protectSelection(t.Context(), p)
			if missing == "snapshot error" || missing == "nft error" {
				if !errors.Is(err, want) || recoveries != 0 {
					t.Fatal(err, recoveries)
				}
				return
			}
			if err != nil || reads != 1 {
				t.Fatal(err, reads)
			}
			if missing == "none" {
				if recoveries != 0 || nft.applies != 0 || routes.blocks != 0 || nft.probes != 1 {
					t.Fatal("idle reconciliation mutated protection")
				}
			} else if recoveries != 1 || nft.applies != 1 || routes.blocks != 1 || routes.exceptions != 1 {
				t.Fatal("kernel drift was not repaired")
			}
		})
	}
}

func TestResolvedStubUsesUpstreamResolvers(t *testing.T) {
	for _, tc := range []struct {
		name, resolv, upstream string
		want                   []string
		fails                  bool
	}{
		{"stub", "nameserver 127.0.0.53\n", "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n", []string{"127.0.0.53", "1.1.1.1", "2606:4700:4700::1111"}, false},
		{"proxy stub", "nameserver 127.0.0.54\n", "nameserver 9.9.9.9\n", []string{"127.0.0.54", "9.9.9.9"}, false},
		{"direct", "nameserver 8.8.8.8\n", "", []string{"8.8.8.8"}, false},
		{"WARP loopback", "nameserver 127.0.2.2\n", "", []string{"127.0.2.2"}, false},
		{"mixed", "nameserver 127.0.0.53\nnameserver 8.8.8.8\n", "", []string{"127.0.0.53", "8.8.8.8"}, false},
		{"upstream missing", "nameserver 127.0.0.53\n", "", nil, true},
		{"upstream malformed", "nameserver 127.0.0.53\n", "nameserver invalid\n", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			resolv, upstream := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "upstream.conf")
			if err := os.WriteFile(resolv, []byte(tc.resolv), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.upstream != "" {
				if err := os.WriteFile(upstream, []byte(tc.upstream), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ips, err := resolverIPsFrom(resolv, upstream)
			if (err != nil) != tc.fails {
				t.Fatal(ips, err)
			}
			if tc.fails {
				return
			}
			var got []string
			for _, ip := range ips {
				got = append(got, ip.String())
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatal(got)
			}
			guard := GuardRules(Plan{DNS: ips})
			for _, ip := range tc.want {
				if !strings.Contains(guard, "daddr "+ip+" meta l4proto { tcp, udp } th dport 53 accept") {
					t.Fatal("resolver absent from guard", guard)
				}
			}
		})
	}
}

func TestForwardChoosesLowestMetricUplink(t *testing.T) {
	for _, metrics := range [][]int{{10, 100, 50}, {100, 50, 10}, {100, 0, 50}} {
		var s Snapshot
		best := 0
		for i, metric := range metrics {
			if metric < metrics[best] {
				best = i
			}
			s.V4.Routes = append(s.V4.Routes, Route{Dst: "default", Dev: fmt.Sprintf("eth%d", i), Metric: metric})
			s.V6.Routes = append(s.V6.Routes, Route{Dst: "default", Dev: fmt.Sprintf("wan%d", i), Metric: metric})
		}
		nft := &protectionNFT{}
		m := Manager{Reader: snapshotFunc(func(context.Context) (Snapshot, error) { return s, nil }), NFT: nft,
			Forwarding: SysctlForwarding{Read: func(string) ([]byte, error) { return []byte("1\n"), nil }}, Firewall: Firewall{DBus: &fakeFirewalld{err: ErrFirewalldUnavailable}}}
		if err := m.Forward(t.Context(), secure.Peer{}, nil, 1172); err != nil {
			t.Fatal(err)
		}
		if m.forwardPlan.Uplink4 != fmt.Sprintf("eth%d", best) || m.forwardPlan.Uplink6 != fmt.Sprintf("wan%d", best) {
			t.Fatalf("metrics %v selected %+v", metrics, m.forwardPlan)
		}
	}
}

func TestSelectionMutationsHonorSettingsSerialization(t *testing.T) {
	rejected := errors.New("settings changed")
	for _, operation := range []string{"install", "remove"} {
		t.Run(operation, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "secure")
			m := Manager{Dir: dir, Mutate: func(func() error) error { return rejected }}
			var err error
			if operation == "install" {
				err = m.protectSelection(t.Context(), Plan{Table: 51840, Priority: 5000})
			} else {
				m.plan = &Plan{Table: 51840, Priority: 5000}
				err = m.deselect(t.Context())
			}
			if !errors.Is(err, rejected) {
				t.Fatalf("mutation bypassed settings guard: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "exit-routing.json")); !os.IsNotExist(err) {
				t.Fatal("rejected mutation wrote recovery state")
			}
		})
	}
}

func TestInstalledProtectionDoesNotAcquireSettingsSerialization(t *testing.T) {
	p, snapshot := protectionFixture()
	m := Manager{plan: &p, prepared: true, NFT: &protectionNFT{installed: true}, Reader: snapshotFunc(func(context.Context) (Snapshot, error) { return snapshot, nil }), Mutate: func(func() error) error {
		t.Fatal("healthy read-only inspection acquired the mutation lock")
		return nil
	}}
	if err := m.protectSelection(t.Context(), p); err != nil {
		t.Fatal(err)
	}
}
