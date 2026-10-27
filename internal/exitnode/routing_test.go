package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

type runnerFunc func(context.Context, string, string, ...string) ([]byte, error)

func (f runnerFunc) Run(c context.Context, input, name string, args ...string) ([]byte, error) {
	return f(c, input, name, args...)
}
func baseline() Snapshot {
	return Snapshot{V4: Family{
		Rules:  []Rule{{Priority: 0, Table: "local"}, {Priority: 5209, Table: "65743", FWMark: "0x100cf", Not: []byte("null")}, {Priority: 5210, Table: "main", FWMark: "0x80000", FWMask: "0xff0000"}, {Priority: 5270, Table: "52"}, {Priority: 32766, Table: "main"}},
		Routes: []Route{{Dst: "default", Dev: "eth0", Gateway: "192.168.1.1"}, {Dst: "192.168.1.0/24", Dev: "eth0"}, {Dst: "100.96.0.0/12", Dev: "CloudflareWARP", Table: "65743"}, {Dst: "100.85.78.6", Dev: "tailscale0", Table: "52"}},
	}, V6: Family{Rules: []Rule{{Priority: 0, Table: "local"}, {Priority: 32766, Table: "main"}}, Routes: []Route{{Dst: "default", Dev: "eth0", Gateway: "fe80::1"}, {Dst: "fd6d:6573:6873::/48", Dev: "meshsecure0"}}}}
}
func TestPlanRouting(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		lan, conflict, competing, occupied bool
		fail                               bool
	}{
		{name: "narrow LAN disabled"}, {name: "explicit LAN", lan: true}, {name: "source overlap", conflict: true, fail: true}, {name: "competing exit", competing: true, fail: true}, {name: "allocate around existing tables", occupied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baseline()
			if tc.conflict {
				s.V4.Routes = append(s.V4.Routes, Route{Dst: "10.0.0.0/8", Dev: "lan0"})
			}
			if tc.competing {
				s.V4.Routes = append(s.V4.Routes, Route{Dst: "default", Dev: "tailscale0", Table: "52"})
			}
			if tc.occupied {
				s.V4.Rules = append(s.V4.Rules, Rule{Priority: 300, Table: "51840"})
			}
			p, err := PlanRouting(s, netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), tc.lan, nil)
			if (err != nil) != tc.fail {
				t.Fatalf("plan=%+v error=%v", p, err)
			}
			if err != nil {
				return
			}
			if p.Priority >= 5209 || p.Priority < 1 || p.Table == 0 || tc.occupied && p.Table == 51840 {
				t.Fatalf("resource collision: %+v", p)
			}
			if len(p.Marks) != 2 {
				t.Fatalf("carrier marks missing: %+v", p.Marks)
			}
			lan := false
			mesh := false
			ts := false
			for _, e := range p.Exceptions {
				lan = lan || e.Route.Dst == "192.168.1.0/24"
				mesh = mesh || e.Route.Dev == "CloudflareWARP"
				ts = ts || e.Route.Dev == "tailscale0"
			}
			if lan != tc.lan || !mesh || !ts {
				t.Fatalf("coexistence: %+v", p)
			}
		})
	}
}
func TestBlockAndActivate(t *testing.T) {
	var commands []string
	run := runnerFunc(func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil, nil
	})
	r := Routing{Run: run}
	p := Plan{Table: 51840, Priority: 5300, Source: netip.MustParseAddr("10.200.1.2"), Source6: netip.MustParseAddr("fd6d:6573:6873::2")}
	if err := r.Block(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	for _, wanted := range []string{"-4 route replace unreachable 0.0.0.0/0 table 51841", "-6 route replace unreachable ::/0 table 51841", "protocol 242", "lookup 51840", "lookup 51841", "unreachable"} {
		if !strings.Contains(joined, wanted) {
			t.Fatalf("missing %q in %s", wanted, joined)
		}
	}
	if strings.Contains(joined, "route replace default") {
		t.Fatal("blocked planner activated a default")
	}
	if err := r.Activate(t.Context(), p, true); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range commands {
		if strings.Contains(cmd, "route") && strings.Contains(cmd, "default") && !strings.Contains(cmd, "table 51841") {
			t.Fatalf("modified host default: %s", cmd)
		}
	}
}
func TestPlanOwnership(t *testing.T) {
	p := Plan{Table: 51840, Priority: 5177}
	s := baseline()
	s.V4.Rules = append(s.V4.Rules, Rule{Priority: p.Priority, Table: "51840"})
	if _, err := PlanRouting(s, netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), false, &p); err == nil {
		t.Fatal("accepted foreign rule in owned block")
	}
	s.V4.Rules[len(s.V4.Rules)-1].Protocol = "242"
	s.V4.Routes = append(s.V4.Routes, Route{Dst: "100.96.0.0/12", Dev: "CloudflareWARP", Table: "51840"})
	got, err := PlanRouting(s, netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), false, &p)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range got.Exceptions {
		if e.Route.Dst == "100.96.0.0/12" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("recopied owned exception table: %+v", got.Exceptions)
	}
}
func TestRoutingErrorsWrap(t *testing.T) {
	sentinel := errors.New("netlink unavailable")
	r := Routing{Run: runnerFunc(func(context.Context, string, string, ...string) ([]byte, error) { return nil, sentinel })}
	if err := r.Activate(t.Context(), Plan{}, true); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func TestCompetingMainTableVPN(t *testing.T) {
	s := baseline()
	s.V4.Routes[0].Dev = "wg-other"
	link := Link{Name: "wg-other"}
	link.Info.Kind = "wireguard"
	s.Links = []Link{link}
	if _, err := PlanRouting(s, netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), false, nil); err == nil {
		t.Fatal("accepted competing WireGuard default in main")
	}
}

func TestPhysicalExceptionsDoNotResolveGatewayThroughSelectedExit(t *testing.T) {
	var commands []string
	r := Routing{Run: runnerFunc(func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		return nil, nil
	})}
	p := Plan{Table: 51840, Control: []Exception{{Family: "-4", Route: Route{Dst: "104.17.110.184", Dev: "eth0", Gateway: "172.17.0.1"}}}, Exceptions: []Exception{{Family: "-4", Route: Route{Dst: "100.96.0.0/12", Dev: "CloudflareWARP"}}}}
	if err := r.Exceptions(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	control := "-4 route replace 104.17.110.184 table 51840 dev eth0 via 172.17.0.1 onlink"
	if !strings.Contains(joined, control) {
		t.Fatal(joined)
	}
	if strings.Index(joined, control) > strings.Index(joined, "route replace 100.96.0.0/12") {
		t.Fatal("restored Mesh before physical recovery routes")
	}
}

func TestGatewayNeighborRouteDoesNotGrantLANAccess(t *testing.T) {
	p, err := PlanRouting(baseline(), netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Gateways) != 2 || p.Gateways[0].Route.Dst != "192.168.1.1" {
		t.Fatal(p.Gateways)
	}
	if strings.Contains(GuardRules(p), "192.168.1.1") {
		t.Fatal("neighbor route grants gateway IP access")
	}
	if len(p.LAN) != 0 {
		t.Fatal("enabled LAN implicitly")
	}
}

func TestExplicitSecureRouteTuning(t *testing.T) {
	for _, tc := range []struct {
		name    string
		install func(Routing) error
		tuned   bool
	}{
		{"plain command does not sniff device", func(r Routing) error {
			return r.command(t.Context(), "-4", "route", "replace", "default", "dev", "meshsecure0")
		}, false},
		{"secure route explicitly tuned", func(r Routing) error {
			return r.installSecureRoute(t.Context(), "-4", "route", "replace", "default", "dev", "meshsecure0")
		}, true},
		{"physical exception", func(r Routing) error {
			return r.installException(t.Context(), "-4", "eth0", "route", "replace", "192.0.2.1", "dev", "eth0")
		}, false},
		{"secure exception", func(r Routing) error {
			return r.installException(t.Context(), "-6", "meshsecure0", "route", "replace", "fd6d:6573:6873::/48", "dev", "meshsecure0")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var commands []string
			r := Routing{Run: runnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
				commands = append(commands, name+" "+strings.Join(args, " "))
				return nil, nil
			})}
			if err := tc.install(r); err != nil {
				t.Fatal(err)
			}
			if len(commands) != 1 || strings.Contains(commands[0], "congctl bbr") != tc.tuned {
				t.Fatal(commands)
			}
		})
	}
}

func TestRuleReplacementAddsBeforeOwnedDeletion(t *testing.T) {
	p := Plan{Table: 51840, Priority: 5000, DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	old := []Rule{{Priority: 5000, Protocol: "242", IPProto: "udp", DPort: 53, Table: "main"}, {Priority: 5004, Protocol: "242", Action: "unreachable"}, {Priority: 5004, Protocol: "99", Table: "main"}}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("add failure=", fail), func(t *testing.T) {
			var commands []string
			want := errors.New("rule add failed")
			r := Routing{Run: runnerFunc(func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
				cmd := strings.Join(args, " ")
				commands = append(commands, cmd)
				if fail && strings.Contains(cmd, "rule add") && strings.HasSuffix(cmd, "lookup 51841") {
					return nil, want
				}
				return nil, nil
			})}
			err := r.replaceRules(t.Context(), "-4", p, old)
			if fail {
				if !errors.Is(err, want) {
					t.Fatal(err)
				}
				for _, cmd := range commands {
					if strings.Contains(cmd, "rule del") {
						t.Fatal("deleted old terminal protection after failed add", commands)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(commands, "\n")
			firstDelete := strings.Index(joined, "-4 rule del")
			lastAdd := strings.LastIndex(joined, "-4 rule add")
			if firstDelete < lastAdd || firstDelete < 0 {
				t.Fatal(commands)
			}
			if !strings.Contains(joined, "-4 rule del priority 5000 protocol 242 ipproto udp dport 53 lookup main") || strings.Contains(joined, "rule del priority 5004 protocol 242") {
				t.Fatal("did not delete exact old owned selectors", commands)
			}
			if strings.Contains(joined, "rule add priority 5004 protocol 242 unreachable") {
				t.Fatal("replaced an identical terminal rule", commands)
			}
			if strings.Contains(joined, "protocol 99") {
				t.Fatal("modified foreign rule", commands)
			}
			// A first install has no old rules to delete, so its additions survive.
			commands = nil
			if err := r.replaceRules(t.Context(), "-4", p, nil); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.Join(commands, "\n"), "rule del") {
				t.Fatal("deleted freshly installed rules")
			}
		})
	}
}

func TestRuleRemovalMatchesOwnership(t *testing.T) {
	var deleted int
	p := Plan{Table: 51840, Priority: 5000, DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")}}
	s := Snapshot{V4: Family{Rules: []Rule{{Priority: 5000, Protocol: "242", Table: "main", IPProto: "udp", DPort: 53, Dst: "1.1.1.1"}, {Priority: 5000, Protocol: "242", Table: "main", IPProto: "udp", DPort: 53, Dst: "9.9.9.9"}, {Priority: 5000, Protocol: "99", Table: "main"}}}}
	r := Routing{Reader: snapshotFunc(func(context.Context) (Snapshot, error) { return s, nil }), Run: runnerFunc(func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		cmd := strings.Join(args, " ")
		if strings.Contains(cmd, "rule del") {
			deleted++
			if !strings.Contains(cmd, "protocol 242") {
				t.Fatal("unscoped rule deletion", cmd)
			}
		}
		return nil, nil
	})}
	if err := r.Remove(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatal(deleted)
	}
}

func TestDNSRulesMatchOnlyAllowedResolverDestinations(t *testing.T) {
	p := Plan{Table: 51840, Priority: 5000, DNS: []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("2606:4700:4700::1111")}, Marks: []Mark{{"0x1", "0xffffffff"}, {"0x2", "0xffffffff"}, {"0x3", "0xffffffff"}, {"0x4", "0xffffffff"}}}
	var commands []string
	r := Routing{Reader: snapshotFunc(func(context.Context) (Snapshot, error) { return Snapshot{}, nil }), Run: runnerFunc(func(_ context.Context, _, _ string, args ...string) ([]byte, error) {
		cmd := strings.Join(args, " ")
		commands = append(commands, cmd)
		return nil, nil
	})}
	if err := r.Block(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	for _, ip := range p.DNS {
		flag := "-4"
		if ip.Is6() {
			flag = "-6"
		}
		for _, proto := range []string{"udp", "tcp"} {
			want := fmt.Sprintf("to %s ipproto %s dport 53 lookup main", ip, proto)
			if !strings.Contains(joined, want) {
				t.Fatal("missing resolver destination", want, commands)
			}
			for _, cmd := range commands {
				if strings.Contains(cmd, want) && !strings.HasPrefix(cmd, flag+" ") {
					t.Fatal("wrong resolver family", cmd)
				}
			}
		}
	}
	for _, cmd := range commands {
		if strings.Contains(cmd, "dport 53") && !strings.Contains(cmd, " to ") {
			t.Fatal("unrestricted DNS bypass", cmd)
		}
		fields := strings.Fields(cmd)
		if len(fields) > 4 && fields[1] == "rule" {
			priority, err := strconv.Atoi(fields[4])
			if err != nil || priority < p.Priority || priority >= p.Priority+16 {
				t.Fatal("DNS exhausted reserved priorities", cmd)
			}
		}
	}
}
