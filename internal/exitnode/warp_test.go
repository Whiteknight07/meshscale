package exitnode

import (
	"net/netip"
	"strings"
	"testing"
)

func TestWARPCompatibilityExceptions(t *testing.T) {
	for _, tc := range []struct {
		name             string
		present, offline bool
		count            int
	}{
		{name: "native has no WARP bypass"},
		{name: "official underlay", present: true, count: 2},
		{name: "retain underlay while WARP reconnects", offline: true, count: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Snapshot{V4: Family{Routes: []Route{{Dst: "default", Dev: "eth0", Gateway: "192.168.1.1"}}}, V6: Family{Routes: []Route{{Dst: "default", Dev: "eth0", Gateway: "fe80::1"}}}}
			var previous *Plan
			if tc.present {
				s.V4.Routes = append(s.V4.Routes, Route{Dst: "100.96.0.0/12", Dev: "CloudflareWARP", Table: "65743"})
			}
			if tc.offline {
				previous = &Plan{WARP: []Exception{{Family: "-4"}}}
			}
			routes := warpUnderlay(s, previous)
			if len(routes) != tc.count {
				t.Fatal(routes)
			}
			body := GuardRules(Plan{WARP: routes})
			for _, e := range routes {
				if e.Route.Dev != "eth0" || e.Route.Dst == "default" {
					t.Fatal(e)
				}
				if !strings.Contains(body, e.Route.Dst+" oifname \"eth0\" udp dport { 443, 500, 1701, 4500, 4443, 8095, 8443 } accept") {
					t.Fatal(body)
				}
				if strings.Contains(body, e.Route.Dst+" oifname \"eth0\" accept") {
					t.Fatal("unrestricted WARP bypass")
				}
			}
		})
	}
	// The inside-tunnel HTTPS check retains its original Mesh path even though
	// UDP ingress/probes use the physical underlay for the containing prefix.
	s := baseline()
	s.V4.Routes = append(s.V4.Routes, Route{Dst: "162.159.197.4", Dev: "CloudflareWARP", Table: "65743"})
	controls, err := ControlRoutes(s, append(warpControlIPs(), netip.MustParseAddr("162.159.197.4")))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range controls {
		if e.Route.Dst == "162.159.197.4" && e.Route.Dev != "CloudflareWARP" {
			t.Fatal(e)
		}
	}
}

func TestWARPDoesNotBootstrapIPv6ThroughItsOwnExit(t *testing.T) {
	s := baseline()
	s.V6.Routes = nil
	routes := warpUnderlay(s, nil)
	if len(routes) != 2 || routes[1].Route.Type != "unreachable" {
		t.Fatal(routes)
	}
	body := GuardRules(Plan{WARP: routes})
	if strings.Contains(body, "ip6 daddr 2606:4700:102::/48") {
		t.Fatal("granted missing physical IPv6 uplink")
	}
}
func TestCarrierMarksSurviveReconnect(t *testing.T) {
	s := baseline()
	previous, err := PlanRouting(s, netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	// WARP's own rules disappear while reconnecting, but terminal owned rules
	// must continue preserving carrier socket marks.
	s.V4.Rules = []Rule{{Priority: 0, Table: "local"}, {Priority: 32766, Table: "main"}}
	next, err := PlanRouting(s, previous.Source, previous.Endpoint, false, &previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Marks) != len(previous.Marks) {
		t.Fatal(next.Marks)
	}
}
