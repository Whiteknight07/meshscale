package exitnode

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestForwardRulesBoundaries(t *testing.T) {
	p := ForwardPlan{Uplink4: "eth0", Uplink6: "eth0", Sources4: []netip.Addr{netip.MustParseAddr("10.200.1.2")}, Sources6: []netip.Addr{netip.MustParseAddr("fd6d:6573:6873::1")}, MSS: 1172}
	body := ForwardRules(p)
	for _, want := range []string{"10.200.1.2", "fd6d:6573:6873::1", "169.254.0.0/16", "100.64.0.0/10", "iifname != \"meshsecure0\" ip saddr @clients4 counter drop", "iifname \"meshsecure0\" oifname \"eth0\" ip saddr @clients4 counter masquerade", "ct state established,related", "maxseg size > 1172 tcp option maxseg size set 1172", "oifname \"meshsecure0\" counter drop"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in %s", want, body)
		}
	}
	p.Uplink6 = ""
	body = ForwardRules(p)
	if strings.Contains(body, "ip6 saddr @clients6 counter masquerade") {
		t.Fatal("IPv6 NAT without ready uplink")
	}
}
func TestGuardDoesNotExemptEstablishedInternet(t *testing.T) {
	p, _ := PlanRouting(baseline(), netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), false, nil)
	p.DNS = []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	p.SSH = []netip.Addr{netip.MustParseAddr("203.0.113.4")}
	body := GuardRules(p)
	for _, want := range []string{"counter reject", "meta mark & 0xffffffff == 0x100cf", "ip daddr 100.96.0.0/12 oifname \"CloudflareWARP\"", "ip daddr 192.168.1.1 meta l4proto { tcp, udp } th dport 53", "ip daddr 203.0.113.4 accept"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	for _, forbidden := range []string{"\n ct state established", "192.168.1.0/24", "oifname \"eth0\" accept"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("guard grants unintended exception: %s", forbidden)
		}
	}
}
func TestForwardingPrerequisites(t *testing.T) {
	sentinel := errors.New("sysctl read failed")
	for _, tc := range []struct {
		name, value string
		readErr     error
		fail        bool
	}{{"enabled", "1\n", nil, false}, {"disabled", "0\n", nil, true}, {"read error", "", sentinel, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := SysctlForwarding{Read: func(string) ([]byte, error) { return []byte(tc.value), tc.readErr }}
			err := f.Check(t.Context())
			if (err != nil) != tc.fail {
				t.Fatal(err)
			}
			if tc.readErr != nil && !errors.Is(err, sentinel) {
				t.Fatal("lost cause")
			}
			if f.IPv6(t.Context()) != (tc.value == "1\n" && tc.readErr == nil) {
				t.Fatal("incorrect IPv6 readiness")
			}
		})
	}
}
func TestNFTSyntaxInIsolatedNamespace(t *testing.T) {
	if os.Getenv("MESHSCALE_EXIT_NETNS_TEST") != "1" {
		t.Skip("set MESHSCALE_EXIT_NETNS_TEST=1 for isolated Linux nft syntax validation")
	}
	p, _ := PlanRouting(baseline(), netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("100.96.0.7"), true, nil)
	for _, body := range []string{GuardRules(p), ForwardRules(ForwardPlan{Uplink4: "eth0", MSS: 1172})} {
		script := `table inet meshscale_test { comment "meshscale exit v2";` + "\n" + body + "\n}\n"
		if out, err := (Commands{}).Run(t.Context(), script, "unshare", "-n", "nft", "--check", "-f", "-"); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
}

func TestGuardRestrictsSecureIdentitySources(t *testing.T) {
	p := Plan{Identities4: []netip.Addr{netip.MustParseAddr("10.200.1.2")}, Identities6: []netip.Addr{netip.MustParseAddr("fd6d:6573:6873::2")}}
	text := GuardRules(p)
	for _, want := range []string{"10.200.1.2", "fd6d:6573:6873::2", "ip saddr 10.192.0.0/10 ip saddr != @identities4 counter drop", "ip6 saddr fd6d:6573:6873::/48 ip6 saddr != @identities6 counter drop"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing identity boundary %q", want)
		}
	}
}

func TestExistingFirewalldReadiness(t *testing.T) {
	sentinel := errors.New("firewall unavailable")
	for _, tc := range []struct {
		name, ingress, egress string
		forward               bool
		stopped, failed       bool
		wantErr               bool
	}{
		{name: "default public zone", ingress: "public", egress: "public", forward: true},
		{name: "explicit matching zone", ingress: "public", egress: "public", forward: true},
		{name: "different zones require admin", ingress: "drop", egress: "public", forward: true, wantErr: true},
		{name: "forwarding disabled", ingress: "public", egress: "public", forward: false, wantErr: true},
		{name: "inactive firewalld", stopped: true},
		{name: "firewalld error", failed: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeFirewalld{zones: map[string]string{"meshsecure0": tc.ingress, "eth0": tc.egress}, forward: tc.forward}
			if tc.stopped {
				client.err = ErrFirewalldUnavailable
			}
			if tc.failed {
				client.err = sentinel
			}
			f := Firewall{DBus: client}
			err := f.Reconcile(t.Context(), ForwardPlan{Uplink4: "eth0", Uplink6: "eth0"})
			if (err != nil) != tc.wantErr {
				t.Fatal(err)
			}
			if tc.failed && !errors.Is(err, sentinel) {
				t.Fatal("lost cause", err)
			}
			if err := f.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFirewalldCacheInvalidatesOnSignal(t *testing.T) {
	client := &fakeFirewalld{zones: map[string]string{"meshsecure0": "public", "eth0": "public"}, forward: true}
	f := Firewall{DBus: client, watching: true}
	plan := ForwardPlan{Uplink4: "eth0"}
	for range 2 {
		if err := f.Reconcile(t.Context(), plan); err != nil {
			t.Fatal(err)
		}
	}
	if client.zoneCalls != 2 || client.forwardCalls != 1 {
		t.Fatalf("cached reads zones=%d forward=%d", client.zoneCalls, client.forwardCalls)
	}
	f.Invalidate()
	if err := f.Reconcile(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if client.zoneCalls != 4 || client.forwardCalls != 2 {
		t.Fatalf("invalidated reads zones=%d forward=%d", client.zoneCalls, client.forwardCalls)
	}
}

type fakeFirewalld struct {
	zones        map[string]string
	forward      bool
	err          error
	zoneCalls    int
	forwardCalls int
}

func (f *fakeFirewalld) Zone(_ context.Context, dev string) (string, error) {
	f.zoneCalls++
	return f.zones[dev], f.err
}
func (f *fakeFirewalld) QueryForward(context.Context, string) (bool, error) {
	f.forwardCalls++
	return f.forward, f.err
}
func (f *fakeFirewalld) Watch(context.Context) (<-chan struct{}, error) {
	return nil, errors.New("no live signal stream in unit test")
}

// TestFirewalldDBusMatchesFirewallCmdLive reads, never changes, the host's firewalld.
func TestFirewalldDBusMatchesFirewallCmdLive(t *testing.T) {
	if os.Getenv("MESHSCALE_LIVE_FIREWALLD") != "1" {
		t.Skip("set MESHSCALE_LIVE_FIREWALLD=1 to compare with firewall-cmd on this host")
	}
	cmd := func(args ...string) string {
		out, _ := exec.Command("firewall-cmd", args...).Output()
		return strings.TrimSpace(string(out))
	}
	client := FirewalldDBus{}
	for _, dev := range []string{"lo", "meshsecure0"} {
		want := cmd("--get-zone-of-interface=" + dev)
		if want == "" || want == "no zone" {
			want = cmd("--get-default-zone")
		}
		zone, err := client.Zone(t.Context(), dev)
		if err != nil || zone != want {
			t.Fatalf("Zone(%s) = %q, %v; firewall-cmd says %q", dev, zone, err, want)
		}
		forward, err := client.QueryForward(t.Context(), zone)
		if want := cmd("--zone="+zone, "--query-forward") == "yes"; err != nil || forward != want {
			t.Fatalf("QueryForward(%s) = %v, %v; firewall-cmd says %v", zone, forward, err, want)
		}
	}
}

func TestClientGuardCoversForwardedEgress(t *testing.T) {
	p := Plan{DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Control: []Exception{{Family: "-4", Route: Route{Dst: "104.17.110.184", Dev: "eth0"}}}}
	body := GuardRules(p)
	for _, chain := range []string{"output", "forward"} {
		_, rest, found := strings.Cut(body, " chain "+chain+" {\n")
		if !found {
			t.Fatalf("client guard lacks %s hook", chain)
		}
		rules, _, _ := strings.Cut(rest, "\n }\n")
		for _, want := range []string{"hook " + chain, `oifname "meshsecure0" accept`, "ip daddr 1.1.1.1 meta l4proto { tcp, udp } th dport 53 accept", `ip daddr 104.17.110.184 oifname "eth0" tcp dport 443 accept`, "counter reject with icmpx type admin-prohibited"} {
			if !strings.Contains(rules, want) {
				t.Fatalf("%s lacks %q: %s", chain, want, rules)
			}
		}
		if strings.Contains(rules, `oifname "eth0" accept`) || strings.Contains(rules, "\n ct state established") {
			t.Fatalf("%s permits physical Internet egress", chain)
		}
		if strings.Contains(rules, `iifname "meshsecure0" ct state established,related accept`) != (chain == "forward") {
			t.Fatalf("%s has wrong tunnel-return allowance", chain)
		}
	}
	// The exit role installs ForwardRules, never the client's guard table.
	exit := ForwardRules(ForwardPlan{Uplink4: "eth0", Sources4: []netip.Addr{netip.MustParseAddr("10.200.1.2")}, MSS: 1172})
	if strings.Contains(exit, "reject with icmpx") || !strings.Contains(exit, `iifname "meshsecure0" oifname "eth0" ip saddr @clients4 counter accept`) {
		t.Fatal("exit no longer permits authenticated tunnel egress")
	}
}
