package secure

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestExitSelection(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	otherKey, _ := GenerateKey()
	other, _ := otherKey.Public()
	ip, _ := Address("account", other)
	self := Peer{PublicKey: public, Owner: "owner@example.com"}
	exit := Peer{RegistrationID: "exit", PublicKey: other, Owner: "OWNER@example.com", Name: "ashburn", DNSName: "ashburn.secure", IP: ip, ExitVersion: 2, OffersExit: true}
	for _, tc := range []struct {
		name, target    string
		mutate          func(*Peer)
		duplicate, fail bool
	}{
		{name: "name", target: "ashburn"}, {name: "secure DNS", target: "ashburn.secure"}, {name: "secure IP", target: ip.String()},
		{name: "unknown", target: "other", fail: true}, {name: "ambiguous", target: "ashburn", duplicate: true, fail: true},
		{name: "different owner", target: "ashburn", mutate: func(p *Peer) { p.Owner = "guest@example.com" }, fail: true},
		{name: "unknown owner", target: "ashburn", mutate: func(p *Peer) { p.Owner = "" }, fail: true},
		{name: "not advertised", target: "ashburn", mutate: func(p *Peer) { p.OffersExit = false }, fail: true},
		{name: "legacy", target: "ashburn", mutate: func(p *Peer) { p.ExitVersion = 0 }, fail: true},
		{name: "self", target: "ashburn", mutate: func(p *Peer) { p.PublicKey = public }, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := exit
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			peers := []Peer{p}
			if tc.duplicate {
				peers = append(peers, p)
			}
			got, err := SelectExit(peers, self, tc.target)
			if (err != nil) != tc.fail {
				t.Fatalf("peer=%+v error=%v", got, err)
			}
			if err == nil && (got.RegistrationID != "exit" || got.PublicKey != other) {
				t.Fatal("lost pinned identity")
			}
		})
	}
}
func TestIPv4Bindings(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	ip, _ := IPv4Address("account", public)
	again, _ := IPv4Address("account", public)
	different, _ := IPv4Address("different", public)
	if !ip.Is4() || ip != again || ip == different || !netip.MustParsePrefix("10.192.0.0/10").Contains(ip) {
		t.Fatalf("bindings %s %s %s", ip, again, different)
	}
	reg := cfapi.Registration{ID: "one", VirtualIPv4: "100.96.0.7", Device: cfapi.RegistrationDevice{ID: "device", Name: "exit"}}
	for _, tc := range []struct {
		name         string
		version      int
		binding      netip.Addr
		offers, fail bool
	}{{"v2", 2, ip, true, false}, {"legacy", 0, netip.Addr{}, false, false}, {"wrong binding", 2, netip.MustParseAddr("10.200.0.1"), true, true}, {"unversioned capability", 0, netip.Addr{}, true, true}, {"unknown version", 3, ip, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			peers, warnings, err := BuildPeers("account", []Record{{RegistrationID: "one", Enabled: true, PublicKey: public, ExitVersion: tc.version, IPv4: tc.binding, OffersExit: tc.offers}}, []cfapi.Registration{reg})
			if err != nil || len(peers) == 0 != tc.fail || len(warnings) > 0 != tc.fail {
				t.Fatalf("%+v %q %v", peers, warnings, err)
			}
		})
	}
}
func TestExitAllowedIPsRequireLocalConsent(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	ip, _ := Address("account", public)
	v4, _ := IPv4Address("account", public)
	p := Peer{PublicKey: public, IP: ip, IPv4: v4, ExitVersion: 2, OffersExit: true}
	transport := &Transport{}
	p.AllowedIPs = ExitAllowedIPs(p, public)
	if transport.validAllowedIPs(p) {
		t.Fatal("advertisement granted default routes")
	}
	transport.AuthorizeExit([]Peer{p}, "")
	if transport.validAllowedIPs(p) {
		t.Fatal("source binding granted default routes")
	}
	transport.AuthorizeExit([]Peer{p}, public)
	if !transport.validAllowedIPs(p) {
		t.Fatal("selected defaults rejected")
	}
	want := []netip.Prefix{netip.PrefixFrom(ip, 128), netip.PrefixFrom(v4, 32), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	if !slices.Equal(p.AllowedIPs, want) {
		t.Fatal(p.AllowedIPs)
	}
	p.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
	if transport.validAllowedIPs(p) {
		t.Fatal("discarded identity binding")
	}
	p.AllowedIPs = want
	transport.AuthorizeExit(nil, "")
	if transport.validAllowedIPs(p) {
		t.Fatal("revoked role remained authorized")
	}
}
