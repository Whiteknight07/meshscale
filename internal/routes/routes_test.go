package routes

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestParse(t *testing.T) {
	got, err := Parse("10.250.0.9/24, fd00::1/64")
	if err != nil || len(got) != 2 || got[0].String() != "10.250.0.0/24" || got[1].String() != "fd00::/64" {
		t.Fatalf("%v %v", got, err)
	}
	for _, s := range []string{"", "10.0.0.1", "0.0.0.0/0", "::/0", "100.96.0.0/12", "100.96.0.4/32", "100.64.0.0/10", "2606:4700:cf1::/48", "::ffff:10.0.0.1/128", "10.0.0.0/24,10.0.0.9/24", "10.0.0.0/24,"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestPlanAndRemoval(t *testing.T) {
	prefixes, _ := Parse("10.250.0.0/24,10.251.0.0/24")
	got, err := Plan(prefixes, "node", nil)
	if err != nil || len(got) != 2 || got[0].TunnelID != "node" || got[0].Comment != marker+"10.250.0.0/24" {
		t.Fatalf("%+v %v", got, err)
	}
	owned := cfapi.Route{ID: "route", Network: got[0].Network, TunnelID: "node", Comment: got[0].Comment}
	got, err = Plan(prefixes, "node", []cfapi.Route{owned})
	if err != nil || len(got) != 1 || got[0].Network != "10.251.0.0/24" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Plan(prefixes, "", nil); err == nil {
		t.Fatal("missing node")
	}
	for _, change := range []func(*cfapi.Route){
		func(r *cfapi.Route) { r.Comment = "customer" },
		func(r *cfapi.Route) { r.TunnelID = "other" },
		func(r *cfapi.Route) { r.VirtualNetworkID = "different"; r.Comment = "customer" },
	} {
		r := owned
		change(&r)
		if _, err := Plan(prefixes, "node", []cfapi.Route{r}); err == nil {
			t.Fatal("collision adopted")
		}
	}
	prefix := netip.MustParsePrefix("10.250.0.0/24")
	if r, err := Removal(prefix, []cfapi.Route{owned}); err != nil || r.ID != "route" {
		t.Fatalf("%+v %v", r, err)
	}
	now := time.Now()
	deleted := owned
	deleted.DeletedAt = &now
	if Owned(deleted) {
		t.Fatal("deleted route owned")
	}
	for _, existing := range [][]cfapi.Route{nil, {deleted}, {owned, owned}, {{ID: "customer", Network: prefix.String()}}, {{Network: prefix.String(), Comment: owned.Comment}}} {
		if _, err := Removal(prefix, existing); err == nil {
			t.Fatalf("accepted %+v", existing)
		}
	}
	if got, err := Plan(prefixes, "node", []cfapi.Route{deleted}); err != nil || len(got) != 2 {
		t.Fatalf("deleted: %v %v", got, err)
	}
}
