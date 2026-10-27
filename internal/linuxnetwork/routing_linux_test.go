package linuxnetwork

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Run explicitly inside unshare -n; never change the production namespace.
func TestKernelRoutingNamespace(t *testing.T) {
	if os.Getenv("MESHSCALE_ROUTING_NAMESPACE_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	if current == initial || current == "" || initial == "" {
		t.Fatal("refusing production network namespace")
	}
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, name := range []string{"tailscale0", "CloudflareWARP"} {
		if err := h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			t.Fatal(err)
		}
		link, err := h.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		address := "100.64.0.10/32"
		if name == "CloudflareWARP" {
			address = "100.96.0.7/32"
		}
		addr, err := netlink.ParseAddr(address)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}
	ts, _ := h.LinkByName("tailscale0")
	warp, _ := h.LinkByName("CloudflareWARP")
	for _, r := range []struct {
		prefix       string
		table, index int
	}{{"100.100.100.100/32", 52, ts.Attrs().Index}, {"100.96.0.0/12", 65743, warp.Attrs().Index}} {
		_, dst, _ := net.ParseCIDR(r.prefix)
		if err := h.RouteAdd(&netlink.Route{Dst: dst, Table: r.table, LinkIndex: r.index, Scope: netlink.SCOPE_LINK}); err != nil {
			t.Fatal(err)
		}
	}
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = 65743
	rule.Priority = 5209
	rule.Mark = 0x100cf
	rule.Invert = true
	if err := h.RuleAdd(rule); err != nil {
		t.Fatal(err)
	}
	runner := newRoutingRunner()
	manager := &routingManager{run: runner}
	defer runner.Close()
	for range 3 {
		if err := manager.reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	}
	for address, index := range map[string]int{"100.100.100.100": ts.Attrs().Index, "100.96.0.6": warp.Attrs().Index} {
		routes, err := h.RouteGet(net.ParseIP(address))
		if err != nil || len(routes) != 1 || routes[0].LinkIndex != index {
			t.Fatalf("route %s: %+v %v", address, routes, err)
		}
	}
	// A default route notification must invalidate the cache and remove our rule.
	_, defaultDestination, _ := net.ParseCIDR("0.0.0.0/0")
	if err := h.RouteAdd(&netlink.Route{Table: 52, Dst: defaultDestination, Type: unix.RTN_UNREACHABLE}); err != nil {
		t.Fatal(err)
	}
	if err := manager.reconcile(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	snapshot, err := runner.Snapshot(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range snapshot.Rules {
		if r.owned() {
			t.Fatal("exit default retained overlap rule")
		}
	}
	if err := manager.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
