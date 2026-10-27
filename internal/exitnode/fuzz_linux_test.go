//go:build linux

package exitnode

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// FuzzRouteSnapshot normalizes arbitrary kernel routes the way Inspect does
// and plans exit routing around them. The ip-style strings must parse back to
// the kernel prefix, and no route can widen LAN access or become an exception
// for a default destination.
func FuzzRouteSnapshot(f *testing.F) {
	f.Add([]byte{192, 168, 1, 0}, uint8(24), 254, unix.RTN_UNICAST, "eth0", []byte{}, false)
	f.Add([]byte{100, 96, 0, 0}, uint8(12), 65743, unix.RTN_UNICAST, "CloudflareWARP", []byte{}, true)
	f.Add([]byte(net.ParseIP("fd6d:6573:6873::").To16()), uint8(48), 254, unix.RTN_UNICAST, "meshsecure0", []byte{}, true)
	f.Add([]byte{10, 192, 0, 1}, uint8(32), 254, unix.RTN_UNICAST, "x\"; flush ruleset", []byte{10, 0, 0, 1}, true)
	f.Add([]byte{0, 0, 0, 0}, uint8(0), 51840, unix.RTN_BLACKHOLE, "", []byte{}, false)
	f.Fuzz(func(t *testing.T, ip []byte, ones uint8, table, kind int, dev string, gateway []byte, allowLAN bool) {
		if len(ip) != 4 && len(ip) != 16 || len(gateway) != 0 && len(gateway) != len(ip) || int(ones) > len(ip)*8 {
			return
		}
		dst := &net.IPNet{IP: net.IP(ip), Mask: net.CIDRMask(int(ones), len(ip)*8)}
		route := netlink.Route{Dst: dst, Table: table, Type: kind, LinkIndex: 7}
		if len(gateway) > 0 {
			route.Gw = net.IP(gateway)
		}
		r := routeFromNetlink(route, map[int]string{7: dev})
		v6 := len(ip) == 16
		prefix, err := r.prefix(v6)
		if err != nil {
			t.Fatalf("normalized destination %q does not parse: %v", r.Dst, err)
		}
		want, _ := netip.AddrFromSlice(ip)
		if v6 {
			want = netip.AddrFrom16(want.As16())
		}
		if ones > 0 && prefix != netip.PrefixFrom(want, int(ones)).Masked() && prefix != netip.PrefixFrom(want, int(ones)) {
			t.Fatalf("route %s/%d normalized to %s", want, ones, prefix)
		}
		s := baseline()
		family := &s.V4
		if v6 {
			family = &s.V6
		}
		family.Routes = append(family.Routes, r)
		p, err := PlanRouting(s, netip.MustParseAddr("10.192.0.1"), netip.MustParseAddr("100.96.0.2"), allowLAN, nil)
		if err != nil {
			return
		}
		if !allowLAN && len(p.LAN) > 0 {
			t.Fatalf("LAN prefixes %v without consent", p.LAN)
		}
		for _, e := range p.Exceptions {
			if e.Route.Dst == "default" {
				t.Fatalf("default route became an exception: %+v", e)
			}
			if exception, err := e.Route.prefix(e.Family == "-6"); err != nil || exception.Bits() == 0 {
				t.Fatalf("exception %q is not a specific prefix", e.Route.Dst)
			}
		}
		_ = GuardRules(p)
	})
}

func FuzzProcAddress(f *testing.F) {
	f.Add("0100007F", false)
	f.Add("0000000000000000FFFF00000100007F", true)
	f.Add("zz", false)
	f.Fuzz(func(t *testing.T, value string, v6 bool) {
		addr, err := procAddress(value, v6)
		if err != nil {
			return
		}
		raw := addr.AsSlice()
		if v6 != (len(raw) == 16) {
			t.Fatalf("%q decoded to %s", value, addr)
		}
		// Re-encode in /proc's host-order words and compare.
		encoded := make([]byte, len(raw))
		for i := 0; i < len(raw); i += 4 {
			encoded[i], encoded[i+1], encoded[i+2], encoded[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		if !strings.EqualFold(hex.EncodeToString(encoded), value) {
			t.Fatalf("%q decoded to %s", value, addr)
		}
	})
}

func FuzzDecodeLookup(f *testing.F) {
	f.Add([]byte(`[{"dst":"1.1.1.1","dev":"eth0","gateway":"192.168.1.1","table":"main"}]`))
	f.Add([]byte(`[{"dst":"1.1.1.1","dev":""}]`))
	f.Add([]byte(`[{"table":7},{"table":null}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := decodeLookup(data)
		if err == nil && r.Dev == "" {
			t.Fatal("accepted a lookup without an interface")
		}
		_ = r.table()
	})
}
