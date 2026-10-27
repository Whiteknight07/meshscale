//go:build linux

package exitnode

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/secureroute"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// configureSourceAddress gives meshsecure0 the device's IPv4 /32 without a
// prefix route, so peer routes stay explicit.
func configureSourceAddress(self secure.Peer) error {
	link, err := netlink.LinkByName("meshsecure0")
	if err != nil {
		return err
	}
	expected := self.IPv4.String() + "/32"
	addresses, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if address.IPNet != nil && address.IPNet.String() == expected && address.Flags&unix.IFA_F_NOPREFIXROUTE != 0 {
			return nil
		}
	}
	_, network, _ := net.ParseCIDR(expected)
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: network, Flags: unix.IFA_F_NOPREFIXROUTE}); err != nil {
		return fmt.Errorf("configure secure source address: %w", err)
	}
	return nil
}

func systemPeerRoute() (func(netip.Addr) error, error) {
	link, err := netlink.LinkByName("meshsecure0")
	if err != nil {
		return nil, err
	}
	return func(ip netip.Addr) error { return ensurePeerRoute(link, ip) }, nil
}

func ensurePeerRoute(link netlink.Link, ip netip.Addr) error {
	if link.Attrs() == nil {
		return fmt.Errorf("secure link has no attributes")
	}
	prefix := netip.PrefixFrom(ip, 32)
	network := &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), 32)}
	routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_MAIN, Dst: network}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return fmt.Errorf("inspect secure peer route %s: %w", ip, err)
	}
	for _, route := range routes {
		if route.LinkIndex == link.Attrs().Index && route.Dst != nil && route.Dst.String() == network.String() {
			return nil
		}
	}
	route := netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_MAIN, Dst: network, Scope: netlink.SCOPE_LINK, Protocol: unix.RTPROT_BOOT}
	if err := secureroute.Replace(secureroute.Command(context.Background()), route); err != nil {
		return fmt.Errorf("install secure peer route %s: %w", ip, err)
	}
	return nil
}
