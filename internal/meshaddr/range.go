// Package meshaddr defines the Cloudflare Mesh device address space.
package meshaddr

import "net/netip"

var (
	// IPv4Range holds every Mesh device's IPv4 address.
	IPv4Range = netip.MustParsePrefix("100.96.0.0/12")
	// IPv6Range holds every Mesh device's IPv6 address.
	IPv6Range = netip.MustParsePrefix("2606:4700:cf1:1000::/64")
	// IPv6Block is the WARP block routed into the tunnel. Besides IPv6Range it
	// holds Cloudflare's own addresses, such as the client's 2606:4700:cf1:2000::1,
	// which are never devices.
	IPv6Block = netip.MustParsePrefix("2606:4700:cf1::/48")
)

// IsIPv4 accepts only native, unzoned Mesh IPv4 endpoints.
func IsIPv4(addr netip.Addr) bool {
	return addr.Is4() && addr.Zone() == "" && IPv4Range.Contains(addr)
}

// IsDevice accepts only unzoned Mesh device addresses of either family, never
// other Cloudflare addresses in IPv6Block.
func IsDevice(addr netip.Addr) bool {
	if addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	return IPv4Range.Contains(addr) || IPv6Range.Contains(addr)
}
