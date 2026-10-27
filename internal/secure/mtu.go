package secure

import "net"

// IPv4 carrier: IP(20) + UDP(8) + WireGuard data header/tag(32).
const carrierOverhead = 60

// PathMTU reserves full 16-byte WireGuard padding. IPv6 interfaces must still
// advertise >=1280; TCP MSS is clamped separately when the carrier is smaller.
func PathMTU(underlay int) (mtu, mss int) {
	budget := (underlay - carrierOverhead) &^ 15
	return max(1280, budget), max(536, budget-40-20)
}
func carrierMTU() int {
	if link, err := net.InterfaceByName("CloudflareWARP"); err == nil {
		return link.MTU
	}
	if link, err := net.InterfaceByName("meshscale0"); err == nil {
		return link.MTU
	}
	return 1280
}
