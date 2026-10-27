package exitnode

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

func decodeLookup(out []byte) (Route, error) {
	var routes []Route
	if err := json.Unmarshal(out, &routes); err != nil {
		return Route{}, fmt.Errorf("decode route lookup: %w", err)
	}
	if len(routes) != 1 || routes[0].Dev == "" {
		return Route{}, fmt.Errorf("route lookup has no unique interface")
	}
	return routes[0], nil
}

// ControlRoutes pins only exact API/auth addresses to their original physical or
// Mesh route. Never use the selected exit's default when refreshing exceptions.
func ControlRoutes(s Snapshot, ips []netip.Addr) ([]Exception, error) {
	var result []Exception
	for _, ip := range ips {
		family, flag := s.V4, "-4"
		if ip.Is6() {
			family, flag = s.V6, "-6"
		}
		best := -1
		var selected Route
		for _, r := range family.Routes {
			if r.Type != "" && r.Type != "unicast" || r.Dev == "meshsecure0" || r.table() != "main" && r.Dev != "CloudflareWARP" && r.Dev != "meshscale0" {
				continue
			}
			prefix, err := r.prefix(ip.Is6())
			if err == nil && prefix.Contains(ip) && prefix.Bits() > best {
				best = prefix.Bits()
				selected = r
			}
		}
		// A client without an IPv6 uplink needs no direct IPv6 control exception.
		if best < 0 {
			if ip.Is6() {
				continue
			}
			return nil, fmt.Errorf("no original control-plane route to %s", ip)
		}
		selected.Dst = ip.String()
		result = append(result, Exception{flag, selected})
	}
	return result, nil
}
