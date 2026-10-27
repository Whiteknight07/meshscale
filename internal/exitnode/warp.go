package exitnode

import "net/netip"

// warpUnderlay preserves WARP's unmarked connection probes as well as marked
// tunnel sockets. Restrict the guard to documented ingress ranges and ports:
// https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/
// These routes live only in the client's owned exception table, never main.
func warpUnderlay(s Snapshot, owned *Plan) []Exception {
	present := owned != nil && len(owned.WARP) > 0
	for _, f := range []Family{s.V4, s.V6} {
		for _, r := range f.Routes {
			present = present || r.Dev == "CloudflareWARP"
		}
	}
	if !present {
		return nil
	}
	var routes []Exception
	for _, target := range []struct {
		family       Family
		flag, prefix string
	}{
		{s.V4, "-4", "162.159.197.0/24"},
		{s.V6, "-6", "2606:4700:102::/48"},
	} {
		found := false
		// Main-table physical underlay only. A tunnel route to an inside-connectivity
		// check must never become the route used to establish the carrier itself.
		for _, r := range target.family.Routes {
			if r.Dst != "default" || r.table() != "main" || r.Dev == "" || r.Dev == "CloudflareWARP" || r.Dev == "meshsecure0" || r.Dev == "tailscale0" || r.Dev == "meshscale0" {
				continue
			}
			r.Dst = target.prefix
			routes = append(routes, Exception{target.flag, r})
			found = true
			break
		}
		if !found {
			routes = append(routes, Exception{target.flag, Route{Dst: target.prefix, Type: "unreachable"}})
		}
	}
	return routes
}

// WARP 2026.8 uses the selected ingress .2 for its outside-tunnel check,
// while Cloudflare documents .3. Preserve both exact HTTPS destinations and
// the documented orchestration API endpoints.
// General HTTPS/Internet destinations remain subject to the selected exit.
func warpControlIPs() []netip.Addr {
	var ips []netip.Addr
	for _, ip := range []string{"162.159.197.2", "2606:4700:102::2", "162.159.197.3", "2606:4700:102::3", "162.159.137.105", "162.159.138.105", "2606:4700:7::a29f:8969", "2606:4700:7::a29f:8a69"} {
		ips = append(ips, netip.MustParseAddr(ip))
	}
	return ips
}
